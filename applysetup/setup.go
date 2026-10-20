// Package applysetup defines the container-local installer boundary. Products own
// configuration changes, conflict handling, runtime activation and atomic audits.
package applysetup

import (
	"encoding/json"
	"flag"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

const Schema = "ky.product-setup/1"
const ReportSchema = "ky.product-setup-report/1"
const MaxBundleBytes = 128 << 10
const MaxSecretBytes = 4 << 10

type Options struct {
	File                                string
	Check, Capabilities, Restart, Stage bool
}

func Parse(args []string) (Options, error) {
	return parse(args, false)
}

// ParsePreparation is an explicit product opt-in. Legacy callers of Parse still
// refuse --stage instead of accidentally interpreting it as ordinary setup.
func ParsePreparation(args []string) (Options, error) {
	return parse(args, true)
}

func parse(args []string, preparation bool) (Options, error) {
	var o Options
	f := flag.NewFlagSet("apply-setup", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.File, "file", "", "private container-local bundle")
	f.BoolVar(&o.Check, "check", false, "inspect without changes")
	f.BoolVar(&o.Capabilities, "capabilities", false, "advertise supported contract")
	f.BoolVar(&o.Restart, "restart", false, "activate committed configuration with a graceful restart")
	if preparation {
		f.BoolVar(&o.Stage, "stage", false, "prepare immutable secret-free metadata from stdin")
	}
	if f.Parse(args) != nil || f.NArg() != 0 || o.Capabilities && (o.File != "" || o.Check || o.Restart || o.Stage) || o.Restart && (o.File != "" || o.Check || o.Stage) || !o.Capabilities && !o.Restart && !filepath.IsAbs(o.File) {
		return o, &Refusal{Reason: "apply-setup requires --file ABSOLUTE-PATH [--check], --capabilities, or --restart"}
	}
	return o, nil
}

type Capabilities struct {
	Schema       string   `json:"schema"`
	Service      string   `json:"service"`
	BundleSchema string   `json:"bundleSchema"`
	Features     []string `json:"features"`
}

func WriteCapabilities(out io.Writer, service string, features ...string) error {
	return json.NewEncoder(out).Encode(Capabilities{Schema: "ky.setup-capabilities/1", Service: service, BundleSchema: Schema, Features: features})
}
func Decode(file string, dest any) error {
	raw, err := keyfile.ReadPrivate(file, MaxBundleBytes)
	if err != nil {
		return &Refusal{Reason: "setup bundle must be a bounded private container-owned regular file"}
	}
	return DecodeRaw(raw, dest)
}
func Secret(file string) (string, error) {
	raw, err := keyfile.ReadPrivate(file, MaxSecretBytes)
	if err != nil {
		return "", &Refusal{Reason: "setup credential requires a bounded private container-owned regular file"}
	}
	secret := strings.TrimSuffix(string(raw), "\n")
	if secret == "" || strings.ContainsAny(secret, "\x00\r\n") {
		return "", &Refusal{Reason: "invalid setup credential file"}
	}
	return secret, nil
}

type Common struct {
	Schema   string     `json:"schema"`
	Service  string     `json:"service"`
	SetupID  string     `json:"setupId"`
	SSO      *SSO       `json:"sso,omitempty"`
	Admins   []Identity `json:"admins,omitempty"`
	Everyday []Identity `json:"everyday,omitempty"`
	Backup   *Backup    `json:"backup,omitempty"`
}
type SSO struct {
	IssuerURL           string `json:"issuerUrl"`
	ClientID            string `json:"clientId"`
	ClientSecretFile    string `json:"clientSecretFile"`
	RedirectURI         string `json:"redirectUri"`
	DirectorySecretFile string `json:"directorySecretFile,omitempty"`
	SCIMTokenFile       string `json:"scimTokenFile,omitempty"`
}
type Identity struct {
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
}
type Backup struct {
	Directory string    `json:"directory,omitempty"`
	Keep      int       `json:"keep,omitempty"`
	Interval  string    `json:"interval,omitempty"`
	Recovery  *Recovery `json:"recovery,omitempty"`
}
type Recovery struct {
	URL             string `json:"url"`
	PairingCodeFile string `json:"pairingCodeFile"`
}

var setupID = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

func Identifier(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}
func HTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && len(s) <= 2048 && !strings.ContainsAny(s, "\x00\r\n\t ")
}
func (c Common) Validate(service string, callbackPath string) error {
	if c.Schema != Schema || c.Service != service || !setupID.MatchString(c.SetupID) {
		return &Refusal{Reason: "setup schema, service or stable setupId is invalid"}
	}
	if s := c.SSO; s != nil {
		if !HTTPS(s.IssuerURL) || !Identifier(s.ClientID) || !HTTPS(s.RedirectURI) || !filepath.IsAbs(s.ClientSecretFile) {
			return &Refusal{Reason: "setup SSO requires HTTPS URLs, client ID and an absolute credential path"}
		}
		u, _ := url.Parse(s.RedirectURI)
		if callbackPath != "" && u.Path != callbackPath {
			return &Refusal{Reason: "setup SSO redirect does not match this product's callback path"}
		}
		for _, file := range []string{s.DirectorySecretFile, s.SCIMTokenFile} {
			if file != "" && !filepath.IsAbs(file) {
				return &Refusal{Reason: "setup SSO credential paths must be absolute"}
			}
		}
	}
	if len(c.Admins) > 16 || len(c.Everyday) > 16 {
		return &Refusal{Reason: "setup accepts at most 16 identities of each kind"}
	}
	names := map[string]bool{}
	subjects := map[[2]string]bool{}
	for _, list := range [][]Identity{c.Admins, c.Everyday} {
		for _, id := range list {
			if !HTTPS(id.Issuer) || !Identifier(id.Subject) || !Identifier(id.Username) || c.SSO != nil && id.Issuer != c.SSO.IssuerURL {
				return &Refusal{Reason: "setup identity requires exact issuer, subject and username"}
			}
			if id.Email != "" && (!Identifier(id.Email) || len(id.Email) > 255) {
				return &Refusal{Reason: "setup identity email is invalid"}
			}
			key := [2]string{id.Issuer, id.Subject}
			name := strings.ToLower(id.Username)
			if subjects[key] || names[name] {
				return &Refusal{Reason: "setup identities must be distinct, including administrator and everyday accounts"}
			}
			subjects[key], names[name] = true, true
		}
	}
	if b := c.Backup; b != nil {
		if b.Directory != "" && !filepath.IsAbs(b.Directory) || b.Keep < 0 || b.Keep > 1000 {
			return &Refusal{Reason: "setup backup directory or retention is invalid"}
		}
		if b.Interval != "" {
			if _, err := Interval(b.Interval); err != nil {
				return err
			}
		}
		if r := b.Recovery; r != nil {
			if !HTTPS(r.URL) || !filepath.IsAbs(r.PairingCodeFile) {
				return &Refusal{Reason: "setup recovery requires HTTPS and an absolute pairing-code path"}
			}
		}
	}
	return nil
}
func Interval(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || d%time.Second != 0 || d != 0 && (d < 15*time.Minute || d > 365*24*time.Hour) {
		return 0, &Refusal{Reason: "setup backup interval must be off (0) or 15 minutes through one year in whole seconds"}
	}
	return d, nil
}

type Object struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}
type Report struct {
	Schema  string   `json:"schema"`
	Service string   `json:"service"`
	SetupID string   `json:"setupId"`
	Created []Object `json:"created"`
	Present []Object `json:"present"`
	Pending []Object `json:"pending"`
}

func NewReport(c Common) Report {
	return Report{Schema: ReportSchema, Service: c.Service, SetupID: c.SetupID, Created: []Object{}, Present: []Object{}, Pending: []Object{}}
}
func (r Report) Write(out io.Writer) error { return json.NewEncoder(out).Encode(r) }
