package applysetup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateBundleAndSecretBoundary(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(file, []byte(`{"schema":"example","secret":"do-not-echo"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var dest struct{ Schema string }
	if err := Decode(file, &dest); err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatal("unknown secret field accepted or echoed", err)
	}
	if err := os.WriteFile(file, []byte(`{"schema":"example"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Decode(file, &dest); err != nil || dest.Schema != "example" {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Decode(file, &dest); err == nil {
		t.Fatal("shared bundle accepted")
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("credential\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := Secret(secret); err != nil || s != "credential" {
		t.Fatal("secret", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.WriteFile(secret, []byte(strings.Repeat("x", MaxSecretBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret(secret); err == nil {
		t.Fatal("oversized secret accepted")
	}
}
func TestCommonIdentityAndCallbackValidation(t *testing.T) {
	c := Common{Schema: Schema, Service: "kydrive", SetupID: "271333e2-c221-4601-b249-563b3d828530", SSO: &SSO{IssuerURL: "https://identity.test", ClientID: "drive", ClientSecretFile: "/data/secret", RedirectURI: "https://drive.test/callback"}, Admins: []Identity{{Issuer: "https://identity.test", Subject: "admin-subject", Username: "owner-admin"}}, Everyday: []Identity{{Issuer: "https://identity.test", Subject: "user-subject", Username: "owner"}}}
	if err := c.Validate("kydrive", "/callback"); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate("kypulse", "/callback"); err == nil {
		t.Fatal("foreign product accepted")
	}
	if err := c.Validate("kydrive", "/other"); err == nil {
		t.Fatal("wrong callback accepted")
	}
	c.Everyday = append(c.Everyday, c.Admins[0])
	if err := c.Validate("kydrive", "/callback"); err == nil {
		t.Fatal("mixed administrator/everyday identity accepted")
	}
	for _, v := range []string{"1m", "-1h", "1.1s", "9000h"} {
		if _, err := Interval(v); err == nil {
			t.Fatalf("interval %s accepted", v)
		}
	}
	for _, u := range []string{"http://identity.test", "https://secret@identity.test", "https://identity.test/#fragment"} {
		if HTTPS(u) {
			t.Fatal("URL accepted", u)
		}
	}
}
func TestCLIAndCapabilityReportsContainNoCredentials(t *testing.T) {
	for _, args := range [][]string{{}, {"--file", "relative"}, {"--capabilities", "--file", "/data/bundle"}, {"--check"}, {"--unknown"}} {
		if _, err := Parse(args); err == nil {
			t.Fatal("arguments accepted", args)
		}
	}
	if o, err := Parse([]string{"--file", "/data/bundle", "--check"}); err != nil || !o.Check {
		t.Fatal("check parser", err)
	}
	var out bytes.Buffer
	if err := WriteCapabilities(&out, "kydrive", "sso", "admin", "check"); err != nil {
		t.Fatal(err)
	}
	var caps Capabilities
	if err := json.Unmarshal(out.Bytes(), &caps); err != nil || caps.BundleSchema != Schema || caps.Service != "kydrive" {
		t.Fatal("caps", err)
	}
}
