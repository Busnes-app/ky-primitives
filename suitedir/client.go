// Package suitedir is the client for KyIdentity's suite directory: which suite apps a user
// may open, the organisation's people for a picker, its suite groups (per org on a multi-tenant KyIdentity), the URL and shared syncauth secret of a paired app, and, on a multi-tenant KyIdentity, its organisations and erased subjects, plus storage usage reports and reserved grants. Server to server, with
// the calling app's own OAuth client credentials (client_secret_basic). Contract:
// KyIdentity-server docs/SUITE-DIRECTORY.md.
package suitedir

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxBody bounds every response read. An app list is a few kilobytes.
const maxBody = 1 << 20

// maxGroupsBody bounds the group list: at most 200 groups with their member subjects.
const maxGroupsBody = 8 << 20

var (
	// ErrUnauthorized is a 401: KyIdentity refused the client credentials.
	ErrUnauthorized = errors.New("suitedir: client credentials refused")
	// ErrNoPeer is a 404 no_peer: the pair is unknown, or the peer is disabled or has no
	// HTTPS origin. Fall back to the app's own configuration.
	ErrNoPeer = errors.New("suitedir: no peer")
	// ErrInsecureIssuer is an issuer that is not HTTPS (loopback http excepted).
	ErrInsecureIssuer = errors.New("suitedir: issuer must be https")
)

// Client calls one KyIdentity. A nil HTTP is a ten-second client; products with an outbound
// policy pass their own. Redirects are refused whatever client is passed.
type Client struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

// App is one launchable suite app. ID is its OAuth client ID.
type App struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Peer is a paired suite app. Secret is the pair's 32-byte syncauth key. Regions, from a
// multi-tenant KyIdentity, maps home regions to the origin serving each; use URLFor.
type Peer struct {
	Client  string
	URL     string
	Secret  []byte
	Regions map[string]string
}

// URLFor is where to reach the peer for an org homed in region (Org.HomeRegion). A peer
// without Regions is its one URL; with Regions, only the region's own entry, and false when
// it has none: never URL, which serves another region.
func (p Peer) URLFor(region string) (string, bool) {
	if p.Regions == nil {
		return p.URL, true
	}
	u, ok := p.Regions[region]
	return u, ok
}

// Apps lists the apps sub may open; an empty sub lists every launchable app. Entries without
// an id, a name or an HTTPS URL are dropped.
func (c *Client) Apps(ctx context.Context, sub string) ([]App, error) {
	q := url.Values{}
	if sub != "" {
		q.Set("sub", sub)
	}
	var body struct {
		Apps []App `json:"apps"`
	}
	if err := c.get(ctx, "apps", q, &body); err != nil {
		return nil, err
	}
	if body.Apps == nil {
		return nil, errors.New("suitedir: apps: response has no apps list")
	}
	apps := body.Apps[:0]
	for _, a := range body.Apps {
		if a.ID != "" && a.Name != "" && isHTTPS(a.URL) {
			apps = append(apps, a)
		}
	}
	return apps, nil
}

// Person is a member of the organisation who may open the calling app. Sub is their
// KyIdentity subject.
type Person struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// People searches the people the user sub may see from this app: q is 2 to 64 characters,
// limit 1 to 20 or 0 for KyIdentity's default of 10. Entries without a sub or email are dropped.
func (c *Client) People(ctx context.Context, sub, q string, limit int) ([]Person, error) {
	v := url.Values{"sub": {sub}, "q": {q}}
	if limit != 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	return c.people(ctx, v)
}

// Resolve maps 1 to 100 email addresses to people; unmatched addresses are absent. No
// addresses is an empty answer without a request.
func (c *Client) Resolve(ctx context.Context, sub string, emails []string) ([]Person, error) {
	if len(emails) == 0 {
		return []Person{}, nil
	}
	return c.people(ctx, url.Values{"sub": {sub}, "email": emails})
}

func (c *Client) people(ctx context.Context, v url.Values) ([]Person, error) {
	if v.Get("sub") == "" {
		return nil, errors.New("suitedir: people: sub is required")
	}
	var body struct {
		People []Person `json:"people"`
	}
	if err := c.get(ctx, "people", v, &body); err != nil {
		return nil, err
	}
	if body.People == nil {
		return nil, errors.New("suitedir: people: response has no people list")
	}
	people := body.People[:0]
	for _, p := range body.People {
		if p.Sub != "" && p.Email != "" {
			people = append(people, p)
		}
	}
	return people, nil
}

// Group is a suite group (KyIdentity docs/SUITE-DIRECTORY.md). Match resources on ID
// only. State is GroupActive, with Members the subjects to grant the ordinary member
// role, or GroupArchived: make the resource read-only with no members, and keep it.
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Slug    string   `json:"slug"`
	State   string   `json:"state"`
	Members []string `json:"members"`
}

const (
	GroupActive   = "active"
	GroupArchived = "archived"
)

// Groups lists the suite groups for the calling app. Malformed entries are dropped, so
// an app must archive only on an explicit GroupArchived, never on absence.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	return c.groups(ctx, url.Values{})
}

// OrgGroups lists org's suite groups on a multi-tenant KyIdentity, as Groups does. An org
// not listed by Orgs is an error (404 unknown_org).
func (c *Client) OrgGroups(ctx context.Context, org string) ([]Group, error) {
	if org == "" {
		return nil, errors.New("suitedir: groups: org is required")
	}
	return c.groups(ctx, url.Values{"org_id": {org}})
}

func (c *Client) groups(ctx context.Context, q url.Values) ([]Group, error) {
	var body struct {
		Groups []Group `json:"groups"`
	}
	if err := c.fetch(ctx, "groups", q, maxGroupsBody, &body); err != nil {
		return nil, err
	}
	if body.Groups == nil {
		return nil, errors.New("suitedir: groups: response has no groups list")
	}
	groups := body.Groups[:0]
	seen := map[string]bool{}
	for _, g := range body.Groups {
		if g.ID == "" || seen[g.ID] || strings.TrimSpace(g.Name) == "" || !validSlug(g.Slug) {
			continue
		}
		switch {
		case g.State == GroupArchived:
			g.Members = []string{}
		case g.State == GroupActive && validMembers(g.Members):
		default:
			continue
		}
		seen[g.ID] = true
		groups = append(groups, g)
	}
	return groups, nil
}

// Org is an organisation of a multi-tenant KyIdentity, as /api/suite/orgs lists it to the
// calling app. Enabled and Quotas (an opaque JSON object) are that app's only. Stop serving
// an org whose Status is not OrgActive; drop its data only at OrgDeleted. HomeRegion is the
// region every multi-region app keeps the org in; it never changes. It is "" from a
// KyIdentity older than home regions, which no regioned peer serves (Peer.URLFor).
type Org struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Revision   int64           `json:"revision"`
	HomeRegion string          `json:"home_region"`
	Enabled    bool            `json:"enabled"`
	Quotas     json.RawMessage `json:"quotas"`
}

const (
	OrgActive            = "active"
	OrgSuspended         = "suspended"
	OrgDeletionScheduled = "deletion_scheduled"
	OrgDeleted           = "deleted"
)

// maxOrgsBody bounds one page: 500 orgs, each with quotas of at most 4 KiB.
const maxOrgsBody = 4 << 20

// maxOrgPages bounds one Orgs call; a longer backlog continues from the revision returned.
var maxOrgPages = 100

// Orgs lists the orgs that changed after revision since (0 for all), following pages, in
// revision order. It returns the revision to pass next time: the last one listed, or since
// when nothing changed. A call cut short at its page bound returns one less than the last
// revision, so orgs sharing that revision on a later page are not skipped; the next call
// lists the ones already seen again, which an app applies as the same state. Any malformed entry fails the whole call, so an app never skips past
// an org it did not apply. Multi-tenant installs only; a single-tenant one answers 404.
func (c *Client) Orgs(ctx context.Context, since int64) ([]Org, int64, error) {
	if since < 0 {
		return nil, since, errors.New("suitedir: orgs: since is negative")
	}
	q := url.Values{"since": {strconv.FormatInt(since, 10)}, "limit": {"500"}}
	orgs, last := []Org{}, since
	for page := 0; ; page++ {
		if page == maxOrgPages {
			if last-1 <= since {
				return nil, since, errors.New("suitedir: orgs: one revision fills every page; no safe place to resume")
			}
			return orgs, last - 1, nil
		}
		var body struct {
			Orgs []Org  `json:"orgs"`
			Next string `json:"next"`
		}
		if err := c.fetch(ctx, "orgs", q, maxOrgsBody, &body); err != nil {
			return nil, since, err
		}
		if body.Orgs == nil {
			return nil, since, errors.New("suitedir: orgs: response has no orgs list")
		}
		for _, o := range body.Orgs {
			if o.ID == "" || o.Revision < last || o.Revision <= since || !validOrgStatus(o.Status) || !jsonObject(o.Quotas) ||
				o.HomeRegion != "" && !validRegion(o.HomeRegion) {
				return nil, since, fmt.Errorf("suitedir: orgs: malformed entry %q", o.ID)
			}
			last = o.Revision
		}
		orgs = append(orgs, body.Orgs...)
		if body.Next == "" || len(body.Orgs) == 0 {
			return orgs, last, nil
		}
		if body.Next == q.Get("cursor") {
			return nil, since, errors.New("suitedir: orgs: the cursor did not advance")
		}
		q = url.Values{"cursor": {body.Next}, "limit": {"500"}}
	}
}

// validRegion matches KyIdentity's home region slug, ^[a-z][a-z0-9-]{1,31}$.
func validRegion(s string) bool {
	if len(s) < 2 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validOrgStatus(s string) bool {
	return s == OrgActive || s == OrgSuspended || s == OrgDeletionScheduled || s == OrgDeleted
}

func jsonObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && m != nil
}

func validSlug(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validMembers(subs []string) bool {
	if subs == nil {
		return false
	}
	for _, s := range subs {
		if s == "" {
			return false
		}
	}
	return true
}

// Peer fetches the connection details for the paired app client.
func (c *Client) Peer(ctx context.Context, client string) (Peer, error) {
	if client == "" {
		return Peer{}, errors.New("suitedir: peer: client is required")
	}
	var body struct {
		Client  string            `json:"client"`
		URL     string            `json:"url"`
		Secret  string            `json:"secret"`
		Regions map[string]string `json:"regions"`
	}
	if err := c.get(ctx, "peer", url.Values{"client": {client}}, &body); err != nil {
		return Peer{}, err
	}
	if body.Client != client {
		return Peer{}, fmt.Errorf("suitedir: peer: asked for %q, got %q", client, body.Client)
	}
	if !isHTTPS(body.URL) {
		return Peer{}, errors.New("suitedir: peer: url is not https")
	}
	secret, err := base64.StdEncoding.DecodeString(body.Secret)
	if err != nil || len(secret) != 32 {
		return Peer{}, errors.New("suitedir: peer: secret is not 32 base64 bytes")
	}
	// A bad entry fails the call: dropping it could leave Regions empty, and URLFor would
	// then send every org to URL.
	if body.Regions != nil && len(body.Regions) == 0 {
		return Peer{}, errors.New("suitedir: peer: regions is empty")
	}
	for region, origin := range body.Regions {
		if !validRegion(region) || !isHTTPS(origin) {
			return Peer{}, fmt.Errorf("suitedir: peer: malformed region %q", region)
		}
	}
	return Peer{Client: body.Client, URL: body.URL, Secret: secret, Regions: body.Regions}, nil
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.fetch(ctx, path, q, maxBody, out)
}

func (c *Client) fetch(ctx context.Context, path string, q url.Values, limit int, out any) error {
	return c.request(ctx, http.MethodGet, path, q, nil, limit, out)
}

func (c *Client) request(ctx context.Context, method, path string, q url.Values, body []byte, limit int, out any) error {
	base, err := url.Parse(strings.TrimRight(c.Issuer, "/"))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		base.Scheme != "https" && !(base.Scheme == "http" && isLoopback(base.Hostname())) {
		return ErrInsecureIssuer
	}
	u := base.JoinPath("api", "suite", path)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := http.Client{Timeout: 10 * time.Second}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	// Go would resend the Basic credentials wherever the server pointed.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are refused")
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error carries the query, and sub names a user.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("suitedir: %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return fmt.Errorf("suitedir: %s: %w", path, err)
	}
	if len(raw) > limit {
		return fmt.Errorf("suitedir: %s: body exceeds %d bytes", path, limit)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusNotFound:
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error == "no_peer" {
			return ErrNoPeer
		}
		fallthrough
	default:
		return fmt.Errorf("suitedir: %s: status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("suitedir: %s: %w", path, err)
	}
	return nil
}

func isHTTPS(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
