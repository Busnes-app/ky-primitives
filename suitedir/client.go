// Package suitedir is the client for KyIdentity's suite directory: which suite apps a user
// may open, and the URL and shared syncauth secret of a paired app. Server to server, with
// the calling app's own OAuth client credentials (client_secret_basic). Contract:
// KyIdentity-server docs/SUITE-DIRECTORY.md.
package suitedir

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBody bounds every response read. An app list is a few kilobytes.
const maxBody = 1 << 20

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

// Peer is a paired suite app. Secret is the pair's 32-byte syncauth key.
type Peer struct {
	Client string
	URL    string
	Secret []byte
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

// Peer fetches the connection details for the paired app client.
func (c *Client) Peer(ctx context.Context, client string) (Peer, error) {
	if client == "" {
		return Peer{}, errors.New("suitedir: peer: client is required")
	}
	var body struct {
		Client string `json:"client"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
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
	return Peer{Client: body.Client, URL: body.URL, Secret: secret}, nil
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	base, err := url.Parse(strings.TrimRight(c.Issuer, "/"))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		base.Scheme != "https" && !(base.Scheme == "http" && isLoopback(base.Hostname())) {
		return ErrInsecureIssuer
	}
	u := base.JoinPath("api", "suite", path)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Accept", "application/json")

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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("suitedir: %s: %w", path, err)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("suitedir: %s: body exceeds %d bytes", path, maxBody)
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
