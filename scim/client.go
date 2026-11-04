package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxBody is the most of any response the client reads. A User is a few kilobytes.
const maxBody = 1 << 20

// Client talks to one SCIM server. The zero HTTPClient is a ten-second client; products with
// an outbound policy (private-range refusal, dial guards) pass their own. Redirects are
// refused whatever client is passed.
type Client struct {
	// BaseURL is the SCIM root, e.g. https://host/scim/v2. HTTPS only.
	BaseURL string
	// Token is sent as Authorization: Bearer and nowhere else.
	Token      string
	HTTPClient *http.Client
}

// Ping fetches ServiceProviderConfig, which proves the URL answers as a SCIM root and the
// token is accepted, without touching a user. Any HTTPS endpoint can return an empty 200, so
// the body must be a JSON object.
func (c *Client) Ping(ctx context.Context) error {
	u, err := c.endpoint("", "ServiceProviderConfig")
	if err != nil {
		return err
	}
	var probe json.RawMessage
	if err := c.do(ctx, http.MethodGet, u, nil, &probe); err != nil {
		return err
	}
	if probe = bytes.TrimSpace(probe); len(probe) == 0 || probe[0] != '{' {
		return fmt.Errorf("%w: ServiceProviderConfig is not a JSON object", ErrMalformedResponse)
	}
	return nil
}

// CreateUser POSTs the user and returns the resource the server minted. The returned ID is
// the handle for every later call; the caller's ID and Meta are not sent. A 409 is
// ErrConflict, never success.
func (c *Client) CreateUser(ctx context.Context, user User) (User, error) {
	u, err := c.endpoint("", "Users")
	if err != nil {
		return User{}, err
	}
	var out User
	if err := c.do(ctx, http.MethodPost, u, outbound(user), &out); err != nil {
		return User{}, err
	}
	if out.ID == "" {
		return User{}, fmt.Errorf("%w: create returned no id", ErrMalformedResponse)
	}
	return out, nil
}

// GetUser fetches one user by the server's ID.
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	u, err := c.user(id)
	if err != nil {
		return User{}, err
	}
	var out User
	return out, c.do(ctx, http.MethodGet, u, nil, &out)
}

// FindUser looks a user up by an equality filter on "externalId" or "userName", the two
// attributes the result can be checked against. Zero matches is ErrNotFound; more than one is
// ErrAmbiguous; one that does not carry the value is ErrMalformedResponse, because a server
// without filtering returns its collection, and one unrelated user in it must not become the
// account that is deactivated next.
func (c *Client) FindUser(ctx context.Context, attribute, value string) (User, error) {
	if attribute != "externalId" && attribute != "userName" {
		return User{}, fmt.Errorf("scim: FindUser supports externalId and userName, not %q", attribute)
	}
	// An empty value would match a user without the attribute and pass the check below.
	if strings.TrimSpace(value) == "" {
		return User{}, fmt.Errorf("scim: FindUser needs a %s to look for", attribute)
	}
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	u, err := c.endpoint(attribute+` eq "`+quoted+`"`, "Users")
	if err != nil {
		return User{}, err
	}
	var list struct {
		TotalResults *int    `json:"totalResults"`
		Resources    *[]User `json:"Resources"`
	}
	if err := c.do(ctx, http.MethodGet, u, nil, &list); err != nil {
		return User{}, err
	}
	// Not found is a list that says so. An empty or foreign body, or a page that counts
	// matches it does not carry, must not read as "no such user": the caller would create a
	// duplicate or skip a deactivation.
	if list.TotalResults == nil && list.Resources == nil {
		return User{}, fmt.Errorf("%w: not a list response", ErrMalformedResponse)
	}
	var resources []User
	if list.Resources != nil {
		resources = *list.Resources
	}
	total := len(resources)
	if list.TotalResults != nil {
		total = *list.TotalResults
	}
	switch {
	case len(resources) > 1 || total > 1:
		return User{}, ErrAmbiguous
	case len(resources) == 0 && total == 0:
		return User{}, ErrNotFound
	case len(resources) == 0:
		return User{}, fmt.Errorf("%w: list reports %d matches and carries none", ErrMalformedResponse, total)
	}
	found := resources[0]
	// userName is not caseExact in the core schema; externalId is.
	if attribute == "externalId" && found.ExternalID != value || attribute == "userName" && !strings.EqualFold(found.UserName, value) {
		return User{}, fmt.Errorf("%w: the user returned does not match the filter", ErrMalformedResponse)
	}
	return found, nil
}

// ReplaceUser PUTs the whole user under the server's ID.
func (c *Client) ReplaceUser(ctx context.Context, id string, user User) (User, error) {
	u, err := c.user(id)
	if err != nil {
		return User{}, err
	}
	var out User
	return out, c.do(ctx, http.MethodPut, u, outbound(user), &out)
}

// PatchUser applies operations, e.g. {Op: "replace", Path: "active", Value: false} to
// deprovision. The returned User is zero when the server answers 204.
func (c *Client) PatchUser(ctx context.Context, id string, ops ...PatchOperation) (User, error) {
	if len(ops) == 0 {
		return User{}, fmt.Errorf("scim: patch needs at least one operation")
	}
	u, err := c.user(id)
	if err != nil {
		return User{}, err
	}
	body := struct {
		Schemas    []string         `json:"schemas"`
		Operations []PatchOperation `json:"Operations"`
	}{[]string{PatchOpSchema}, ops}
	var out User
	return out, c.do(ctx, http.MethodPatch, u, body, &out)
}

// DeleteUser removes the user. A 404 is ErrNotFound; whether that is fine is the caller's call.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	u, err := c.user(id)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, u, nil, nil)
}

// outboundUser is the body of a create or replace. Roles is always sent, as [] when the user
// has none: a server may keep or default an attribute a PUT leaves out (RFC 7644 section
// 3.5.1), so omitting it would let a revoked last role survive downstream.
type outboundUser struct {
	User
	Roles []MultiValue `json:"roles"`
}

// outbound is the user as sent: schema filled in, server-owned fields cleared, roles present.
func outbound(user User) outboundUser {
	user.ID, user.Meta = "", nil
	if len(user.Schemas) == 0 {
		user.Schemas = []string{UserSchema}
	}
	roles := user.Roles
	if roles == nil {
		roles = []MultiValue{}
	}
	return outboundUser{User: user, Roles: roles}
}

// user is the URL of one user. The ID is path-escaped and must be a real segment: an empty
// one turns DELETE /Users/{id} into DELETE /Users, and a dot would be cleaned out of the path.
func (c *Client) user(id string) (string, error) {
	if id == "" || id == "." || id == ".." {
		return "", fmt.Errorf("scim: %q is not a resource id", id)
	}
	return c.endpoint("", "Users", url.PathEscape(id))
}

// endpoint validates BaseURL and joins the escaped segments and optional filter onto it.
func (c *Client) endpoint(filter string, segments ...string) (string, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil ||
		base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return "", ErrInsecureURL
	}
	if c.Token == "" {
		return "", ErrNoToken
	}
	u := base.JoinPath(segments...)
	if filter != "" {
		u.RawQuery = url.Values{"filter": {filter}}.Encode()
	}
	return u.String(), nil
}

func (c *Client) do(ctx context.Context, method, target string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	base := c.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	// Go would replay the body, and the bearer, wherever the server pointed.
	client := *base
	client.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		return fmt.Errorf("scim: server redirected to %s://%s%s; redirects are refused", r.URL.Scheme, r.URL.Host, r.URL.Path)
	}
	resp, err := client.Do(req)
	if err != nil {
		// url.Error carries the full URL, and FindUser's query names a user.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("scim: %s %s: %w", method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	if resp.StatusCode >= 400 {
		return c.remoteError(resp, raw)
	}
	// A 3xx without Location, a 1xx, or a 202 from something that is not a SCIM server is
	// not the outcome the caller asked for, and a delete recorded on it never happened.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%w: status %d", ErrMalformedResponse, resp.StatusCode)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrMalformedResponse, maxBody)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	return nil
}

// remoteError reads the RFC 7644 error body when there is one. The status comes from the
// response line, not the body, so a body that lies or is not JSON still classifies. Gateways
// echo the credential they rejected, so the token is redacted before the text can be logged.
func (c *Client) remoteError(resp *http.Response, raw []byte) error {
	e := &Error{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	var body struct {
		ScimType string `json:"scimType"`
		Detail   string `json:"detail"`
	}
	if json.Unmarshal(raw, &body) == nil {
		redact := func(s string) string { return printable(strings.ReplaceAll(s, c.Token, "[token]")) }
		e.ScimType, e.Detail = redact(body.ScimType), redact(body.Detail)
	}
	return e
}

// maxRetryAfter caps the server's hint. A caller that sleeps on it must not be parked for
// years, or handed a negative duration by an overflowed one, by the server it is retrying.
const maxRetryAfter = time.Hour

func retryAfter(h string) time.Duration {
	var d time.Duration
	if secs, err := strconv.ParseInt(h, 10, 64); err == nil {
		if secs > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = time.Until(t)
	}
	return max(0, min(d, maxRetryAfter))
}
