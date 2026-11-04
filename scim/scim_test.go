package scim

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is a SCIM server that mints its own IDs, so a client that reuses local IDs
// for later calls is caught.
type fakeServer struct {
	mu       sync.Mutex
	users    map[string]User // by server ID
	nextID   int
	requests []*http.Request
	bodies   [][]byte
	srv      *httptest.Server
}

const token = "test-bearer-token-0123456789abcdef"

func newFake(t *testing.T) *fakeServer {
	f := &fakeServer{users: map[string]User{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) client() *Client {
	return &Client{BaseURL: f.srv.URL + "/scim/v2", Token: token, HTTPClient: f.srv.Client()}
}

func writeErr(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{ErrorSchema}, "status": status, "scimType": scimType, "detail": detail})
}

func writeUser(w http.ResponseWriter, status int, u User) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(u)
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	f.bodies = append(f.bodies, body)
	if r.Header.Get("Authorization") != "Bearer "+token {
		writeErr(w, 401, "", "Invalid or missing bearer token")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/scim/v2")
	switch {
	case path == "/ServiceProviderConfig" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"patch":{"supported":true}}`))
	case path == "/Users" && r.Method == http.MethodPost:
		var u User
		if err := json.Unmarshal(body, &u); err != nil || u.UserName == "" {
			writeErr(w, 400, "invalidValue", "userName required")
			return
		}
		for _, existing := range f.users {
			if existing.UserName == u.UserName {
				writeErr(w, 409, "uniqueness", "userName already exists")
				return
			}
		}
		f.nextID++
		u.ID = "srv-" + strings.Repeat("x", f.nextID)
		u.Meta = &Meta{ResourceType: "User", Location: f.srv.URL + "/scim/v2/Users/" + u.ID}
		f.users[u.ID] = u
		writeUser(w, 201, u)
	case path == "/Users" && r.Method == http.MethodGet:
		filter := r.URL.Query().Get("filter")
		var out []User
		for _, u := range f.users {
			if filter == `externalId eq "`+u.ExternalID+`"` || filter == `userName eq "`+u.UserName+`"` || filter == "" {
				out = append(out, u)
			}
		}
		w.Header().Set("Content-Type", "application/scim+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{ListResponseSchema}, "totalResults": len(out), "Resources": out})
	case strings.HasPrefix(path, "/Users/"):
		id, err := url.PathUnescape(strings.TrimPrefix(path, "/Users/"))
		if err != nil {
			writeErr(w, 400, "invalidPath", "bad id")
			return
		}
		u, ok := f.users[id]
		if !ok {
			writeErr(w, 404, "", "Resource "+id+" not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeUser(w, 200, u)
		case http.MethodPut:
			var in User
			if err := json.Unmarshal(body, &in); err != nil {
				writeErr(w, 400, "invalidSyntax", err.Error())
				return
			}
			in.ID, in.Meta = id, u.Meta
			f.users[id] = in
			writeUser(w, 200, in)
		case http.MethodPatch:
			var op struct {
				Schemas    []string         `json:"schemas"`
				Operations []PatchOperation `json:"Operations"`
			}
			if err := json.Unmarshal(body, &op); err != nil || len(op.Schemas) != 1 || op.Schemas[0] != PatchOpSchema {
				writeErr(w, 400, "invalidSyntax", "bad PatchOp")
				return
			}
			for _, o := range op.Operations {
				if o.Op == "replace" && o.Path == "active" {
					u.Active, _ = o.Value.(bool)
				}
			}
			f.users[id] = u
			writeUser(w, 200, u)
		case http.MethodDelete:
			delete(f.users, id)
			w.WriteHeader(204)
		default:
			writeErr(w, 405, "", "no")
		}
	default:
		writeErr(w, 404, "", "no route")
	}
}

func (f *fakeServer) last() (*http.Request, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1], f.bodies[len(f.bodies)-1]
}

func TestLifecycleAgainstServerMintedIDs(t *testing.T) {
	f := newFake(t)
	c := f.client()
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	local := User{ExternalID: "local-42", UserName: "alice", DisplayName: "Alice", Active: true,
		Emails: []MultiValue{{Value: "alice@example.com", Type: "work", Primary: true}}}
	created, err := c.CreateUser(ctx, local)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == "" || created.ID == local.ExternalID {
		t.Fatalf("CreateUser must return the server's id, got %q", created.ID)
	}
	req, body := f.last()
	if req.Header.Get("Content-Type") != "application/scim+json" || !strings.Contains(req.Header.Get("Accept"), "application/scim+json") {
		t.Fatalf("content negotiation headers wrong: %v", req.Header)
	}
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatal(err)
	}
	if schemas, _ := sent["schemas"].([]any); len(schemas) != 1 || schemas[0] != UserSchema {
		t.Fatalf("schemas not filled in on the wire: %v", sent["schemas"])
	}
	if _, has := sent["id"]; has {
		t.Fatalf("a create must not send an id: %s", body)
	}

	found, err := c.FindUser(ctx, "externalId", "local-42")
	if err != nil || found.ID != created.ID {
		t.Fatalf("FindUser: %v %+v", err, found)
	}
	got, err := c.GetUser(ctx, created.ID)
	if err != nil || got.UserName != "alice" {
		t.Fatalf("GetUser: %v %+v", err, got)
	}

	local.DisplayName = "Alice Q"
	replaced, err := c.ReplaceUser(ctx, created.ID, local)
	if err != nil || replaced.DisplayName != "Alice Q" || replaced.ID != created.ID {
		t.Fatalf("ReplaceUser: %v %+v", err, replaced)
	}

	patched, err := c.PatchUser(ctx, created.ID, PatchOperation{Op: "replace", Path: "active", Value: false})
	if err != nil || patched.Active {
		t.Fatalf("PatchUser: %v %+v", err, patched)
	}

	if err := c.DeleteUser(ctx, created.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := c.DeleteUser(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: want ErrNotFound, got %v", err)
	}
	if _, err := c.GetUser(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser after delete: want ErrNotFound, got %v", err)
	}
}

func TestCreateConflictIsAnErrorNotSuccess(t *testing.T) {
	f := newFake(t)
	c := f.client()
	ctx := context.Background()
	if _, err := c.CreateUser(ctx, User{UserName: "bob"}); err != nil {
		t.Fatal(err)
	}
	_, err := c.CreateUser(ctx, User{UserName: "bob"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	var se *Error
	if !errors.As(err, &se) || se.Status != 409 || se.ScimType != "uniqueness" {
		t.Fatalf("want *Error with 409 uniqueness, got %#v", err)
	}
}

func TestCreateWithoutAnIDIsAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"schemas":["` + UserSchema + `"],"userName":"x"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	if _, err := c.CreateUser(context.Background(), User{UserName: "x"}); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("want ErrMalformedResponse, got %v", err)
	}
}

func TestFindUserZeroAndManyResults(t *testing.T) {
	var resources, total string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"schemas":["` + ListResponseSchema + `"],"totalResults":` + total + `,"Resources":[` + resources + `]}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	total = "0"
	if _, err := c.FindUser(context.Background(), "userName", "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero results: want ErrNotFound, got %v", err)
	}
	resources, total = `{"id":"1","userName":"a"},{"id":"2","userName":"a"}`, "2"
	if _, err := c.FindUser(context.Background(), "userName", "a"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("two results: want ErrAmbiguous, got %v", err)
	}
}

func TestFilterIsEscapedAndAttributeRestricted(t *testing.T) {
	var gotFilter string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("filter")
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 1, "Resources": []User{{ID: "1", UserName: `a"b\c or userName pr`}}})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	if _, err := c.FindUser(context.Background(), "userName", `a"b\c or userName pr`); err != nil {
		t.Fatal(err)
	}
	if want := `userName eq "a\"b\\c or userName pr"`; gotFilter != want {
		t.Fatalf("filter %q, want %q", gotFilter, want)
	}
	gotFilter = ""
	for _, attr := range []string{"", `userName eq "x" or`, "displayName", "emails.value", "externalid"} {
		if _, err := c.FindUser(context.Background(), attr, "v"); err == nil {
			t.Fatalf("attribute %q accepted", attr)
		}
	}
	if gotFilter != "" {
		t.Fatal("a bad attribute reached the server")
	}
}

func TestResourceIDsAreEscapedAndRequired(t *testing.T) {
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL + "/scim/v2/", Token: token, HTTPClient: srv.Client()}
	if err := c.DeleteUser(context.Background(), "a/b?c d"); err != nil {
		t.Fatal(err)
	}
	if want := "/scim/v2/Users/a%2Fb%3Fc%20d"; gotPath != want {
		t.Fatalf("path %q, want %q", gotPath, want)
	}
	gotPath = ""
	for _, id := range []string{"", ".", ".."} {
		if err := c.DeleteUser(context.Background(), id); err == nil {
			t.Fatalf("id %q accepted", id)
		}
		if _, err := c.GetUser(context.Background(), id); err == nil {
			t.Fatalf("id %q accepted", id)
		}
	}
	if gotPath != "" {
		t.Fatalf("an empty or dot id reached the server: %s", gotPath)
	}
}

func TestPlaintextOrMalformedBaseURLIsRefusedWithoutARequest(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a plaintext server")
	}))
	defer plain.Close()
	for _, base := range []string{
		plain.URL,
		"https://user:pw@host/scim/v2",
		"https://host/scim/v2?x=1",
		"https://host/scim/v2#f",
		"https:///scim/v2",
		"",
		"://bad",
	} {
		c := &Client{BaseURL: base, Token: token, HTTPClient: plain.Client()}
		if err := c.Ping(context.Background()); !errors.Is(err, ErrInsecureURL) {
			t.Errorf("%q: want ErrInsecureURL, got %v", base, err)
		}
	}
	c := &Client{BaseURL: "https://host/scim/v2", HTTPClient: plain.Client()}
	if err := c.Ping(context.Background()); !errors.Is(err, ErrNoToken) {
		t.Errorf("empty token: want ErrNoToken, got %v", err)
	}
}

func TestRedirectIsRefusedAndTokenNotReplayed(t *testing.T) {
	var leaked bool
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer sink.Close()
	bouncer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/Users", http.StatusTemporaryRedirect)
	}))
	defer bouncer.Close()
	// One client trusting both certificates would follow if the redirect policy allowed it.
	c := &Client{BaseURL: bouncer.URL, Token: token, HTTPClient: bouncer.Client()}
	_, err := c.CreateUser(context.Background(), User{UserName: "x"})
	// Go copies Authorization to a redirect on the same hostname, port aside, so without the
	// client's own refusal this sink does receive the bearer. Checked first: it is the claim.
	if leaked {
		t.Fatal("bearer token followed the redirect")
	}
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("want a redirect refusal, got %v", err)
	}
}

func TestErrorBodyIsBoundedAndPrintable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(429)
		detail := "slow\x1b[31m down\n" + strings.Repeat("A", 5000)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "429", "detail": detail})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	_, err := c.GetUser(context.Background(), "1")
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("want *Error, got %v", err)
	}
	if !errors.Is(err, ErrThrottled) || se.Status != 429 || se.RetryAfter != 7*time.Second {
		t.Fatalf("throttle not surfaced: %#v", se)
	}
	if strings.ContainsAny(se.Detail, "\x1b\n") || len(se.Detail) > 210 || !strings.HasPrefix(se.Detail, "slow[31m down ") {
		t.Fatalf("detail not sanitised: %q", se.Detail)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("token in error text")
	}
}

func TestUnauthorizedAndNonJSONErrors(t *testing.T) {
	status := 401
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("<html>nope</html>"))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	err := c.Ping(context.Background())
	var se *Error
	if !errors.Is(err, ErrUnauthorized) || !errors.As(err, &se) || se.Status != 401 || se.Detail != "" {
		t.Fatalf("html 401: got %v / %#v", err, se)
	}
	status = 403
	if err := c.Ping(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("403: got %v", err)
	}
	status = 503
	if err := c.Ping(context.Background()); !errors.Is(err, ErrThrottled) {
		t.Fatalf("503: got %v", err)
	}
	status = 500
	if err := c.Ping(context.Background()); errors.Is(err, ErrThrottled) || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) {
		t.Fatalf("500 matched a sentinel it should not: %v", err)
	}
}

func TestOversizedSuccessBodyIsRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":"1","displayName":"` + strings.Repeat("A", maxBody) + `"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	if _, err := c.GetUser(context.Background(), "1"); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("want ErrMalformedResponse, got %v", err)
	}
}

func TestPatchWireShape(t *testing.T) {
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		if r.Method != http.MethodPatch {
			t.Errorf("method %s", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	if _, err := c.PatchUser(context.Background(), "1", PatchOperation{Op: "replace", Path: "active", Value: false}); err != nil {
		t.Fatal(err)
	}
	want := `{"schemas":["` + PatchOpSchema + `"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	if strings.TrimSpace(string(body)) != want {
		t.Fatalf("patch body %s\nwant %s", body, want)
	}
	if _, err := c.PatchUser(context.Background(), "1"); err == nil {
		t.Fatal("a PATCH with no operations was sent")
	}
}

func TestRetryAfterIsBoundedAndNonNegative(t *testing.T) {
	cases := map[string]time.Duration{
		"":                     0,
		"7":                    7 * time.Second,
		"3600":                 time.Hour,
		"3601":                 time.Hour,
		"9000000000":           time.Hour,
		"10000000000":          time.Hour,
		"99999999999999999999": 0, // overflows the parser: garbage, so no hint
		"-5":                   0,
		"soon":                 0,
		time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat):   0,
		time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat): time.Hour,
	}
	for in, want := range cases {
		if got := retryAfter(in); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", in, got, want)
		}
	}
	if got := retryAfter(time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)); got <= 0 || got > 10*time.Second {
		t.Errorf("near-future date gave %v", got)
	}
}

func TestUnexpectedStatusesAreNotSuccess(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	ctx := context.Background()
	// A 3xx without Location is handed back as a response, not followed. 1xx never reaches
	// the client as a final status, so it is not here.
	for _, status = range []int{302, 202, 206, 304} {
		if err := c.DeleteUser(ctx, "1"); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("DeleteUser on %d: want ErrMalformedResponse, got %v", status, err)
		}
	}
	status = 200
	for _, body = range []string{"", "<html>portal</html>", `[]`, `"ok"`} {
		if err := c.Ping(ctx); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("Ping on 200 %q: want ErrMalformedResponse, got %v", body, err)
		}
	}
	body = ` {"patch":{"supported":true}}`
	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping on a JSON object: %v", err)
	}
}

func TestTokenIsRedactedFromErrorDetail(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 401, "invalid "+token, "token "+token+" was rejected; also "+token)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	err := c.Ping(context.Background())
	var se *Error
	if !errors.As(err, &se) || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(se.Detail, token) || strings.Contains(se.ScimType, token) {
		t.Fatalf("token survived redaction: %q / %q", se.ScimType, se.Detail)
	}
	if se.Detail != "token [token] was rejected; also [token]" || se.ScimType != "invalid [token]" {
		t.Fatalf("unexpected redaction: %q / %q", se.ScimType, se.Detail)
	}
}

func TestFindUserRefusesAUserThatDoesNotMatch(t *testing.T) {
	// A server that ignores the filter and returns its one user, with an honest total.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 1, "Resources": []User{{ID: "srv-9", ExternalID: "someone-else", UserName: "Carol"}}})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	ctx := context.Background()
	if _, err := c.FindUser(ctx, "externalId", "local-42"); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("unrelated user by externalId: want ErrMalformedResponse, got %v", err)
	}
	if _, err := c.FindUser(ctx, "userName", "alice"); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("unrelated user by userName: want ErrMalformedResponse, got %v", err)
	}
	if u, err := c.FindUser(ctx, "userName", "carol"); err != nil || u.ID != "srv-9" {
		t.Fatalf("userName is not caseExact; got %v %+v", err, u)
	}
	if _, err := c.FindUser(ctx, "externalId", "SOMEONE-ELSE"); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("externalId is caseExact; got %v", err)
	}
}

func TestTransportErrorsDoNotCarryTheQuery(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	_, err := c.FindUser(context.Background(), "externalId", "person-42")
	if err == nil || strings.Contains(err.Error(), "person-42") || strings.Contains(err.Error(), "filter") {
		t.Fatalf("query leaked into the transport error: %v", err)
	}
}

// A replace that revokes a user's last role must say so: a server may keep an attribute a PUT
// leaves out (RFC 7644 section 3.5.1), so roles goes on the wire as [] and is never omitted.
func TestCreateAndReplaceAlwaysSendRoles(t *testing.T) {
	f := newFake(t)
	c := f.client()
	ctx := context.Background()

	admin := User{ExternalID: "local-7", UserName: "bob", Active: true,
		Roles: []MultiValue{{Value: "admin"}}}
	created, err := c.CreateUser(ctx, admin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, body := f.last(); !strings.Contains(string(body), `"roles":[{"value":"admin"}]`) {
		t.Fatalf("create lost the roles: %s", body)
	}

	admin.Roles = nil
	if _, err := c.ReplaceUser(ctx, created.ID, admin); err != nil {
		t.Fatalf("ReplaceUser: %v", err)
	}
	_, body := f.last()
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatal(err)
	}
	if string(sent["roles"]) != "[]" {
		t.Fatalf("a replace without roles must send roles: [], sent %s", body)
	}

	if _, err := c.CreateUser(ctx, User{UserName: "carol", Active: true, Roles: []MultiValue{}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, body := f.last(); !strings.Contains(string(body), `"roles":[]`) {
		t.Fatalf("a create without roles must send roles: [], sent %s", body)
	}
}

// Only a list that says "no matches" is ErrNotFound. Anything else would let a caller create a
// duplicate or skip a deactivation on a broken or paged answer.
func TestFindUserNotFoundOnlyFromAnHonestEmptyList(t *testing.T) {
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	ctx := context.Background()
	for _, b := range []string{`{"totalResults":0,"Resources":[]}`, `{"totalResults":0}`, `{"Resources":[]}`} {
		body = b
		if _, err := c.FindUser(ctx, "userName", "nobody"); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: want ErrNotFound, got %v", b, err)
		}
	}
	for _, b := range []string{`{"totalResults":1,"Resources":[]}`, `{}`, `{"error":"filtering unsupported"}`, ``} {
		body = b
		if _, err := c.FindUser(ctx, "userName", "nobody"); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("%q: want ErrMalformedResponse, got %v", b, err)
		}
	}
	body = `{"Resources":[{"id":"1","userName":"a"}]}`
	if u, err := c.FindUser(ctx, "userName", "a"); err != nil || u.ID != "1" {
		t.Errorf("one result without totalResults: %v %+v", err, u)
	}
}

// An empty value matches a user without the attribute, and that user passes the match check.
func TestFindUserRefusesAnEmptyValue(t *testing.T) {
	f := newFake(t)
	for _, v := range []string{"", "  "} {
		if _, err := f.client().FindUser(context.Background(), "externalId", v); err == nil {
			t.Fatalf("FindUser(%q) was sent", v)
		}
	}
	if len(f.requests) != 0 {
		t.Fatalf("%d requests sent", len(f.requests))
	}
}

// The redirect target carries FindUser's filter, which names a user; the error must not.
func TestRedirectErrorOmitsTheQuery(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/?"+r.URL.RawQuery, http.StatusMovedPermanently)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: token, HTTPClient: srv.Client()}
	_, err := c.FindUser(context.Background(), "userName", "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "redirect") || strings.Contains(err.Error(), "alice") {
		t.Fatalf("want a redirect refusal without the filter, got %v", err)
	}
}
