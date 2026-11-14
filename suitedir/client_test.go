package suitedir

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var secret32 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

// serve answers every request with status and body; the returned func yields the last request.
func serve(t *testing.T, status int, body string) (*Client, func() *http.Request) {
	t.Helper()
	var mu sync.Mutex
	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Clone(context.Background())
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := &Client{Issuer: srv.URL + "/", ClientID: "kycalendar", ClientSecret: "s3:cr/t"}
	return c, func() *http.Request { mu.Lock(); defer mu.Unlock(); return last }
}

func TestAppsSendsBasicAuthAndDropsInvalidEntries(t *testing.T) {
	c, lastReq := serve(t, 200, `{"apps":[
		{"id":"kypost","name":"KyPost","url":"https://mail.example.com/api/auth/oidc/login"},
		{"id":"plain","name":"Plain","url":"http://plain.example.com"},
		{"id":"","name":"NoID","url":"https://x.example.com"},
		{"id":"noname","name":"","url":"https://x.example.com"},
		{"id":"rel","name":"Rel","url":"/relative"},
		{"id":"cred","name":"Cred","url":"https://u:p@x.example.com"}]}`)
	apps, err := c.Apps(context.Background(), "user 1")
	if err != nil {
		t.Fatal(err)
	}
	req := lastReq()
	want := App{ID: "kypost", Name: "KyPost", URL: "https://mail.example.com/api/auth/oidc/login"}
	if len(apps) != 1 || apps[0] != want {
		t.Fatalf("apps = %+v", apps)
	}
	if req.URL.Path != "/api/suite/apps" || req.URL.Query().Get("sub") != "user 1" {
		t.Fatalf("request = %s", req.URL)
	}
	if id, secret, ok := req.BasicAuth(); !ok || id != "kycalendar" || secret != "s3:cr/t" {
		t.Fatalf("basic auth = %q %q %v", id, secret, ok)
	}
}

func TestAppsWithoutSubSendsNoQuery(t *testing.T) {
	c, lastReq := serve(t, 200, `{"apps":[]}`)
	apps, err := c.Apps(context.Background(), "")
	if err != nil || len(apps) != 0 {
		t.Fatalf("apps = %v, %v", apps, err)
	}
	if req := lastReq(); req.URL.RawQuery != "" {
		t.Fatalf("query = %q", req.URL.RawQuery)
	}
}

func TestPeer(t *testing.T) {
	c, lastReq := serve(t, 200, `{"client":"kypost","url":"https://mail.example.com","secret":"`+secret32+`"}`)
	p, err := c.Peer(context.Background(), "kypost")
	if err != nil {
		t.Fatal(err)
	}
	req := lastReq()
	if p.Client != "kypost" || p.URL != "https://mail.example.com" || !bytes.Equal(p.Secret, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("peer = %+v", p)
	}
	if req.URL.Path != "/api/suite/peer" || req.URL.Query().Get("client") != "kypost" {
		t.Fatalf("request = %s", req.URL)
	}
}

func TestStatusErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{401, `{"error":"invalid_client"}`, ErrUnauthorized},
		{404, `{"error":"no_peer"}`, ErrNoPeer},
		{404, `not found`, nil},
		{500, `{"error":"no_peer"}`, nil},
		{302, ``, nil},
	} {
		c, _ := serve(t, tc.status, tc.body)
		_, err := c.Peer(context.Background(), "kypost")
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) ||
			tc.want == nil && (errors.Is(err, ErrNoPeer) || errors.Is(err, ErrUnauthorized)) {
			t.Errorf("%d %s: err = %v", tc.status, tc.body, err)
		}
	}
	c, _ := serve(t, 401, `{"error":"invalid_client"}`)
	if _, err := c.Apps(context.Background(), ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("apps 401: err = %v", err)
	}
}

func TestMalformedBodiesAreErrors(t *testing.T) {
	for _, body := range []string{``, `nope`, `{}`, `{"apps":{}}`, `{"apps":[1]}`} {
		c, _ := serve(t, 200, body)
		if apps, err := c.Apps(context.Background(), ""); err == nil {
			t.Errorf("apps %q = %v, want error", body, apps)
		}
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	long := base64.StdEncoding.EncodeToString(make([]byte, 33))
	for _, body := range []string{
		``, `nope`, `{}`,
		`{"client":"kypost","url":"https://m.example.com","secret":"` + short + `"}`,
		`{"client":"kypost","url":"https://m.example.com","secret":"` + long + `"}`,
		`{"client":"kypost","url":"https://m.example.com","secret":"!!not base64!!"}`,
		`{"client":"kypost","url":"http://m.example.com","secret":"` + secret32 + `"}`,
		`{"client":"kypost","url":"","secret":"` + secret32 + `"}`,
		`{"client":"kyother","url":"https://m.example.com","secret":"` + secret32 + `"}`,
	} {
		c, _ := serve(t, 200, body)
		if p, err := c.Peer(context.Background(), "kypost"); err == nil {
			t.Errorf("peer %q = %+v, want error", body, p)
		}
	}
}

func TestOversizeBodyIsRefused(t *testing.T) {
	c, _ := serve(t, 200, `{"apps":[],"pad":"`+strings.Repeat("a", maxBody)+`"}`)
	if _, err := c.Apps(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestRedirectIsRefusedAndCredentialsNotReplayed(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
	}))
	defer target.Close()
	srv := httptest.NewServer(http.RedirectHandler(target.URL+"/api/suite/apps", http.StatusFound))
	defer srv.Close()
	c := &Client{Issuer: srv.URL, ClientID: "a", ClientSecret: "b", HTTP: &http.Client{}}
	if _, err := c.Apps(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v", err)
	}
	if hit.Load() {
		t.Fatal("redirect was followed")
	}
}

func TestInsecureIssuerIsRefusedWithoutARequest(t *testing.T) {
	for _, issuer := range []string{
		"", "http://id.example.com", "http://localhost:8080", "ftp://127.0.0.1",
		"https://u:p@id.example.com", "https://id.example.com?x=1", "https:///nohost",
	} {
		c := &Client{Issuer: issuer, HTTP: &http.Client{Transport: failTransport{t}}}
		if _, err := c.Apps(context.Background(), ""); !errors.Is(err, ErrInsecureIssuer) {
			t.Errorf("%q: err = %v", issuer, err)
		}
	}
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("request sent to %s", r.URL)
	return nil, errors.New("no")
}

func TestIssuerPathIsKept(t *testing.T) {
	var path string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"apps":[]}`))
	}))
	defer srv.Close()
	c := &Client{Issuer: srv.URL + "/kyid/", HTTP: srv.Client()}
	if _, err := c.Apps(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if path != "/kyid/api/suite/apps" {
		t.Fatalf("path = %q", path)
	}
}

func TestPeopleSearch(t *testing.T) {
	c, lastReq := serve(t, 200, `{"people":[
		{"sub":"u1","name":"Alice Example","email":"alice@example.com"},
		{"sub":"","name":"NoSub","email":"x@example.com"},
		{"sub":"u3","name":"NoEmail","email":""}]}`)
	people, err := c.People(context.Background(), "me 1", "ali", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := Person{Sub: "u1", Name: "Alice Example", Email: "alice@example.com"}
	if len(people) != 1 || people[0] != want {
		t.Fatalf("people = %+v", people)
	}
	req := lastReq()
	q := req.URL.Query()
	if req.URL.Path != "/api/suite/people" || q.Get("sub") != "me 1" || q.Get("q") != "ali" ||
		q.Get("limit") != "5" || q.Has("email") {
		t.Fatalf("request = %s", req.URL)
	}
	if id, _, ok := req.BasicAuth(); !ok || id != "kycalendar" {
		t.Fatal("no basic auth")
	}
	if _, err := c.People(context.Background(), "me", "ali", 0); err != nil {
		t.Fatal(err)
	}
	if lastReq().URL.Query().Has("limit") {
		t.Fatal("limit 0 was sent")
	}
}

func TestResolve(t *testing.T) {
	c, lastReq := serve(t, 200, `{"people":[{"sub":"u1","name":"A","email":"a@example.com"}]}`)
	people, err := c.Resolve(context.Background(), "me", []string{"a@example.com", "B@example.com"})
	if err != nil || len(people) != 1 || people[0].Sub != "u1" {
		t.Fatalf("people = %+v, %v", people, err)
	}
	q := lastReq().URL.Query()
	if got := q["email"]; len(got) != 2 || got[0] != "a@example.com" || got[1] != "B@example.com" || q.Has("q") {
		t.Fatalf("query = %v", q)
	}

	c = &Client{Issuer: "https://id.example.com", HTTP: &http.Client{Transport: failTransport{t}}}
	if people, err := c.Resolve(context.Background(), "me", nil); err != nil || people == nil || len(people) != 0 {
		t.Fatalf("no emails = %v, %v", people, err)
	}
	if _, err := c.People(context.Background(), "", "ali", 0); err == nil {
		t.Fatal("empty sub accepted")
	}
	if _, err := c.Resolve(context.Background(), "", []string{"a@example.com"}); err == nil {
		t.Fatal("empty sub accepted")
	}
}

func TestPeopleErrorsAndMalformedBodies(t *testing.T) {
	for _, body := range []string{``, `nope`, `{}`, `{"people":{}}`, `{"people":[1]}`} {
		c, _ := serve(t, 200, body)
		if p, err := c.People(context.Background(), "me", "ali", 0); err == nil {
			t.Errorf("people %q = %v, want error", body, p)
		}
	}
	c, _ := serve(t, 401, `{"error":"invalid_client"}`)
	if _, err := c.Resolve(context.Background(), "me", []string{"a@example.com"}); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("401: err = %v", err)
	}
	c, _ = serve(t, 400, `{"error":"invalid_request"}`)
	if _, err := c.People(context.Background(), "me", "a", 0); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Errorf("400: err = %v", err)
	}
	c, _ = serve(t, 200, `{"people":[],"pad":"`+strings.Repeat("a", maxBody)+`"}`)
	if _, err := c.People(context.Background(), "me", "ali", 0); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversize: err = %v", err)
	}
}

func TestPeopleRedirectRefusedAndErrorCarriesNoQuery(t *testing.T) {
	srv := httptest.NewServer(http.RedirectHandler("https://elsewhere.example/", http.StatusFound))
	defer srv.Close()
	c := &Client{Issuer: srv.URL, ClientID: "a", ClientSecret: "b"}
	_, err := c.Resolve(context.Background(), "secret-sub", []string{"alice@example.com"})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v", err)
	}
	srv.Close()
	_, err2 := c.People(context.Background(), "secret-sub", "alice", 0)
	for _, e := range []error{err, err2} {
		if e == nil || strings.Contains(e.Error(), "secret-sub") || strings.Contains(e.Error(), "alice") {
			t.Fatalf("error leaks the query: %v", e)
		}
	}
	c.Issuer = "http://id.example.com"
	if _, err := c.People(context.Background(), "me", "ali", 0); !errors.Is(err, ErrInsecureIssuer) {
		t.Fatalf("insecure issuer: err = %v", err)
	}
}
