package oidcverify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type issuer struct {
	t       *testing.T
	key     *rsa.PrivateKey
	kid     string
	srv     *httptest.Server
	fetches atomic.Int32
	jwks    func() any
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{t: t, key: key, kid: "k1"}
	is.jwks = func() any {
		return map[string]any{"keys": []any{jwkFor(is.kid, &key.PublicKey)}}
	}
	is.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.fetches.Add(1)
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(is.jwks())
	}))
	t.Cleanup(is.srv.Close)
	return is
}

func jwkFor(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}

func seg(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (is *issuer) mint(header map[string]any, claims map[string]any, key *rsa.PrivateKey) string {
	if header == nil {
		header = map[string]any{"alg": "RS256", "kid": is.kid, "typ": "JWT"}
	}
	if key == nil {
		key = is.key
	}
	signing := seg(header) + "." + seg(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		is.t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (is *issuer) verifier() *Verifier {
	return &Verifier{Issuer: is.srv.URL, Audience: "kynotes", HTTPClient: is.srv.Client()}
}

func good(is *issuer) map[string]any {
	now := time.Now()
	return map[string]any{"iss": is.srv.URL, "sub": "user-1", "aud": "kynotes", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "role": "admin"}
}

func TestVerifyAcceptsAGoodToken(t *testing.T) {
	is := newIssuer(t)
	c, err := is.verifier().Verify(context.Background(), is.mint(nil, good(is), nil))
	if err != nil || c.Subject != "user-1" || c.String("role") != "admin" || c.KeyID != "k1" || len(c.Audience) != 1 {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestVerifyRefusesEachBadClaim(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	now := time.Now()
	cases := []struct {
		name string
		mut  func(m map[string]any)
		want error
	}{
		{"wrong issuer", func(m map[string]any) { m["iss"] = "https://evil.example" }, ErrIssuer},
		{"wrong audience", func(m map[string]any) { m["aud"] = "kypost" }, ErrAudience},
		{"multi audience off", func(m map[string]any) { m["aud"] = []string{"kynotes", "kypost"} }, ErrAudience},
		{"no audience", func(m map[string]any) { delete(m, "aud") }, ErrAudience},
		{"expired", func(m map[string]any) { m["exp"] = now.Add(-2 * time.Minute).Unix() }, ErrExpired},
		{"no exp", func(m map[string]any) { delete(m, "exp") }, ErrExpired},
		{"nbf future", func(m map[string]any) { m["nbf"] = now.Add(time.Hour).Unix() }, ErrNotYetValid},
		{"iat future", func(m map[string]any) { m["iat"] = now.Add(time.Hour).Unix() }, ErrIssuedInFuture},
		{"no sub", func(m map[string]any) { delete(m, "sub") }, ErrNoSubject},
		{"exp string", func(m map[string]any) { m["exp"] = "tomorrow" }, ErrMalformed},
	}
	for _, tc := range cases {
		m := good(is)
		tc.mut(m)
		if _, err := v.Verify(context.Background(), is.mint(nil, m, nil)); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	m := good(is)
	m["aud"] = []string{"kynotes", "kypost"}
	v.AllowMultipleAudiences = true
	if _, err := v.Verify(context.Background(), is.mint(nil, m, nil)); err != nil {
		t.Errorf("multi audience opt-in: %v", err)
	}
	m = good(is)
	m["exp"] = float64(now.Add(time.Hour).Unix()) + 0.5
	if _, err := v.Verify(context.Background(), is.mint(nil, m, nil)); err != nil {
		t.Errorf("float exp: %v", err)
	}
}

func TestVerifyRefusesAlgorithmConfusionAndBadSignatures(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	claims := good(is)
	for name, header := range map[string]map[string]any{
		"none":  {"alg": "none", "kid": "k1"},
		"HS256": {"alg": "HS256", "kid": "k1"},
		"RS512": {"alg": "RS512", "kid": "k1"},
		"ES256": {"alg": "ES256", "kid": "k1"},
	} {
		if _, err := v.Verify(context.Background(), is.mint(header, claims, nil)); !errors.Is(err, ErrAlgorithm) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// alg none with an empty signature segment, the classic bypass.
	tok := seg(map[string]any{"alg": "none"}) + "." + seg(claims) + "."
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrAlgorithm) {
		t.Errorf("none with empty sig: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(context.Background(), is.mint(nil, claims, other)); !errors.Is(err, ErrSignature) {
		t.Errorf("other key: %v", err)
	}
	good := is.mint(nil, claims, nil)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + seg(map[string]any{"iss": is.srv.URL, "sub": "user-2", "aud": "kynotes", "exp": time.Now().Add(time.Hour).Unix()}) + "." + parts[2]
	if _, err := v.Verify(context.Background(), tampered); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered payload: %v", err)
	}
	if _, err := v.Verify(context.Background(), parts[0]+"."+parts[1]); !errors.Is(err, ErrMalformed) {
		t.Errorf("two parts: %v", err)
	}
	padded := parts[0] + "." + parts[1] + "==." + parts[2]
	if _, err := v.Verify(context.Background(), padded); !errors.Is(err, ErrMalformed) {
		t.Errorf("padded segment: %v", err)
	}
	if _, err := v.Verify(context.Background(), is.mint(map[string]any{"alg": "RS256", "kid": "unknown"}, claims, nil)); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown kid: %v", err)
	}
}

func TestJWKSIgnoresNonRSAKeysUnderTheSameKid(t *testing.T) {
	is := newIssuer(t)
	is.jwks = func() any {
		return map[string]any{"keys": []any{
			map[string]any{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "AA", "y": "AA"},
			map[string]any{"kty": "oct", "kid": "k1", "k": "AAAA"},
		}}
	}
	if _, err := is.verifier().Verify(context.Background(), is.mint(nil, good(is), nil)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("%v", err)
	}
}

func TestJWKSRefreshIsRateLimitedAndStaleSetSurvivesOutage(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	v.MinRefresh = time.Hour
	if _, err := v.Verify(context.Background(), is.mint(nil, good(is), nil)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _ = v.Verify(context.Background(), is.mint(map[string]any{"alg": "RS256", "kid": "k-new"}, good(is), nil))
	}
	if n := is.fetches.Load(); n != 1 {
		t.Fatalf("unknown kids fetched %d times inside MinRefresh", n)
	}
	// Rotation: after MinRefresh the new kid is fetched once.
	base := time.Now()
	v.Now = func() time.Time { return base.Add(2 * time.Hour) }
	is.kid = "k-new"
	claims := good(is)
	claims["exp"] = base.Add(3 * time.Hour).Unix()
	claims["iat"] = base.Add(2 * time.Hour).Unix()
	if _, err := v.Verify(context.Background(), is.mint(nil, claims, nil)); err != nil {
		t.Fatalf("rotated kid: %v", err)
	}
	if n := is.fetches.Load(); n != 2 {
		t.Fatalf("fetched %d", n)
	}
	// Issuer down: the known key still verifies.
	is.srv.Close()
	v.Now = func() time.Time { return base.Add(4 * time.Hour) }
	claims["exp"] = base.Add(5 * time.Hour).Unix()
	claims["iat"] = base.Add(4 * time.Hour).Unix()
	if _, err := v.Verify(context.Background(), is.mint(nil, claims, nil)); err != nil {
		t.Fatalf("stale set during outage: %v", err)
	}
}

func TestNonce(t *testing.T) {
	is := newIssuer(t)
	claims := good(is)
	claims["nonce"] = "n-1"
	tok := is.mint(nil, claims, nil)
	if _, err := is.verifier().VerifyWithNonce(context.Background(), tok, "n-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := is.verifier().VerifyWithNonce(context.Background(), tok, "n-2"); !errors.Is(err, ErrNonce) {
		t.Fatalf("%v", err)
	}
}

func TestMiddleware(t *testing.T) {
	is := newIssuer(t)
	var got Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	var rejected []error
	h := is.verifier().Middleware(func(_ *http.Request, err error) { rejected = append(rejected, err) })(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+is.mint(nil, good(is), nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent || got.Subject != "user-1" {
		t.Fatalf("%d %+v", w.Code, got)
	}
	for _, auth := range []string{"", "Basic abc", "Bearer ", "Bearer not.a.jwt"} {
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" || !strings.Contains(w.Body.String(), "invalid_token") {
			t.Errorf("%q: %d %s", auth, w.Code, w.Body.String())
		}
	}
	if len(rejected) != 4 {
		t.Errorf("rejections %v", rejected)
	}
}

func TestUnknownKidDoesNotStallVerification(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	if _, err := v.Verify(context.Background(), is.mint(nil, good(is), nil)); err != nil {
		t.Fatal(err)
	}
	// The issuer now hangs. Unknown kids may trigger at most one refresh per MinRefresh,
	// and that one costs at most the client timeout.
	release := make(chan struct{})
	entered := atomic.Int32{}
	hang := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		<-release
	}))
	defer func() { close(release); hang.Close() }()
	v.JWKSURL = hang.URL + "/.well-known/jwks.json"
	hc := hang.Client()
	hc.Timeout = 200 * time.Millisecond
	v.HTTPClient = hc
	v.MinRefresh = time.Hour
	// Only the cached set is fresh for known kids; force a stale set so a known kid would
	// also want a refresh, then check it is served from the stale set without waiting.
	start := time.Now()
	for i := 0; i < 20; i++ {
		_, err := v.Verify(context.Background(), is.mint(map[string]any{"alg": "RS256", "kid": "k-unknown"}, good(is), nil))
		if !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrJWKS) {
			t.Fatalf("unknown kid: %v", err)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("20 unknown-kid verifications took %s; the failed fetch is not rate-limited", d)
	}
	if n := entered.Load(); n > 2 {
		t.Fatalf("issuer entered %d times", n)
	}
	if _, err := v.Verify(context.Background(), is.mint(nil, good(is), nil)); err != nil {
		t.Fatalf("known kid during outage: %v", err)
	}
}

func TestConcurrentUnknownKidsShareOneFetch(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	v.MinRefresh = time.Hour
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.Verify(context.Background(), is.mint(nil, good(is), nil))
		}()
	}
	wg.Wait()
	if n := is.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches for one cold start", n)
	}
}

func TestPlaintextIssuerIsRefusedWithoutARequest(t *testing.T) {
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer plain.Close()
	is := newIssuer(t)
	tok := is.mint(nil, good(is), nil)
	for _, v := range []*Verifier{
		{Issuer: plain.URL, Audience: "kynotes", HTTPClient: plain.Client()},
		{Issuer: is.srv.URL, JWKSURL: plain.URL + "/.well-known/jwks.json", Audience: "kynotes", HTTPClient: plain.Client()},
		{Issuer: "https://user:pw@issuer.example", Audience: "kynotes"},
	} {
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrInsecureIssuer) {
			t.Errorf("%s / %s: %v", v.Issuer, v.JWKSURL, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("plaintext endpoint was contacted %d times", hits.Load())
	}
}

func TestJWKSRedirectIsRefused(t *testing.T) {
	is := newIssuer(t)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, is.srv.URL+"/.well-known/jwks.json", http.StatusFound)
	}))
	defer redirector.Close()
	v := &Verifier{Issuer: is.srv.URL, JWKSURL: redirector.URL + "/jwks", Audience: "kynotes", HTTPClient: redirector.Client()}
	if _, err := v.Verify(context.Background(), is.mint(nil, good(is), nil)); !errors.Is(err, ErrJWKS) {
		t.Fatalf("%v", err)
	}
}

// A caller that hangs up mid-fetch must not cancel the shared JWKS fetch: the attempt is
// recorded for everyone, so a cancelled one used to lock every user out of a new key for
// MinRefresh.
func TestCancelledCallerDoesNotSpoilTheSharedFetch(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = v.Verify(ctx, is.mint(map[string]any{"alg": "RS256", "kid": "junk"}, good(is), nil))
	if _, err := v.Verify(context.Background(), is.mint(nil, good(is), nil)); err != nil {
		t.Fatalf("valid token after a cancelled caller: %v", err)
	}
}

// The caller's own deadline still bounds its wait while the shared fetch carries on.
func TestCallerDeadlineBoundsTheWaitForAFetch(t *testing.T) {
	is := newIssuer(t)
	release := make(chan struct{})
	hang := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer func() { close(release); hang.Close() }()
	v := is.verifier()
	v.JWKSURL = hang.URL + "/.well-known/jwks.json"
	hc := hang.Client()
	hc.Timeout = 5 * time.Second
	v.HTTPClient = hc
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := v.Verify(ctx, is.mint(nil, good(is), nil)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller's deadline", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("caller waited %s for a fetch past its deadline", d)
	}
}

// A caller that arrives while someone else's fetch is in flight waits on that fetch, and
// its own deadline still ends the wait.
func TestFollowerDeadlineBoundsTheWaitForAFetch(t *testing.T) {
	is := newIssuer(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	hang := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	defer func() { close(release); hang.Close() }()
	v := is.verifier()
	v.JWKSURL = hang.URL + "/.well-known/jwks.json"
	hc := hang.Client()
	hc.Timeout = 5 * time.Second
	v.HTTPClient = hc
	go func() { _, _ = v.Verify(context.Background(), is.mint(nil, good(is), nil)) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := v.Verify(ctx, is.mint(map[string]any{"alg": "RS256", "kid": "other"}, good(is), nil)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the follower's deadline", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("follower waited %s past its deadline", d)
	}
}
