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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func logoutFixture(is *issuer, now time.Time) (map[string]any, map[string]any) {
	return map[string]any{"alg": "RS256", "kid": is.kid, "typ": "logout+jwt"},
		map[string]any{
			"iss": is.srv.URL, "aud": "kynotes", "sub": "user-1", "sid": "session-1",
			"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": "logout-1",
			"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
		}
}

func TestVerifyLogoutScopesAndReplayBoundary(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	v.Now = func() time.Time { return now }
	for _, scope := range []string{"both", "subject", "session"} {
		t.Run(scope, func(t *testing.T) {
			header, claims := logoutFixture(is, now)
			if scope == "subject" {
				delete(claims, "sid")
			}
			if scope == "session" {
				delete(claims, "sub")
			}
			token := is.mint(header, claims, nil)
			c, err := v.VerifyLogout(context.Background(), token)
			if err != nil {
				t.Fatal(err)
			}
			if c.Issuer != is.srv.URL || c.JWTID != "logout-1" || c.KeyID != is.kid || len(c.Audience) != 1 || c.Audience[0] != "kynotes" ||
				!c.IssuedAt.Equal(now) || !c.ExpiresAt.Equal(now.Add(2*time.Minute)) || !c.ReplayUntil.Equal(now.Add(3*time.Minute)) {
				t.Fatalf("unexpected claims: %+v", c)
			}
			if (scope == "subject" && c.SessionID != "") || (scope != "subject" && c.SessionID != "session-1") ||
				(scope == "session" && c.Subject != "") || (scope != "session" && c.Subject != "user-1") {
				t.Fatalf("wrong logout scope: %+v", c)
			}
			// Verification is stateless; the receiver records jti atomically with logout.
			if _, err := v.VerifyLogout(context.Background(), token); err != nil {
				t.Fatal(err)
			}
		})
	}
	if got := is.fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times", got)
	}
}

func TestVerifyLogoutRejectsInvalidClaims(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	v.Now = func() time.Time { return now }
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.example" }, ErrIssuer},
		{"wrong audience", func(c map[string]any) { c["aud"] = "kypost" }, ErrAudience},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }, ErrAudience},
		{"multiple audiences", func(c map[string]any) { c["aud"] = []string{"kynotes", "kypost"} }, ErrAudience},
		{"missing expiry", func(c map[string]any) { delete(c, "exp") }, ErrExpired},
		{"expired at leeway boundary", func(c map[string]any) {
			c["iat"] = now.Add(-2 * time.Minute).Unix()
			c["exp"] = now.Add(-time.Minute).Unix()
		}, ErrExpired},
		{"missing issued at", func(c map[string]any) { delete(c, "iat") }, ErrLogoutClaims},
		{"future issued at", func(c map[string]any) { c["iat"] = now.Add(time.Minute + time.Second).Unix() }, ErrIssuedInFuture},
		{"not yet valid", func(c map[string]any) { c["nbf"] = now.Add(time.Minute + time.Second).Unix() }, ErrNotYetValid},
		{"stale issued at", func(c map[string]any) { c["iat"] = now.Add(-MaxLogoutTokenAge - time.Minute).Unix() }, ErrExpired},
		{"expiry before issued at", func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }, ErrLogoutClaims},
		{"expiry equals issued at", func(c map[string]any) { c["exp"] = now.Unix() }, ErrLogoutClaims},
		{"null issued at", func(c map[string]any) { c["iat"] = nil }, ErrMalformed},
		{"quoted issued at", func(c map[string]any) { c["iat"] = "1789387200" }, ErrMalformed},
		{"null expiry", func(c map[string]any) { c["exp"] = nil }, ErrMalformed},
		{"quoted expiry", func(c map[string]any) { c["exp"] = "1789387320" }, ErrMalformed},
		{"overflow expiry", func(c map[string]any) { c["exp"] = 1e100 }, ErrMalformed},
		{"null not before", func(c map[string]any) { c["nbf"] = nil }, ErrMalformed},
		{"missing target", func(c map[string]any) { delete(c, "sub"); delete(c, "sid") }, ErrLogoutClaims},
		{"null subject with session", func(c map[string]any) { c["sub"] = nil }, ErrLogoutClaims},
		{"numeric subject with session", func(c map[string]any) { c["sub"] = 123 }, ErrLogoutClaims},
		{"empty session with subject", func(c map[string]any) { c["sid"] = "" }, ErrLogoutClaims},
		{"null session with subject", func(c map[string]any) { c["sid"] = nil }, ErrLogoutClaims},
		{"numeric session with subject", func(c map[string]any) { c["sid"] = 123 }, ErrLogoutClaims},
		{"missing jti", func(c map[string]any) { delete(c, "jti") }, ErrLogoutClaims},
		{"empty jti", func(c map[string]any) { c["jti"] = "" }, ErrLogoutClaims},
		{"null jti", func(c map[string]any) { c["jti"] = nil }, ErrLogoutClaims},
		{"numeric jti", func(c map[string]any) { c["jti"] = 123 }, ErrLogoutClaims},
		{"nonce", func(c map[string]any) { c["nonce"] = "login-nonce" }, ErrLogoutClaims},
		{"empty nonce", func(c map[string]any) { c["nonce"] = "" }, ErrLogoutClaims},
		{"null nonce", func(c map[string]any) { c["nonce"] = nil }, ErrLogoutClaims},
		{"access token marker", func(c map[string]any) { c["token_use"] = "access" }, ErrLogoutClaims},
		{"null token marker", func(c map[string]any) { c["token_use"] = nil }, ErrLogoutClaims},
		{"missing events", func(c map[string]any) { delete(c, "events") }, ErrLogoutClaims},
		{"null events", func(c map[string]any) { c["events"] = nil }, ErrLogoutClaims},
		{"array events", func(c map[string]any) { c["events"] = []any{} }, ErrLogoutClaims},
		{"wrong event", func(c map[string]any) { c["events"] = map[string]any{"other": map[string]any{}} }, ErrLogoutClaims},
		{"null event", func(c map[string]any) { c["events"] = map[string]any{backchannelLogoutEvent: nil} }, ErrLogoutClaims},
		{"array event", func(c map[string]any) { c["events"] = map[string]any{backchannelLogoutEvent: []any{}} }, ErrLogoutClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, claims := logoutFixture(is, now)
			tc.mutate(claims)
			c, err := v.VerifyLogout(context.Background(), is.mint(header, claims, nil))
			if !errors.Is(err, tc.want) || c.Issuer != "" {
				t.Fatalf("got %+v, %v; want %v", c, err, tc.want)
			}
		})
	}
}

func TestVerifyLogoutFreshnessAndAudienceOptions(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	issued := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	now := issued
	v.Now = func() time.Time { return now }
	v.Leeway = 10 * time.Second
	header, claims := logoutFixture(is, issued)
	claims["exp"] = issued.Add(time.Hour).Unix()
	claims["aud"] = []string{"kynotes", "kypost"}
	// Other event members and contents are allowed by the logout specification.
	claims["events"] = map[string]any{backchannelLogoutEvent: map[string]any{"extra": true}, "other": map[string]any{}}
	v.AllowMultipleAudiences = true
	token := is.mint(header, claims, nil)
	c, err := v.VerifyLogout(context.Background(), token)
	if err != nil || !c.ReplayUntil.Equal(issued.Add(MaxLogoutTokenAge+v.Leeway)) {
		t.Fatalf("%+v %v", c, err)
	}
	now = c.ReplayUntil.Add(-time.Nanosecond)
	if _, err := v.VerifyLogout(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	now = c.ReplayUntil
	if _, err := v.VerifyLogout(context.Background(), token); !errors.Is(err, ErrExpired) {
		t.Fatalf("freshness boundary: %v", err)
	}
}

func TestLogoutAndAuthenticationTokensStaySeparate(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	now := time.Now()
	header, claims := logoutFixture(is, now)
	for _, typ := range []string{"logout+jwt", "JWT", "at+jwt", ""} {
		header["typ"] = typ
		token := is.mint(header, claims, nil)
		if _, err := v.Verify(context.Background(), token); !errors.Is(err, ErrTokenType) {
			t.Errorf("Verify accepted events with typ %q: %v", typ, err)
		}
		if _, err := v.VerifyWithNonce(context.Background(), token, ""); !errors.Is(err, ErrTokenType) {
			t.Errorf("VerifyWithNonce accepted logout with typ %q: %v", typ, err)
		}
		h := v.Middleware(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("logout reached authenticated handler") }))
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("middleware returned %d", w.Code)
		}
		if typ != "logout+jwt" {
			if _, err := v.VerifyLogout(context.Background(), token); !errors.Is(err, ErrTokenType) {
				t.Errorf("logout accepted typ %q: %v", typ, err)
			}
		}
	}
	for _, typ := range []string{"", "JWT", "at+jwt"} {
		header["typ"] = typ
		auth := good(is)
		token := is.mint(header, auth, nil)
		if _, err := v.Verify(context.Background(), token); err != nil {
			t.Errorf("authentication compatibility typ %q: %v", typ, err)
		}
		if _, err := v.VerifyLogout(context.Background(), token); !errors.Is(err, ErrTokenType) {
			t.Errorf("authentication used for logout: %v", err)
		}
	}
	header["typ"] = "logout+jwt"
	if _, err := v.VerifyLogout(context.Background(), is.mint(header, good(is), nil)); !errors.Is(err, ErrLogoutClaims) {
		t.Fatalf("retyped authentication token: %v", err)
	}
}

func TestVerifyLogoutSignatureAndJWKS(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	header, claims := logoutFixture(is, time.Now())
	token := is.mint(header, claims, nil)
	if _, err := v.VerifyLogout(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), is.mint(nil, good(is), nil)); err != nil {
		t.Fatal(err)
	}
	if got := is.fetches.Load(); got != 1 {
		t.Fatalf("logout and authentication fetched JWKS %d times", got)
	}
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	if _, err := v.VerifyLogout(context.Background(), parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(signature)); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered signature: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyLogout(context.Background(), is.mint(header, claims, other)); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong signer: %v", err)
	}
	for _, alg := range []string{"none", "HS256", "ES256", ""} {
		header["alg"] = alg
		if _, err := v.VerifyLogout(context.Background(), is.mint(header, claims, nil)); !errors.Is(err, ErrAlgorithm) {
			t.Errorf("alg %q: %v", alg, err)
		}
	}
	header["alg"] = "RS256"
	header["kid"] = "unknown"
	for i := 0; i < 3; i++ {
		if _, err := v.VerifyLogout(context.Background(), is.mint(header, claims, nil)); !errors.Is(err, ErrUnknownKey) {
			t.Fatal(err)
		}
	}
	if got := is.fetches.Load(); got != 1 {
		t.Fatalf("unknown kids fetched JWKS %d times", got)
	}
	v.Issuer = "http://issuer.example"
	if _, err := v.VerifyLogout(context.Background(), token); !errors.Is(err, ErrInsecureIssuer) {
		t.Fatalf("plaintext issuer: %v", err)
	}
}

func TestVerifyLogoutRejectsMalformedPayload(t *testing.T) {
	is := newIssuer(t)
	v := is.verifier()
	header, claims := logoutFixture(is, time.Now())
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"null", string(payload) + "{}", string(payload) + " trailing"} {
		signing := seg(header) + "." + base64.RawURLEncoding.EncodeToString([]byte(raw))
		sum := sha256.Sum256([]byte(signing))
		signature, err := rsa.SignPKCS1v15(rand.Reader, is.key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		token := signing + "." + base64.RawURLEncoding.EncodeToString(signature)
		if _, err := v.VerifyLogout(context.Background(), token); !errors.Is(err, ErrMalformed) {
			t.Fatalf("malformed payload accepted: %v", err)
		}
	}
}
