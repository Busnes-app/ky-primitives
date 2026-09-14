// Package oidcverify verifies tokens KySignOn issues: RS256 JWTs whose signing key is
// published at the issuer's JWKS endpoint. Five products parsed these with their own code,
// and at least one read the claims without checking the signature at all. One wrong check
// of alg, aud, iss, exp or kid accepts a token it should not, indistinguishable from a good
// one, so the check lives here once, on the standard library alone.
//
// The algorithm is pinned to RS256 because that is what KySignOn signs with. A token whose
// header says anything else, including "none", is refused before any signature work.
package oidcverify

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrMalformed      = errors.New("oidcverify: token is not a three-part JWT")
	ErrTokenType      = errors.New("oidcverify: token purpose does not match")
	ErrAlgorithm      = errors.New("oidcverify: token algorithm is not RS256")
	ErrUnknownKey     = errors.New("oidcverify: no JWKS key matches the token's kid")
	ErrSignature      = errors.New("oidcverify: signature does not verify")
	ErrIssuer         = errors.New("oidcverify: issuer does not match")
	ErrAudience       = errors.New("oidcverify: audience does not include this client")
	ErrExpired        = errors.New("oidcverify: token has expired")
	ErrNotYetValid    = errors.New("oidcverify: token is not yet valid")
	ErrIssuedInFuture = errors.New("oidcverify: token was issued in the future")
	ErrNoSubject      = errors.New("oidcverify: token has no subject")
	ErrNonce          = errors.New("oidcverify: nonce does not match")
	ErrJWKS           = errors.New("oidcverify: JWKS fetch failed")
)

// Claims are the standard claims every KySignOn token carries, plus the raw set for
// product-specific ones (role, groups, email).
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	Nonce     string
	KeyID     string
	Raw       map[string]json.RawMessage
}

// String returns a string claim from Raw, or "".
func (c Claims) String(name string) string {
	var s string
	if raw, ok := c.Raw[name]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// Verifier checks tokens for one issuer and one audience. Zero Leeway means one minute.
type Verifier struct {
	Issuer   string
	Audience string
	// AllowMultipleAudiences accepts an aud array that names this client among others.
	// Off by default: a token minted for several clients is a token any of them can replay.
	AllowMultipleAudiences bool
	// JWKSURL defaults to Issuer + "/.well-known/jwks.json".
	JWKSURL string
	// HTTPClient defaults to a client with a ten-second timeout.
	HTTPClient *http.Client
	// Now defaults to time.Now.
	Now func() time.Time
	// Leeway is the clock-skew allowance for exp, nbf and iat.
	Leeway time.Duration
	// MinRefresh bounds how often an unknown kid may trigger a JWKS fetch. Default 30s.
	MinRefresh time.Duration
	// MaxAge is how long a fetched key set is trusted before a refresh. Default 1h.
	MaxAge time.Duration

	mu          sync.Mutex // guards keys, fetchedAt, attemptedAt
	fetchMu     sync.Mutex // single-flight for the HTTP fetch; never held with mu
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	attemptedAt time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) leeway() time.Duration {
	if v.Leeway == 0 {
		return time.Minute
	}
	return v.Leeway
}

// Verify checks an authentication token against the issuer's JWKS and standard claims.
// Logout and other security-event tokens are refused; use VerifyLogout for logout.
// An unknown kid triggers at most one rate-limited JWKS refresh.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	return v.VerifyWithNonce(ctx, token, "")
}

// VerifyWithNonce is Verify plus a nonce check, for ID tokens from the authorization-code
// flow. An empty nonce skips the check; a token carrying a nonce when none is expected is
// still accepted, since access tokens carry none.
func (v *Verifier) VerifyWithNonce(ctx context.Context, token, nonce string) (Claims, error) {
	c, err := v.verifyJWT(ctx, token, "")
	if err != nil {
		return Claims{}, err
	}
	if _, ok := c.Raw["events"]; ok {
		return Claims{}, ErrTokenType
	}
	if c.Subject == "" {
		return Claims{}, ErrNoSubject
	}
	if nonce != "" && c.Nonce != nonce {
		return Claims{}, ErrNonce
	}
	return c, nil
}

// verifyJWT shares cryptographic, issuer, audience and time checks across purposes.
// An empty tokenType selects authentication; logout requires its exact explicit type.
func (v *Verifier) verifyJWT(ctx context.Context, token, tokenType string) (Claims, error) {
	if _, err := v.jwksURL(); err != nil {
		return Claims{}, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, ErrMalformed
	}
	if header.Alg != "RS256" {
		return Claims{}, ErrAlgorithm
	}
	if tokenType != "" {
		if header.Typ != tokenType {
			return Claims{}, ErrTokenType
		}
	} else if header.Typ != "" && header.Typ != "JWT" && header.Typ != "at+jwt" {
		return Claims{}, ErrTokenType
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	// Decoded before the signature check only to reject a malformed segment early; nothing
	// in it is trusted until the signature verifies.
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return Claims{}, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return Claims{}, ErrSignature
	}
	c, err := parseClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	c.KeyID = header.Kid
	now := v.now()
	lw := v.leeway()
	switch {
	case c.Issuer != v.Issuer:
		return Claims{}, ErrIssuer
	case !v.audienceOK(c.Audience):
		return Claims{}, ErrAudience
	case c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt.Add(lw)):
		return Claims{}, ErrExpired
	case !c.NotBefore.IsZero() && now.Add(lw).Before(c.NotBefore):
		return Claims{}, ErrNotYetValid
	case !c.IssuedAt.IsZero() && c.IssuedAt.After(now.Add(lw)):
		return Claims{}, ErrIssuedInFuture
	}
	return c, nil
}

func (v *Verifier) audienceOK(aud []string) bool {
	switch len(aud) {
	case 0:
		return false
	case 1:
		return aud[0] == v.Audience
	default:
		if !v.AllowMultipleAudiences {
			return false
		}
		for _, a := range aud {
			if a == v.Audience {
				return true
			}
		}
		return false
	}
}

// decodeSegment decodes base64url without padding, as RFC 7515 requires; padded input is
// refused so two encodings of one token cannot exist.
func decodeSegment(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/") {
		return nil, ErrMalformed
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func parseClaims(payload []byte) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return Claims{}, ErrMalformed
	}
	c := Claims{Raw: raw}
	c.Issuer = c.String("iss")
	c.Subject = c.String("sub")
	c.Nonce = c.String("nonce")
	if a, ok := raw["aud"]; ok {
		var one string
		if json.Unmarshal(a, &one) == nil {
			c.Audience = []string{one}
		} else {
			var many []string
			if json.Unmarshal(a, &many) != nil {
				return Claims{}, ErrMalformed
			}
			c.Audience = many
		}
	}
	var err error
	if c.ExpiresAt, err = numericDate(raw["exp"]); err != nil {
		return Claims{}, err
	}
	if c.IssuedAt, err = numericDate(raw["iat"]); err != nil {
		return Claims{}, err
	}
	if c.NotBefore, err = numericDate(raw["nbf"]); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// numericDate reads a JSON number as seconds since the epoch. Fractions are truncated;
// anything that is not a number is malformed.
func numericDate(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, nil
	}
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return time.Time{}, ErrMalformed
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return time.Time{}, ErrMalformed
	}
	if i, err := n.Int64(); err == nil {
		return time.Unix(i, 0), nil
	}
	f, err := n.Float64()
	if err != nil || f >= math.MaxInt64 || f < math.MinInt64 {
		return time.Time{}, ErrMalformed
	}
	return time.Unix(int64(f), 0), nil
}

// key returns the RSA key for kid. The cached set is used while fresh; an unknown kid or a
// stale set triggers a refresh, at most once per MinRefresh whether the fetch succeeds or
// fails, so an attacker-chosen kid cannot make every request pay the issuer's timeout. The
// HTTP fetch runs outside the state mutex under its own single-flight lock, so concurrent
// verifications share one fetch instead of queueing behind it.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	maxAge := v.MaxAge
	if maxAge == 0 {
		maxAge = time.Hour
	}
	minRefresh := v.MinRefresh
	if minRefresh == 0 {
		minRefresh = 30 * time.Second
	}
	now := v.now()

	v.mu.Lock()
	k, known := v.keys[kid]
	fresh := now.Sub(v.fetchedAt) < maxAge
	recentAttempt := !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < minRefresh
	v.mu.Unlock()
	if known && fresh {
		return k, nil
	}
	if recentAttempt {
		if known {
			return k, nil
		}
		return nil, ErrUnknownKey
	}

	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	// Another verification may have fetched while this one waited.
	v.mu.Lock()
	if k, ok := v.keys[kid]; ok && v.now().Sub(v.fetchedAt) < maxAge {
		v.mu.Unlock()
		return k, nil
	}
	if !v.attemptedAt.IsZero() && v.now().Sub(v.attemptedAt) < minRefresh {
		k, ok := v.keys[kid]
		v.mu.Unlock()
		if ok {
			return k, nil
		}
		return nil, ErrUnknownKey
	}
	v.attemptedAt = v.now()
	v.mu.Unlock()

	keys, err := v.fetch(ctx)

	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil {
		// A stale set beats no set: the issuer being unreachable must not log everyone out.
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
		return nil, err
	}
	v.keys = keys
	v.fetchedAt = v.now()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

// ErrInsecureIssuer means the issuer or JWKS URL is not HTTPS. Key discovery over plaintext
// lets whoever answers the request decide which keys verify tokens.
var ErrInsecureIssuer = errors.New("oidcverify: issuer and JWKS URL must be https with a host")

func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: %q", ErrInsecureIssuer, raw)
	}
	return nil
}

// jwksURL is the effective JWKS endpoint, checked to be HTTPS along with the issuer.
func (v *Verifier) jwksURL() (string, error) {
	if err := requireHTTPS(v.Issuer); err != nil {
		return "", err
	}
	u := v.JWKSURL
	if u == "" {
		u = strings.TrimRight(v.Issuer, "/") + "/.well-known/jwks.json"
	}
	if err := requireHTTPS(u); err != nil {
		return "", err
	}
	return u, nil
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	u, err := v.jwksURL()
	if err != nil {
		return nil, err
	}
	base := v.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	// Key discovery needs no redirect; following one would let a redirector choose the keys.
	client := *base
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("%w: JWKS endpoint redirected to %s", ErrJWKS, req.URL.Redacted())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKS, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKS, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrJWKS, resp.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKS, err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		// Only RSA signing keys under a kid are usable; an EC key or an encryption key that
		// shares a kid is ignored rather than mistaken for the signer.
		if k.Kty != "RSA" || k.Kid == "" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaFromJWK(k)
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	return out, nil
}

func rsaFromJWK(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 {
		return nil, errors.New("oidcverify: RSA key too small or exponent invalid")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

type ctxKey struct{}

// ClaimsFromContext returns the Claims Middleware stored.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// Middleware reads a bearer token, verifies it, and stores the Claims on the context. Every
// failure answers 401 with a fixed body; the reason goes only to onReject.
func (v *Verifier) Middleware(onReject func(r *http.Request, err error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			const scheme = "Bearer "
			if len(auth) <= len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
				reject(w, r, ErrMalformed, onReject)
				return
			}
			c, err := v.Verify(r.Context(), strings.TrimSpace(auth[len(scheme):]))
			if err != nil {
				reject(w, r, err, onReject)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
		})
	}
}

func reject(w http.ResponseWriter, r *http.Request, err error, onReject func(*http.Request, error)) {
	if onReject != nil {
		onReject(r, err)
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
}
