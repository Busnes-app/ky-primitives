// Package oidcverify verifies tokens KySignOn issues: ML-DSA-65 (RFC 9964 AKP JWK) and
// RS256 (RSA JWK) JWTs whose signing keys are published at the issuer's JWKS endpoint.
// Five products parsed these with their own code, and at least one read the claims without
// checking the signature at all. One wrong check of alg, aud, iss, exp or kid accepts a
// token it should not, indistinguishable from a good one, so the check lives here once, on
// the standard library alone.
//
// Only ML-DSA-65 (on Go 1.27+) and RS256 are accepted, with strict alg/kty binding so an
// RSA key can never verify an ML-DSA-65 header or vice versa. A token whose header says
// anything else, including "none", is refused before any signature work.
package oidcverify

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrMalformed      = errors.New("oidcverify: token is not a three-part JWT")
	ErrTokenType      = errors.New("oidcverify: token purpose does not match")
	ErrAlgorithm      = errors.New("oidcverify: unsupported token algorithm")
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
	Algorithm string
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
	// AllowedAlgorithms optionally restricts the JWS algorithms accepted by this Verifier
	// (a subset of SupportedAlgorithms). Empty accepts every algorithm supported by this
	// build (ML-DSA-65 and RS256 on Go 1.27+; RS256 on Go 1.26).
	AllowedAlgorithms []string
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

	mu          sync.Mutex // guards the fields below
	keys        map[string]verifyKey
	fetchedAt   time.Time
	attemptedAt time.Time
	inflight    chan struct{} // closed when the fetch in progress finishes; nil when idle
	fetchErr    error         // the last fetch's error, for callers that waited on it
}

type verifyKey struct {
	alg   string
	rsa   *rsa.PublicKey
	mldsa mldsaPublicKey
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

func (v *Verifier) algAllowed(alg string) bool {
	supported := false
	switch alg {
	case AlgRS256:
		supported = true
	case AlgMLDSA65:
		supported = mldsa65Supported
	}
	if !supported {
		return false
	}
	if len(v.AllowedAlgorithms) == 0 {
		return true
	}
	return slices.Contains(v.AllowedAlgorithms, alg)
}

// PreferredAlgorithm returns the strongest supported and allowed signing algorithm
// offered by the issuer's JWKS, preferring ML-DSA-65 over RS256 when both are present.
// It shares Verify's JWKS cache, refresh limits, and HTTPS checks.
func (v *Verifier) PreferredAlgorithm(ctx context.Context) (string, error) {
	if _, err := v.jwksURL(); err != nil {
		return "", err
	}
	keys, err := v.keySet(ctx)
	if err != nil {
		return "", err
	}
	return pickPreferredAlgorithm(keys, v.AllowedAlgorithms)
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
	header, err := parseStrictJWSHeader(headerJSON)
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if !v.algAllowed(header.Alg) {
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
	// Strict alg/kty binding: an RSA key cannot verify ML-DSA-65 and an AKP key cannot
	// verify RS256.
	if key.alg != header.Alg {
		return Claims{}, ErrAlgorithm
	}
	signingInput := parts[0] + "." + parts[1]
	switch header.Alg {
	case AlgRS256:
		sum := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(key.rsa, crypto.SHA256, sum[:], sig); err != nil {
			return Claims{}, ErrSignature
		}
	case AlgMLDSA65:
		if err := verifyMLDSA65(key.mldsa, []byte(signingInput), sig); err != nil {
			return Claims{}, ErrSignature
		}
	default:
		return Claims{}, ErrAlgorithm
	}
	c, err := parseClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	c.KeyID = header.Kid
	c.Algorithm = header.Alg
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

// decodeSegment decodes canonical unpadded base64url, as RFC 7515 requires; padded or
// non-canonical input is refused so two encodings of one token cannot exist.
func decodeSegment(s string) ([]byte, error) {
	return decodeStrictBase64URL(s)
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

// key returns the verification key for kid. The cached set is used while fresh; an unknown
// kid or a stale set triggers a refresh, at most once per MinRefresh whether the fetch
// succeeds or fails, so an attacker-chosen kid cannot make every request pay the issuer's
// timeout. One fetch runs at a time, on its own goroutine: it serves everyone who waits on
// it, so a caller that hangs up stops waiting but cannot cancel it — one dropped request
// would otherwise lock everyone out of a rotated key for MinRefresh.
func (v *Verifier) key(ctx context.Context, kid string) (verifyKey, error) {
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
	switch {
	case known && now.Sub(v.fetchedAt) < maxAge:
		v.mu.Unlock()
		return k, nil
	case known && (v.inflight != nil || (!v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < minRefresh)):
		// A stale key beats waiting on a refresh.
		v.mu.Unlock()
		return k, nil
	case v.inflight != nil:
		done := v.inflight
		v.mu.Unlock()
		return v.await(ctx, done, kid)
	case !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < minRefresh:
		v.mu.Unlock()
		return verifyKey{}, ErrUnknownKey
	}
	done := v.startFetchLocked(ctx, now)
	v.mu.Unlock()
	return v.await(ctx, done, kid)
}

func (v *Verifier) keySet(ctx context.Context) (map[string]verifyKey, error) {
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
	hasKeys := len(v.keys) > 0
	switch {
	case hasKeys && now.Sub(v.fetchedAt) < maxAge:
		out := v.keys
		v.mu.Unlock()
		return out, nil
	case hasKeys && (v.inflight != nil || (!v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < minRefresh)):
		out := v.keys
		v.mu.Unlock()
		return out, nil
	case v.inflight != nil:
		done := v.inflight
		v.mu.Unlock()
		return v.awaitSet(ctx, done)
	case !v.attemptedAt.IsZero() && now.Sub(v.attemptedAt) < minRefresh:
		err := v.fetchErr
		out := v.keys
		v.mu.Unlock()
		if len(out) > 0 {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		return nil, ErrUnknownKey
	}
	done := v.startFetchLocked(ctx, now)
	v.mu.Unlock()
	return v.awaitSet(ctx, done)
}

func (v *Verifier) startFetchLocked(ctx context.Context, now time.Time) <-chan struct{} {
	done := make(chan struct{})
	v.inflight, v.attemptedAt = done, now
	go func() {
		keys, err := v.fetch(context.WithoutCancel(ctx))
		v.mu.Lock()
		if err == nil {
			v.keys, v.fetchedAt = keys, v.now()
		}
		v.fetchErr, v.inflight = err, nil
		v.mu.Unlock()
		close(done)
	}()
	return done
}

// await waits for the fetch behind done, or for the caller to give up.
func (v *Verifier) await(ctx context.Context, done <-chan struct{}, kid string) (verifyKey, error) {
	select {
	case <-done:
	case <-ctx.Done():
		return verifyKey{}, ctx.Err()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	// A stale set beats no set: the issuer being unreachable must not log everyone out.
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if v.fetchErr != nil {
		return verifyKey{}, v.fetchErr
	}
	return verifyKey{}, ErrUnknownKey
}

func (v *Verifier) awaitSet(ctx context.Context, done <-chan struct{}) (map[string]verifyKey, error) {
	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) > 0 {
		return v.keys, nil
	}
	if v.fetchErr != nil {
		return nil, v.fetchErr
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

func (v *Verifier) fetch(ctx context.Context) (map[string]verifyKey, error) {
	u, err := v.jwksURL()
	if err != nil {
		return nil, err
	}
	base := v.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	if base.Timeout == 0 {
		// The fetch outlives the request that started it, so something must bound it.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKS, err)
	}
	if len(raw) > MaxJWKSBytes {
		return nil, fmt.Errorf("%w: response exceeds 1 MiB", ErrJWKS)
	}
	parsed, err := parseStrictJWKS(raw)
	if err != nil {
		return nil, err
	}
	return extractSigningKeys(parsed)
}

func extractSigningKeys(parsed []parsedJWK) (map[string]verifyKey, error) {
	out := make(map[string]verifyKey)
	for _, k := range parsed {
		// Only signing keys under a non-empty kid are usable; encryption keys and
		// unsupported key types (such as EC or oct) are ignored rather than mistaken
		// for a signer.
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if k.hasKeyOps && !slices.Contains(k.keyOps, "verify") {
			continue
		}
		switch k.Kty {
		case "RSA":
			if k.hasPub || (k.Alg != "" && k.Alg != AlgRS256) {
				continue
			}
			pub, err := parseRSAPublicKey(k.N, k.E)
			if err != nil {
				continue
			}
			if _, dup := out[k.Kid]; dup {
				return nil, fmt.Errorf("%w: duplicate signing kid %q", ErrJWKS, k.Kid)
			}
			out[k.Kid] = verifyKey{alg: AlgRS256, rsa: pub}
		case "AKP":
			if !mldsa65Supported || k.hasN || k.hasE || k.Alg != AlgMLDSA65 {
				continue
			}
			pubBytes, err := decodeStrictBase64URL(k.Pub)
			if err != nil {
				continue
			}
			pub, err := parseMLDSA65PublicKey(pubBytes)
			if err != nil {
				continue
			}
			if _, dup := out[k.Kid]; dup {
				return nil, fmt.Errorf("%w: duplicate signing kid %q", ErrJWKS, k.Kid)
			}
			out[k.Kid] = verifyKey{alg: AlgMLDSA65, mldsa: pub}
		}
	}
	return out, nil
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
