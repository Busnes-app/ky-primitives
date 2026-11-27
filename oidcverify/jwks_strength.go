package oidcverify

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ValidateJWKS validates a raw JWKS document using a strict case-sensitive,
// duplicate-rejecting stdlib JSON token walk. It enforces:
//
//   - Body size at most MaxJWKSBytes (1 MiB)
//   - Exact case-sensitive "keys" array with no duplicate or case-variant members
//   - Every RSA key has a valid canonical base64url modulus >= 2048 bits and odd exponent >= 3
//   - Every AKP key has alg "ML-DSA-65", optional use "sig", and a valid 1952-byte raw public key
//   - No polyglot RSA/AKP parameter mixing
//
// Other key types (such as EC or OKP) are accepted after strict JSON structure and
// duplicate-member checks so upstream OIDC verifiers can handle them.
func ValidateJWKS(raw []byte) error {
	keys, err := parseStrictJWKS(raw)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.Kty == "" {
			return fmt.Errorf("%w: JWK missing kty", ErrJWKS)
		}
		switch k.Kty {
		case "RSA":
			if k.hasPub {
				return fmt.Errorf("%w: RSA key must not contain pub", ErrJWKS)
			}
			if strings.HasPrefix(k.Alg, "ML-DSA-") {
				return fmt.Errorf("%w: %w: RSA key cannot use %s", ErrJWKS, ErrWeakKey, k.Alg)
			}
			if _, err := parseRSAPublicKey(k.N, k.E); err != nil {
				return fmt.Errorf("%w: %w", ErrJWKS, err)
			}
		case "AKP":
			if k.hasN || k.hasE {
				return fmt.Errorf("%w: AKP key must not contain RSA parameters", ErrJWKS)
			}
			if k.Alg != AlgMLDSA65 {
				return fmt.Errorf("%w: %w: AKP key alg must be %s", ErrJWKS, ErrWeakKey, AlgMLDSA65)
			}
			if k.Use != "" && k.Use != "sig" {
				return fmt.Errorf("%w: %w: AKP key use must be sig", ErrJWKS, ErrWeakKey)
			}
			pubBytes, err := decodeStrictBase64URL(k.Pub)
			if err != nil {
				return fmt.Errorf("%w: %w: invalid AKP pub encoding", ErrJWKS, ErrWeakKey)
			}
			if _, err := parseMLDSA65PublicKey(pubBytes); err != nil {
				return fmt.Errorf("%w: %w", ErrJWKS, err)
			}
		}
	}
	return nil
}

// StrongJWKSTransport wraps an http.RoundTripper for OIDC JWKS fetches (for example
// coreos/go-oidc's RemoteKeySet). It refuses 3xx redirects, caps 200 OK responses at
// MaxJWKSBytes (1 MiB), validates every RSA and AKP key with ValidateJWKS, and returns
// the exact unmodified response bytes to the caller.
type StrongJWKSTransport struct {
	// Base is the underlying RoundTripper. Nil uses http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t StrongJWKSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: OIDC JWKS redirects are refused", ErrJWKS)
	}
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxJWKSBytes {
		return nil, fmt.Errorf("%w: OIDC JWKS exceeds 1 MiB", ErrJWKS)
	}
	if err := ValidateJWKS(raw); err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}
