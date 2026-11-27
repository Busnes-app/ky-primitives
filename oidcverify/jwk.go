package oidcverify

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strings"
)

const (
	// AlgRS256 is the JWS algorithm identifier for RSASSA-PKCS1-v1_5 using SHA-256.
	AlgRS256 = "RS256"
	// AlgMLDSA65 is the RFC 9964 JWS algorithm identifier for FIPS 204 ML-DSA-65.
	AlgMLDSA65 = "ML-DSA-65"

	// MLDSA65PublicKeySize is the raw byte length of a FIPS 204 ML-DSA-65 public key.
	MLDSA65PublicKeySize = 1952
	// MinRSABits is the minimum accepted RSA modulus bit length for OIDC JWKS keys.
	MinRSABits = 2048
	// MaxJWKSBytes is the maximum accepted JWKS HTTP response body size (1 MiB).
	MaxJWKSBytes = 1 << 20

	maxJSONDepth = 64
)

// ErrWeakKey reports a JWKS key that violates key-strength or parameter requirements
// (for example an RSA modulus shorter than 2048 bits or an AKP key that is not a valid
// 1952-byte ML-DSA-65 public key).
var ErrWeakKey = errors.New("oidcverify: JWKS key does not meet strength requirements")

// PublicJWK is a public RFC 7517 / RFC 9964 JSON Web Key for RSA (RS256) or AKP (ML-DSA-65).
type PublicJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Pub string `json:"pub,omitempty"`
}

// JWKS is an RFC 7517 JSON Web Key Set.
type JWKS struct {
	Keys []PublicJWK `json:"keys"`
}

// SupportedAlgorithms returns the JWS algorithms supported by this build in preference
// order. On Go 1.27+ ML-DSA-65 is preferred ahead of RS256; on Go 1.26 only RS256 is
// supported. Callers configuring external OIDC libraries (such as coreos/go-oidc) can
// pass this slice directly as SupportedSigningAlgs.
func SupportedAlgorithms() []string {
	if mldsa65Supported {
		return []string{AlgMLDSA65, AlgRS256}
	}
	return []string{AlgRS256}
}

// MarshalRSAPublicJWK encodes a >= 2048-bit RSA public key as an RS256 PublicJWK.
func MarshalRSAPublicJWK(kid string, pub *rsa.PublicKey) (PublicJWK, error) {
	if kid == "" {
		return PublicJWK{}, fmt.Errorf("%w: kid is required", ErrMalformed)
	}
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.N.BitLen() < MinRSABits {
		return PublicJWK{}, fmt.Errorf("%w: RSA key must be at least %d bits", ErrWeakKey, MinRSABits)
	}
	if pub.E < 3 || pub.E > math.MaxInt32 || pub.E%2 == 0 {
		return PublicJWK{}, fmt.Errorf("%w: invalid RSA public exponent", ErrWeakKey)
	}
	return PublicJWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: AlgRS256,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}, nil
}

// MarshalAKPPublicJWK encodes a raw 1952-byte FIPS 204 ML-DSA-65 public key as an
// RFC 9964 AKP PublicJWK.
func MarshalAKPPublicJWK(kid string, rawPub []byte) (PublicJWK, error) {
	if kid == "" {
		return PublicJWK{}, fmt.Errorf("%w: kid is required", ErrMalformed)
	}
	if _, err := parseMLDSA65PublicKey(rawPub); err != nil {
		return PublicJWK{}, err
	}
	return PublicJWK{
		Kty: "AKP",
		Kid: kid,
		Use: "sig",
		Alg: AlgMLDSA65,
		Pub: base64.RawURLEncoding.EncodeToString(rawPub),
	}, nil
}

// ParseAKPPublicJWK validates an RFC 9964 AKP PublicJWK for ML-DSA-65 and returns
// the raw 1952-byte FIPS 204 public key bytes.
func ParseAKPPublicJWK(k PublicJWK) ([]byte, error) {
	if k.Kty != "AKP" {
		return nil, fmt.Errorf("%w: expected kty AKP, got %q", ErrAlgorithm, k.Kty)
	}
	if k.Alg != AlgMLDSA65 {
		return nil, fmt.Errorf("%w: AKP key alg must be %s", ErrAlgorithm, AlgMLDSA65)
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("%w: AKP key use must be sig", ErrWeakKey)
	}
	if k.N != "" || k.E != "" {
		return nil, fmt.Errorf("%w: AKP key must not contain RSA parameters", ErrMalformed)
	}
	raw, err := decodeStrictBase64URL(k.Pub)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid AKP pub encoding", ErrMalformed)
	}
	if _, err := parseMLDSA65PublicKey(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// NewJWKS validates keys and builds a multi-key JWKS suitable for publication by an
// OIDC issuer (such as KyIdentity). Every key must have a unique non-empty kid and be
// either a >= 2048-bit RSA (RS256) key or a 1952-byte AKP (ML-DSA-65) key.
func NewJWKS(keys ...PublicJWK) (JWKS, error) {
	out := make([]PublicJWK, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k.Kid == "" {
			return JWKS{}, fmt.Errorf("%w: JWKS key missing kid", ErrMalformed)
		}
		if _, dup := seen[k.Kid]; dup {
			return JWKS{}, fmt.Errorf("%w: duplicate kid %q in JWKS", ErrMalformed, k.Kid)
		}
		seen[k.Kid] = struct{}{}
		if k.Use != "" && k.Use != "sig" {
			return JWKS{}, fmt.Errorf("%w: signing JWKS key %q has use %q", ErrWeakKey, k.Kid, k.Use)
		}
		switch k.Kty {
		case "RSA":
			if k.Pub != "" {
				return JWKS{}, fmt.Errorf("%w: RSA key %q must not contain pub", ErrMalformed, k.Kid)
			}
			if k.Alg != "" && k.Alg != AlgRS256 {
				return JWKS{}, fmt.Errorf("%w: RSA key %q has unsupported alg %q", ErrAlgorithm, k.Kid, k.Alg)
			}
			if _, err := parseRSAPublicKey(k.N, k.E); err != nil {
				return JWKS{}, err
			}
		case "AKP":
			if _, err := ParseAKPPublicJWK(k); err != nil {
				return JWKS{}, err
			}
		default:
			return JWKS{}, fmt.Errorf("%w: unsupported key type %q", ErrAlgorithm, k.Kty)
		}
		out = append(out, k)
	}
	return JWKS{Keys: out}, nil
}

// MarshalJWKS validates keys with NewJWKS and returns the serialized JSON Web Key Set.
func MarshalJWKS(keys ...PublicJWK) ([]byte, error) {
	set, err := NewJWKS(keys...)
	if err != nil {
		return nil, err
	}
	return json.Marshal(set)
}

// PreferredAlgorithm inspects a serialized JWKS and returns the strongest supported
// signing algorithm offered by it: ML-DSA-65 when an AKP ML-DSA-65 signing key is
// present (on Go 1.27+), otherwise RS256 when a >= 2048-bit RSA signing key is present.
func PreferredAlgorithm(jwksJSON []byte) (string, error) {
	parsed, err := parseStrictJWKS(jwksJSON)
	if err != nil {
		return "", err
	}
	keys, err := extractSigningKeys(parsed)
	if err != nil {
		return "", err
	}
	return pickPreferredAlgorithm(keys, nil)
}

func pickPreferredAlgorithm(keys map[string]verifyKey, allowed []string) (string, error) {
	var hasMLDSA, hasRSA bool
	for _, k := range keys {
		switch k.alg {
		case AlgMLDSA65:
			hasMLDSA = true
		case AlgRS256:
			hasRSA = true
		}
	}
	for _, alg := range SupportedAlgorithms() {
		if len(allowed) > 0 && !slices.Contains(allowed, alg) {
			continue
		}
		if alg == AlgMLDSA65 && hasMLDSA {
			return AlgMLDSA65, nil
		}
		if alg == AlgRS256 && hasRSA {
			return AlgRS256, nil
		}
	}
	return "", ErrUnknownKey
}

func decodeStrictBase64URL(s string) ([]byte, error) {
	if s == "" || strings.ContainsAny(s, "=+/ \t\r\n") {
		return nil, ErrMalformed
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nb, err := decodeStrictBase64URL(nStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid RSA modulus encoding", ErrWeakKey)
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < MinRSABits {
		return nil, fmt.Errorf("%w: RSA key must be at least %d bits", ErrWeakKey, MinRSABits)
	}
	eb, err := decodeStrictBase64URL(eStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid RSA exponent encoding", ErrWeakKey)
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > math.MaxInt32 || e.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: invalid RSA public exponent", ErrWeakKey)
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

type parsedJWK struct {
	PublicJWK
	hasKeyOps bool
	keyOps    []string
	hasN      bool
	hasE      bool
	hasPub    bool
}

var knownJWKMembers = []string{"kty", "kid", "alg", "use", "key_ops", "n", "e", "pub", "priv"}

// parseStrictJWKS decodes a JWKS document using encoding/json.Decoder's token stream,
// enforcing exact case-sensitive member names and rejecting duplicate members,
// case-variant smuggling of known fields, missing "keys", and trailing data.
func parseStrictJWKS(raw []byte) ([]parsedJWK, error) {
	if len(raw) > MaxJWKSBytes {
		return nil, fmt.Errorf("%w: response exceeds 1 MiB", ErrJWKS)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrJWKS, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%w: JWKS must be a JSON object", ErrJWKS)
	}

	seen := make(map[string]struct{})
	var keys []parsedJWK
	hasKeys := false

	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid JSON: %v", ErrJWKS, err)
		}
		name, ok := ktok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: expected JSON object key", ErrJWKS)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: duplicate JWKS member %q", ErrJWKS, name)
		}
		seen[name] = struct{}{}

		if name == "keys" {
			hasKeys = true
			arrTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("%w: invalid keys member: %v", ErrJWKS, err)
			}
			if d, ok := arrTok.(json.Delim); !ok || d != '[' {
				return nil, fmt.Errorf("%w: JWKS keys must be a JSON array", ErrJWKS)
			}
			for dec.More() {
				k, err := parseStrictJWKObject(dec)
				if err != nil {
					return nil, err
				}
				keys = append(keys, k)
			}
			endTok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("%w: invalid keys array: %v", ErrJWKS, err)
			}
			if d, ok := endTok.(json.Delim); !ok || d != ']' {
				return nil, fmt.Errorf("%w: expected closing bracket for keys", ErrJWKS)
			}
			continue
		}
		if strings.EqualFold(name, "keys") {
			return nil, fmt.Errorf("%w: case-variant JWKS member %q refused", ErrJWKS, name)
		}
		if err := skipJSONValue(dec, 1); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrJWKS, err)
		}
	}

	endTok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrJWKS, err)
	}
	if d, ok := endTok.(json.Delim); !ok || d != '}' {
		return nil, fmt.Errorf("%w: expected closing brace", ErrJWKS)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after JWKS object", ErrJWKS)
	}
	if !hasKeys {
		return nil, fmt.Errorf("%w: JWKS missing keys member", ErrJWKS)
	}
	return keys, nil
}

func parseStrictJWKObject(dec *json.Decoder) (parsedJWK, error) {
	tok, err := dec.Token()
	if err != nil {
		return parsedJWK{}, fmt.Errorf("%w: invalid JWK: %v", ErrJWKS, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return parsedJWK{}, fmt.Errorf("%w: JWK entry must be a JSON object", ErrJWKS)
	}

	var k parsedJWK
	seen := make(map[string]struct{})

	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return parsedJWK{}, fmt.Errorf("%w: invalid JWK: %v", ErrJWKS, err)
		}
		name, ok := ktok.(string)
		if !ok {
			return parsedJWK{}, fmt.Errorf("%w: expected JWK member name", ErrJWKS)
		}
		if _, dup := seen[name]; dup {
			return parsedJWK{}, fmt.Errorf("%w: duplicate JWK member %q", ErrJWKS, name)
		}
		seen[name] = struct{}{}

		for _, known := range knownJWKMembers {
			if name != known && strings.EqualFold(name, known) {
				return parsedJWK{}, fmt.Errorf("%w: case-variant JWK member %q refused", ErrJWKS, name)
			}
		}

		switch name {
		case "kty", "kid", "alg", "use", "n", "e", "pub":
			vtok, err := dec.Token()
			if err != nil {
				return parsedJWK{}, fmt.Errorf("%w: invalid JWK member %q: %v", ErrJWKS, name, err)
			}
			s, ok := vtok.(string)
			if !ok {
				return parsedJWK{}, fmt.Errorf("%w: JWK member %q must be a string", ErrJWKS, name)
			}
			switch name {
			case "kty":
				k.Kty = s
			case "kid":
				k.Kid = s
			case "alg":
				k.Alg = s
			case "use":
				k.Use = s
			case "n":
				k.N = s
				k.hasN = true
			case "e":
				k.E = s
				k.hasE = true
			case "pub":
				k.Pub = s
				k.hasPub = true
			}
		case "key_ops":
			ops, err := readStringArray(dec)
			if err != nil {
				return parsedJWK{}, fmt.Errorf("%w: invalid key_ops: %v", ErrJWKS, err)
			}
			k.hasKeyOps = true
			k.keyOps = ops
		default:
			if err := skipJSONValue(dec, 2); err != nil {
				return parsedJWK{}, fmt.Errorf("%w: %v", ErrJWKS, err)
			}
		}
	}

	endTok, err := dec.Token()
	if err != nil {
		return parsedJWK{}, fmt.Errorf("%w: invalid JWK: %v", ErrJWKS, err)
	}
	if d, ok := endTok.(json.Delim); !ok || d != '}' {
		return parsedJWK{}, fmt.Errorf("%w: expected closing brace for JWK", ErrJWKS)
	}
	return k, nil
}

func readStringArray(dec *json.Decoder) ([]string, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, errors.New("expected JSON array")
	}
	var out []string
	for dec.More() {
		vtok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		s, ok := vtok.(string)
		if !ok {
			return nil, errors.New("expected string element")
		}
		out = append(out, s)
	}
	endTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := endTok.(json.Delim); !ok || d != ']' {
		return nil, errors.New("expected closing bracket")
	}
	return out, nil
}

func skipJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting depth exceeded")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			ktok, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := ktok.(string)
			if !ok {
				return errors.New("expected object key")
			}
			if _, dup := seen[name]; dup {
				return fmt.Errorf("duplicate JSON member %q", name)
			}
			seen[name] = struct{}{}
			if err := skipJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		endTok, err := dec.Token()
		if err != nil {
			return err
		}
		if ed, ok := endTok.(json.Delim); !ok || ed != '}' {
			return errors.New("expected closing brace")
		}
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		endTok, err := dec.Token()
		if err != nil {
			return err
		}
		if ed, ok := endTok.(json.Delim); !ok || ed != ']' {
			return errors.New("expected closing bracket")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", d)
	}
	return nil
}

type jwsHeader struct {
	Alg string
	Kid string
	Typ string
}

var knownHeaderMembers = []string{"alg", "kid", "typ", "crit"}

func parseStrictJWSHeader(raw []byte) (jwsHeader, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return jwsHeader{}, ErrMalformed
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return jwsHeader{}, ErrMalformed
	}

	var h jwsHeader
	seen := make(map[string]struct{})

	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return jwsHeader{}, ErrMalformed
		}
		name, ok := ktok.(string)
		if !ok {
			return jwsHeader{}, ErrMalformed
		}
		if _, dup := seen[name]; dup {
			return jwsHeader{}, ErrMalformed
		}
		seen[name] = struct{}{}

		for _, known := range knownHeaderMembers {
			if name != known && strings.EqualFold(name, known) {
				return jwsHeader{}, ErrMalformed
			}
		}

		switch name {
		case "alg", "kid", "typ":
			vtok, err := dec.Token()
			if err != nil {
				return jwsHeader{}, ErrMalformed
			}
			s, ok := vtok.(string)
			if !ok {
				return jwsHeader{}, ErrMalformed
			}
			switch name {
			case "alg":
				h.Alg = s
			case "kid":
				h.Kid = s
			case "typ":
				h.Typ = s
			}
		case "crit":
			// RFC 7515 §4.1.11: reject any JWS with unsupported critical extensions.
			return jwsHeader{}, ErrMalformed
		default:
			if err := skipJSONValue(dec, 1); err != nil {
				return jwsHeader{}, ErrMalformed
			}
		}
	}

	endTok, err := dec.Token()
	if err != nil {
		return jwsHeader{}, ErrMalformed
	}
	if d, ok := endTok.(json.Delim); !ok || d != '}' {
		return jwsHeader{}, ErrMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return jwsHeader{}, ErrMalformed
	}
	return h, nil
}
