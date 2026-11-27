//go:build go1.27

package oidcverify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mldsaIssuer struct {
	t        *testing.T
	key      *mldsa.PrivateKey
	kid      string
	rsaKey   *rsa.PrivateKey
	rsaKid   string
	server   *httptest.Server
	mu       sync.Mutex
	jwksBody []byte
	fetches  atomic.Int32
}

func newMLDSAIssuer(t *testing.T, withRSA bool) *mldsaIssuer {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	iss := &mldsaIssuer{
		t:   t,
		key: key,
		kid: "mldsa-k1",
	}
	akpJWK, err := MarshalMLDSA65PublicJWK(iss.kid, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	keys := []PublicJWK{akpJWK}
	if withRSA {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		iss.rsaKey = rk
		iss.rsaKid = "rsa-k1"
		rsaJWK, err := MarshalRSAPublicJWK(iss.rsaKid, &rk.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, rsaJWK)
	}
	body, err := MarshalJWKS(keys...)
	if err != nil {
		t.Fatal(err)
	}
	iss.jwksBody = body
	iss.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss.fetches.Add(1)
		iss.mu.Lock()
		b := iss.jwksBody
		iss.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(iss.server.Close)
	return iss
}

func (iss *mldsaIssuer) verifier(now func() time.Time) *Verifier {
	return &Verifier{
		Issuer:     iss.server.URL,
		Audience:   "test-client",
		HTTPClient: iss.server.Client(),
		Now:        now,
	}
}

func (iss *mldsaIssuer) signMLDSA(header, claims map[string]any) string {
	iss.t.Helper()
	return signMLDSAWithKey(iss.t, iss.key, header, claims, "")
}

func signMLDSAWithKey(t *testing.T, key *mldsa.PrivateKey, header, claims map[string]any, ctxStr string) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sig, err := key.Sign(nil, []byte(h+"."+p), &mldsa.Options{Context: ctxStr})
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (iss *mldsaIssuer) signRSA(header, claims map[string]any) string {
	iss.t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		iss.t.Fatal(err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		iss.t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, iss.rsaKey, crypto.SHA256, sum[:])
	if err != nil {
		iss.t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (iss *mldsaIssuer) baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":  iss.server.URL,
		"sub":  "user-pqc-42",
		"aud":  "test-client",
		"exp":  now.Add(time.Hour).Unix(),
		"iat":  now.Unix(),
		"role": "admin",
	}
}

func flipTrailingBase64URLBit(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := s[len(s)-1]
	idx := strings.IndexByte(alphabet, last)
	if idx < 0 {
		t.Fatalf("unexpected base64url char %q", last)
	}
	// Flip bit 0 (unused trailing bit when len(s)%4 == 2 or 3).
	return s[:len(s)-1] + string(alphabet[idx^1])
}

func TestSupportedAlgorithmsGo127(t *testing.T) {
	got := SupportedAlgorithms()
	want := []string{AlgMLDSA65, AlgRS256}
	if !slices.Equal(got, want) {
		t.Fatalf("SupportedAlgorithms() = %v, want %v", got, want)
	}
}

func TestMLDSA65VerifyNonceAndMiddleware(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	iss := newMLDSAIssuer(t, false)
	v := iss.verifier(func() time.Time { return now })

	claims := iss.baseClaims(now)
	claims["nonce"] = "pqc-nonce-1"
	tok := iss.signMLDSA(map[string]any{"alg": AlgMLDSA65, "kid": iss.kid, "typ": "JWT"}, claims)

	got, err := v.VerifyWithNonce(context.Background(), tok, "pqc-nonce-1")
	if err != nil {
		t.Fatalf("VerifyWithNonce(ML-DSA-65): %v", err)
	}
	if got.Subject != "user-pqc-42" || got.KeyID != iss.kid || got.Algorithm != AlgMLDSA65 || got.String("role") != "admin" {
		t.Fatalf("unexpected claims: %+v", got)
	}

	if _, err := v.VerifyWithNonce(context.Background(), tok, "wrong-nonce"); !errors.Is(err, ErrNonce) {
		t.Fatalf("wrong nonce: got %v, want ErrNonce", err)
	}

	// Verify via HTTP middleware too.
	var gotSub, gotAlg string
	h := v.Middleware(func(_ *http.Request, err error) {
		t.Errorf("unexpected middleware rejection: %v", err)
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("claims missing from context")
			return
		}
		gotSub, gotAlg = c.Subject, c.Algorithm
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || gotSub != "user-pqc-42" || gotAlg != AlgMLDSA65 {
		t.Fatalf("middleware: status=%d sub=%q alg=%q", rec.Code, gotSub, gotAlg)
	}
}

func TestMLDSA65VerifyLogout(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	iss := newMLDSAIssuer(t, false)
	v := iss.verifier(func() time.Time { return now })

	tok := iss.signMLDSA(
		map[string]any{"alg": AlgMLDSA65, "kid": iss.kid, "typ": "logout+jwt"},
		map[string]any{
			"iss":    iss.server.URL,
			"sub":    "user-pqc-42",
			"sid":    "sess-pqc-9",
			"aud":    "test-client",
			"iat":    now.Unix(),
			"exp":    now.Add(2 * time.Minute).Unix(),
			"jti":    "logout-pqc-1",
			"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
		},
	)

	got, err := v.VerifyLogout(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyLogout(ML-DSA-65): %v", err)
	}
	if got.Subject != "user-pqc-42" || got.SessionID != "sess-pqc-9" || got.JWTID != "logout-pqc-1" || got.KeyID != iss.kid || got.Algorithm != AlgMLDSA65 {
		t.Fatalf("unexpected logout claims: %+v", got)
	}
	// Authentication Verify must refuse ML-DSA-65 logout tokens.
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrTokenType) {
		t.Fatalf("Verify on logout token: got %v, want ErrTokenType", err)
	}
}

func TestDualKeyJWKSSeamlessVerificationAndPreferredAlgorithm(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	iss := newMLDSAIssuer(t, true)
	v := iss.verifier(func() time.Time { return now })

	// Static PreferredAlgorithm helper prefers ML-DSA-65 over RS256.
	pref, err := PreferredAlgorithm(iss.jwksBody)
	if err != nil || pref != AlgMLDSA65 {
		t.Fatalf("PreferredAlgorithm(dual JWKS) = (%q, %v), want (%q, nil)", pref, err, AlgMLDSA65)
	}

	// Verifier.PreferredAlgorithm shares JWKS cache with Verify.
	vPref, err := v.PreferredAlgorithm(context.Background())
	if err != nil || vPref != AlgMLDSA65 {
		t.Fatalf("v.PreferredAlgorithm() = (%q, %v), want (%q, nil)", vPref, err, AlgMLDSA65)
	}

	mldsaTok := iss.signMLDSA(map[string]any{"alg": AlgMLDSA65, "kid": iss.kid, "typ": "JWT"}, iss.baseClaims(now))
	rsaTok := iss.signRSA(map[string]any{"alg": AlgRS256, "kid": iss.rsaKid, "typ": "JWT"}, iss.baseClaims(now))

	c1, err := v.Verify(context.Background(), mldsaTok)
	if err != nil || c1.Algorithm != AlgMLDSA65 || c1.KeyID != iss.kid {
		t.Fatalf("Verify(ML-DSA-65) = (%+v, %v)", c1, err)
	}
	c2, err := v.Verify(context.Background(), rsaTok)
	if err != nil || c2.Algorithm != AlgRS256 || c2.KeyID != iss.rsaKid {
		t.Fatalf("Verify(RS256) = (%+v, %v)", c2, err)
	}
	if got := iss.fetches.Load(); got != 1 {
		t.Fatalf("expected 1 shared JWKS fetch across PreferredAlgorithm + dual Verify, got %d", got)
	}

	// Restricting AllowedAlgorithms to ML-DSA-65 rejects RS256.
	vPQCOnly := iss.verifier(func() time.Time { return now })
	vPQCOnly.AllowedAlgorithms = []string{AlgMLDSA65}
	if _, err := vPQCOnly.Verify(context.Background(), mldsaTok); err != nil {
		t.Fatalf("ML-DSA-65-only verifier rejected ML-DSA-65: %v", err)
	}
	if _, err := vPQCOnly.Verify(context.Background(), rsaTok); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("ML-DSA-65-only verifier on RS256: got %v, want ErrAlgorithm", err)
	}

	// Restricting AllowedAlgorithms to RS256 rejects ML-DSA-65 and reports RS256 as preferred.
	vRSAOnly := iss.verifier(func() time.Time { return now })
	vRSAOnly.AllowedAlgorithms = []string{AlgRS256}
	if pref, err := vRSAOnly.PreferredAlgorithm(context.Background()); err != nil || pref != AlgRS256 {
		t.Fatalf("RS256-only PreferredAlgorithm = (%q, %v), want RS256", pref, err)
	}
	if _, err := vRSAOnly.Verify(context.Background(), rsaTok); err != nil {
		t.Fatalf("RS256-only verifier rejected RS256: %v", err)
	}
	if _, err := vRSAOnly.Verify(context.Background(), mldsaTok); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("RS256-only verifier on ML-DSA-65: got %v, want ErrAlgorithm", err)
	}
}

func TestMLDSA65AlgorithmConfusionAndMutations(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	iss := newMLDSAIssuer(t, true)
	v := iss.verifier(func() time.Time { return now })

	good := iss.signMLDSA(map[string]any{"alg": AlgMLDSA65, "kid": iss.kid, "typ": "JWT"}, iss.baseClaims(now))
	parts := strings.Split(good, ".")

	// Tampered payload
	tamperedPayloadClaims := iss.baseClaims(now)
	tamperedPayloadClaims["sub"] = "attacker"
	tpb, _ := json.Marshal(tamperedPayloadClaims)
	tamperedPayload := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tpb) + "." + parts[2]

	// Tampered header
	thb, _ := json.Marshal(map[string]any{"alg": AlgMLDSA65, "kid": iss.kid, "typ": "at+jwt"})
	tamperedHeader := base64.RawURLEncoding.EncodeToString(thb) + "." + parts[1] + "." + parts[2]

	// Tampered signature (1-bit flip)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	flippedSig := append([]byte(nil), sigBytes...)
	flippedSig[len(flippedSig)/2] ^= 0x01
	tamperedSig := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(flippedSig)

	// Truncated & oversized signatures
	truncatedSig := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes[:len(sigBytes)-1])
	oversizedSig := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), sigBytes...), 0))

	// Non-empty ML-DSA context string must fail (RFC 9964 requires empty context)
	wrongContext := signMLDSAWithKey(t, iss.key, map[string]any{"alg": AlgMLDSA65, "kid": iss.kid}, iss.baseClaims(now), "non-empty")

	// Signed by a different ML-DSA-65 key with the same kid
	otherKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := signMLDSAWithKey(t, otherKey, map[string]any{"alg": AlgMLDSA65, "kid": iss.kid}, iss.baseClaims(now), "")

	// Unknown kid
	unknownKid := iss.signMLDSA(map[string]any{"alg": AlgMLDSA65, "kid": "no-such-kid"}, iss.baseClaims(now))

	// Algorithm confusion: ML-DSA-65 header pointing at RSA kid, and RS256 header pointing at AKP kid
	mldsaHeaderRSAKid := iss.signMLDSA(map[string]any{"alg": AlgMLDSA65, "kid": iss.rsaKid}, iss.baseClaims(now))
	rsaHeaderAKPKid := iss.signRSA(map[string]any{"alg": AlgRS256, "kid": iss.kid}, iss.baseClaims(now))

	// Unsupported / forbidden algorithms
	algNone := iss.signMLDSA(map[string]any{"alg": "none", "kid": iss.kid}, iss.baseClaims(now))
	alg44 := iss.signMLDSA(map[string]any{"alg": "ML-DSA-44", "kid": iss.kid}, iss.baseClaims(now))
	alg87 := iss.signMLDSA(map[string]any{"alg": "ML-DSA-87", "kid": iss.kid}, iss.baseClaims(now))

	// Non-canonical base64url in segments (padding, newline, non-zero trailing pad bits)
	paddedSig := parts[0] + "." + parts[1] + "." + parts[2] + "="
	newlineSig := parts[0] + "." + parts[1] + "." + parts[2][:10] + "\n" + parts[2][10:]
	// Make a payload whose length % 3 == 2 so flipping the last base64url char's bit 0 is non-canonical.
	raw2 := []byte(`{"iss":"a","sub":"b","x":"1"}`) // 29 bytes -> 29 % 3 == 2
	nonCanonPayload := parts[0] + "." + flipTrailingBase64URLBit(t, base64.RawURLEncoding.EncodeToString(raw2)) + "." + parts[2]

	// Strict header JSON checks: duplicate alg, case-variant Alg, crit header
	dupAlgHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","alg":"ML-DSA-65","kid":"` + iss.kid + `"}`))
	caseAlgHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"Alg":"none","alg":"ML-DSA-65","kid":"` + iss.kid + `"}`))
	critHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ML-DSA-65","kid":"` + iss.kid + `","crit":["exp"]}`))

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"tampered payload", tamperedPayload, ErrSignature},
		{"tampered header", tamperedHeader, ErrSignature},
		{"tampered signature", tamperedSig, ErrSignature},
		{"truncated signature", truncatedSig, ErrSignature},
		{"oversized signature", oversizedSig, ErrSignature},
		{"non-empty ML-DSA context", wrongContext, ErrSignature},
		{"wrong ML-DSA-65 key", wrongKey, ErrSignature},
		{"unknown kid", unknownKid, ErrUnknownKey},
		{"ML-DSA-65 header against RSA key", mldsaHeaderRSAKid, ErrAlgorithm},
		{"RS256 header against AKP key", rsaHeaderAKPKid, ErrAlgorithm},
		{"alg none", algNone, ErrAlgorithm},
		{"alg ML-DSA-44", alg44, ErrAlgorithm},
		{"alg ML-DSA-87", alg87, ErrAlgorithm},
		{"padded signature", paddedSig, ErrMalformed},
		{"newline in signature", newlineSig, ErrMalformed},
		{"non-canonical trailing base64url bits", nonCanonPayload, ErrMalformed},
		{"duplicate header alg", dupAlgHdr + "." + parts[1] + "." + parts[2], ErrMalformed},
		{"case-variant header Alg", caseAlgHdr + "." + parts[1] + "." + parts[2], ErrMalformed},
		{"critical header extension", critHdr + "." + parts[1] + "." + parts[2], ErrMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tc.token); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMLDSA65JWKSFilteringAndDuplicateKid(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pubRaw := key.PublicKey().Bytes()
	pubB64 := base64.RawURLEncoding.EncodeToString(pubRaw)
	nonCanonPub := flipTrailingBase64URLBit(t, pubB64)

	cases := []struct {
		name    string
		jwks    string
		wantErr error
	}{
		{
			name:    "AKP with wrong pub length 1951",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","use":"sig","pub":"` + base64.RawURLEncoding.EncodeToString(pubRaw[:1951]) + `"}]}`,
			wantErr: ErrUnknownKey,
		},
		{
			name:    "AKP with non-canonical base64url pub",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","use":"sig","pub":"` + nonCanonPub + `"}]}`,
			wantErr: ErrUnknownKey,
		},
		{
			name:    "AKP with use enc",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","use":"enc","pub":"` + pubB64 + `"}]}`,
			wantErr: ErrUnknownKey,
		},
		{
			name:    "AKP with missing alg",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","use":"sig","pub":"` + pubB64 + `"}]}`,
			wantErr: ErrUnknownKey,
		},
		{
			name:    "AKP with key_ops sign only",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","key_ops":["sign"],"pub":"` + pubB64 + `"}]}`,
			wantErr: ErrUnknownKey,
		},
		{
			name:    "AKP with key_ops verify accepted",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","key_ops":["verify"],"pub":"` + pubB64 + `"}]}`,
			wantErr: nil,
		},
		{
			name:    "duplicate signing kid fails JWKS fetch",
			jwks:    `{"keys":[{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","pub":"` + pubB64 + `"},{"kty":"AKP","kid":"k1","alg":"ML-DSA-65","pub":"` + pubB64 + `"}]}`,
			wantErr: ErrJWKS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.jwks))
			}))
			defer srv.Close()

			v := &Verifier{
				Issuer:     srv.URL,
				Audience:   "test-client",
				HTTPClient: srv.Client(),
				Now:        func() time.Time { return now },
			}
			tok := signMLDSAWithKey(t, key, map[string]any{"alg": AlgMLDSA65, "kid": "k1"}, map[string]any{
				"iss": srv.URL,
				"sub": "user-1",
				"aud": "test-client",
				"exp": now.Add(time.Hour).Unix(),
			}, "")

			_, err := v.Verify(context.Background(), tok)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAKPJWKMarshalAndParseHelpers(t *testing.T) {
	k65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	jwk65, err := MarshalMLDSA65PublicJWK("mldsa-1", k65.PublicKey())
	if err != nil {
		t.Fatalf("MarshalMLDSA65PublicJWK: %v", err)
	}
	if jwk65.Kty != "AKP" || jwk65.Alg != AlgMLDSA65 || jwk65.Use != "sig" || jwk65.Kid != "mldsa-1" {
		t.Fatalf("unexpected AKP JWK: %+v", jwk65)
	}
	parsedPub, err := ParseMLDSA65PublicJWK(jwk65)
	if err != nil {
		t.Fatalf("ParseMLDSA65PublicJWK: %v", err)
	}
	if !bytes.Equal(parsedPub.Bytes(), k65.PublicKey().Bytes()) {
		t.Fatal("round-tripped ML-DSA-65 public key bytes differ")
	}

	// Reject wrong parameter sets (ML-DSA-44 and ML-DSA-87), nil, uninitialized, empty kid.
	k44, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	k87, _ := mldsa.GenerateKey(mldsa.MLDSA87())
	if _, err := MarshalMLDSA65PublicJWK("k44", k44.PublicKey()); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("ML-DSA-44: got %v, want ErrWeakKey", err)
	}
	if _, err := MarshalMLDSA65PublicJWK("k87", k87.PublicKey()); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("ML-DSA-87: got %v, want ErrWeakKey", err)
	}
	if _, err := MarshalMLDSA65PublicJWK("nil", nil); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("nil pub: got %v, want ErrWeakKey", err)
	}
	if _, err := MarshalMLDSA65PublicJWK("zero", &mldsa.PublicKey{}); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("zero pub: got %v, want ErrWeakKey", err)
	}
	if _, err := MarshalMLDSA65PublicJWK("", k65.PublicKey()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty kid: got %v, want ErrMalformed", err)
	}

	// ParseAKPPublicJWK negative checks.
	badKty := jwk65
	badKty.Kty = "RSA"
	if _, err := ParseAKPPublicJWK(badKty); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("bad kty: got %v, want ErrAlgorithm", err)
	}
	badAlg := jwk65
	badAlg.Alg = "ML-DSA-44"
	if _, err := ParseAKPPublicJWK(badAlg); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("bad alg: got %v, want ErrAlgorithm", err)
	}
	badUse := jwk65
	badUse.Use = "enc"
	if _, err := ParseAKPPublicJWK(badUse); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("bad use: got %v, want ErrWeakKey", err)
	}
	polyglot := jwk65
	polyglot.N = "AQAB"
	if _, err := ParseAKPPublicJWK(polyglot); !errors.Is(err, ErrMalformed) {
		t.Fatalf("polyglot AKP+RSA: got %v, want ErrMalformed", err)
	}

	// MarshalJWKS round-trip with RSA + AKP and rejection of duplicate kid / weak RSA.
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwkRSA, err := MarshalRSAPublicJWK("rsa-1", &rsa2048.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rawJWKS, err := MarshalJWKS(jwk65, jwkRSA)
	if err != nil {
		t.Fatalf("MarshalJWKS(dual): %v", err)
	}
	if err := ValidateJWKS(rawJWKS); err != nil {
		t.Fatalf("ValidateJWKS(MarshalJWKS): %v", err)
	}
	if _, err := MarshalJWKS(jwk65, jwk65); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate kid in MarshalJWKS: got %v, want ErrMalformed", err)
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalRSAPublicJWK("weak", &rsa1024.PublicKey); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak RSA in MarshalRSAPublicJWK: got %v, want ErrWeakKey", err)
	}
}
