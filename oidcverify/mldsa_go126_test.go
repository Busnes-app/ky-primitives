//go:build !go1.27

package oidcverify

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
)

func TestGo126FallbackBehavior(t *testing.T) {
	got := SupportedAlgorithms()
	want := []string{AlgRS256}
	if !slices.Equal(got, want) {
		t.Fatalf("SupportedAlgorithms() = %v, want %v", got, want)
	}

	iss := newIssuer(t)
	v := iss.verifier()

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ML-DSA-65","kid":"m1"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss.srv.URL + `","sub":"u","aud":"kynotes","exp":9999999999}`))
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 3309))
	if _, err := v.Verify(context.Background(), hdr+"."+pay+"."+sig); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("ML-DSA-65 on Go 1.26: got %v, want ErrAlgorithm", err)
	}

	raw := make([]byte, MLDSA65PublicKeySize)
	jwk, err := MarshalAKPPublicJWK("m1", raw)
	if err != nil {
		t.Fatalf("MarshalAKPPublicJWK on Go 1.26: %v", err)
	}
	if _, err := ParseAKPPublicJWK(jwk); err != nil {
		t.Fatalf("ParseAKPPublicJWK on Go 1.26: %v", err)
	}
	if _, err := MarshalAKPPublicJWK("bad", raw[:MLDSA65PublicKeySize-1]); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("short AKP key on Go 1.26: got %v, want ErrWeakKey", err)
	}
}
