package oidcverify

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func rsaJWKFields(t *testing.T, bits int) (nB64, eB64 string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
}

func modulusOfBits(bits int) string {
	// Set the top bit at position bits-1 so BitLen() == bits exactly.
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func validAKPPubB64() string {
	raw := make([]byte, MLDSA65PublicKeySize)
	for i := range raw {
		raw[i] = byte(i*31 + 7)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func nonCanonicalB64URL(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	idx := strings.IndexByte(alphabet, s[len(s)-1])
	if idx < 0 {
		t.Fatalf("invalid base64url tail %q", s[len(s)-1])
	}
	return s[:len(s)-1] + string(alphabet[idx^1])
}

func TestValidateJWKSAndStrongTransportKeyStrength(t *testing.T) {
	n2048, e2048 := rsaJWKFields(t, 2048)
	n1024, e1024 := rsaJWKFields(t, 1024)
	n2047 := modulusOfBits(2047)
	akpPub := validAKPPubB64()
	akp1951 := base64.RawURLEncoding.EncodeToString(make([]byte, MLDSA65PublicKeySize-1))
	akp1953 := base64.RawURLEncoding.EncodeToString(make([]byte, MLDSA65PublicKeySize+1))

	acceptCases := []struct {
		name string
		body string
	}{
		{"valid RSA-2048 without kid", `{"keys":[{"kty":"RSA","n":"` + n2048 + `","e":"` + e2048 + `"}]}`},
		{"valid AKP ML-DSA-65", `{"keys":[{"kty":"AKP","kid":"m1","use":"sig","alg":"ML-DSA-65","pub":"` + akpPub + `"}]}`},
		{"valid AKP ML-DSA-65 without kid or use", `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + akpPub + `"}]}`},
		{"valid dual RSA-2048 and AKP ML-DSA-65", `{"keys":[{"kty":"RSA","kid":"r1","use":"sig","alg":"RS256","n":"` + n2048 + `","e":"` + e2048 + `"},{"kty":"AKP","kid":"m1","use":"sig","alg":"ML-DSA-65","pub":"` + akpPub + `"}]}`},
		{"empty keys array", `{"keys":[]}`},
		{"EC P-256 passthrough", `{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`},
	}

	for _, tc := range acceptCases {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			client := &http.Client{Transport: StrongJWKSTransport{Base: srv.Client().Transport}}
			resp, err := client.Get(srv.URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.body {
				t.Fatalf("response body altered:\ngot:  %q\nwant: %q", string(got), tc.body)
			}
		})
	}

	rejectCases := []struct {
		name        string
		body        string
		wantWeak    bool
		wantContain string
	}{
		{
			name:        "weak 1024-bit RSA key",
			body:        `{"keys":[{"kty":"RSA","n":"` + n1024 + `","e":"` + e1024 + `"}]}`,
			wantWeak:    true,
			wantContain: "at least 2048 bits",
		},
		{
			name:        "weak 2047-bit RSA key",
			body:        `{"keys":[{"kty":"RSA","n":"` + n2047 + `","e":"AQAB"}]}`,
			wantWeak:    true,
			wantContain: "at least 2048 bits",
		},
		{
			name:        "mixed strong RSA and weak RSA",
			body:        `{"keys":[{"kty":"RSA","n":"` + n2048 + `","e":"` + e2048 + `"},{"kty":"RSA","n":"` + n1024 + `","e":"` + e1024 + `"}]}`,
			wantWeak:    true,
			wantContain: "at least 2048 bits",
		},
		{
			name:     "RSA with even exponent 2",
			body:     `{"keys":[{"kty":"RSA","n":"` + n2048 + `","e":"Ag"}]}`,
			wantWeak: true,
		},
		{
			name:     "RSA with exponent 1",
			body:     `{"keys":[{"kty":"RSA","n":"` + n2048 + `","e":"AQ"}]}`,
			wantWeak: true,
		},
		{
			name:     "RSA declaring ML-DSA-65 alg",
			body:     `{"keys":[{"kty":"RSA","alg":"ML-DSA-65","n":"` + n2048 + `","e":"` + e2048 + `"}]}`,
			wantWeak: true,
		},
		{
			name: "polyglot RSA with pub",
			body: `{"keys":[{"kty":"RSA","n":"` + n2048 + `","e":"` + e2048 + `","pub":"` + akpPub + `"}]}`,
		},
		{
			name:     "AKP missing alg",
			body:     `{"keys":[{"kty":"AKP","pub":"` + akpPub + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP ML-DSA-44",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-44","pub":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 1312)) + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP ML-DSA-87",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-87","pub":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 2592)) + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP alg RS256",
			body:     `{"keys":[{"kty":"AKP","alg":"RS256","pub":"` + akpPub + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP use enc",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","use":"enc","pub":"` + akpPub + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP pub 1951 bytes",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + akp1951 + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP pub 1953 bytes",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + akp1953 + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP pub padded base64url",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + akpPub + `="}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP pub embedded newline",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + akpPub[:16] + `\n` + akpPub[16:] + `"}]}`,
			wantWeak: true,
		},
		{
			name:     "AKP pub non-canonical trailing base64url bits",
			body:     `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + nonCanonicalB64URL(t, akpPub) + `"}]}`,
			wantWeak: true,
		},
		{
			name: "polyglot AKP with RSA n and e",
			body: `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"` + akpPub + `","n":"` + n2048 + `","e":"` + e2048 + `"}]}`,
		},
	}

	for _, tc := range rejectCases {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := ValidateJWKS([]byte(tc.body))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrJWKS) {
				t.Fatalf("error %v does not wrap ErrJWKS", err)
			}
			if tc.wantWeak && !errors.Is(err, ErrWeakKey) {
				t.Fatalf("error %v does not wrap ErrWeakKey", err)
			}
			if tc.wantContain != "" && !strings.Contains(err.Error(), tc.wantContain) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantContain)
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			client := &http.Client{Transport: StrongJWKSTransport{Base: srv.Client().Transport}}
			if resp, err := client.Get(srv.URL); err == nil {
				resp.Body.Close()
				t.Fatal("StrongJWKSTransport accepted invalid JWKS")
			}
		})
	}
}

func TestValidateJWKSRejectsJSONSmugglingAndMalformedInput(t *testing.T) {
	n2048, e2048 := rsaJWKFields(t, 2048)
	n1024, e1024 := rsaJWKFields(t, 1024)
	akpPub := validAKPPubB64()

	deepNested := `{"keys":[],"extra":` + strings.Repeat(`[`, maxJSONDepth+5) + strings.Repeat(`]`, maxJSONDepth+5) + `}`

	cases := []struct {
		name string
		body string
	}{
		{"duplicate n weak then strong", `{"keys":[{"kty":"RSA","n":"` + n1024 + `","n":"` + n2048 + `","e":"` + e2048 + `"}]}`},
		{"duplicate n strong then weak", `{"keys":[{"kty":"RSA","n":"` + n2048 + `","n":"` + n1024 + `","e":"` + e2048 + `"}]}`},
		{"duplicate pub", `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","pub":"bad","pub":"` + akpPub + `"}]}`},
		{"duplicate kty", `{"keys":[{"kty":"RSA","kty":"EC","n":"` + n1024 + `","e":"` + e1024 + `"}]}`},
		{"duplicate top-level keys", `{"keys":[{"kty":"RSA","n":"` + n2048 + `","e":"` + e2048 + `"}],"keys":[{"kty":"RSA","n":"` + n1024 + `","e":"` + e1024 + `"}]}`},
		{"duplicate nested member", `{"keys":[],"meta":{"a":1,"a":2}}`},
		{"capitalized Keys only", `{"Keys":[{"kty":"RSA","n":"` + n1024 + `","e":"` + e1024 + `"}]}`},
		{"capitalized Keys alongside keys", `{"keys":[],"Keys":[{"kty":"RSA","n":"` + n1024 + `","e":"` + e1024 + `"}]}`},
		{"case-variant N", `{"keys":[{"kty":"RSA","N":"` + n1024 + `","n":"` + n2048 + `","e":"` + e2048 + `"}]}`},
		{"case-variant Kty", `{"keys":[{"Kty":"RSA","n":"` + n1024 + `","e":"` + e1024 + `"}]}`},
		{"case-variant Alg", `{"keys":[{"kty":"AKP","Alg":"ML-DSA-44","alg":"ML-DSA-65","pub":"` + akpPub + `"}]}`},
		{"case-variant Pub", `{"keys":[{"kty":"AKP","alg":"ML-DSA-65","Pub":"bad","pub":"` + akpPub + `"}]}`},
		{"missing keys member", `{}`},
		{"null keys member", `{"keys":null}`},
		{"object keys member", `{"keys":{}}`},
		{"null JWK entry", `{"keys":[null]}`},
		{"missing kty", `{"keys":[{"alg":"ML-DSA-65","pub":"` + akpPub + `"}]}`},
		{"non-string kty", `{"keys":[{"kty":123}]}`},
		{"trailing JSON", `{"keys":[]} {"extra":true}`},
		{"excessive nesting depth", deepNested},
		{"not JSON", `not-json`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateJWKS([]byte(tc.body)); !errors.Is(err, ErrJWKS) {
				t.Fatalf("ValidateJWKS(%s) = %v, want ErrJWKS", tc.name, err)
			}
		})
	}
}

func TestStrongJWKSTransportHTTPGuards(t *testing.T) {
	t.Run("refuses 3xx redirect without following", func(t *testing.T) {
		var targetHits atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHits.Add(1)
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer target.Close()

		redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		defer redir.Close()

		client := &http.Client{Transport: StrongJWKSTransport{Base: redir.Client().Transport}}
		resp, err := client.Get(redir.URL)
		if err == nil {
			resp.Body.Close()
			t.Fatal("expected redirect to be refused")
		}
		if !errors.Is(err, ErrJWKS) {
			t.Fatalf("redirect error %v does not wrap ErrJWKS", err)
		}
		if targetHits.Load() != 0 {
			t.Fatalf("redirect target was contacted %d times", targetHits.Load())
		}
	})

	t.Run("caps response at 1 MiB", func(t *testing.T) {
		oversized := `{"keys":[],"pad":"` + strings.Repeat("a", MaxJWKSBytes+1) + `"}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(oversized))
		}))
		defer srv.Close()

		client := &http.Client{Transport: StrongJWKSTransport{Base: srv.Client().Transport}}
		resp, err := client.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
			t.Fatal("expected oversized JWKS to be refused")
		}
		if !errors.Is(err, ErrJWKS) {
			t.Fatalf("oversized error %v does not wrap ErrJWKS", err)
		}
	})

	t.Run("non-200 passes through untouched", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("upstream down"))
		}))
		defer srv.Close()

		client := &http.Client{Transport: StrongJWKSTransport{Base: srv.Client().Transport}}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error on 503: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusServiceUnavailable || string(body) != "upstream down" {
			t.Fatalf("status=%d body=%q", resp.StatusCode, string(body))
		}
	})

	t.Run("preserves exact unmodified response bytes", func(t *testing.T) {
		n2048, e2048 := rsaJWKFields(t, 2048)
		// Deliberate custom formatting/whitespace that re-marshaling would alter.
		exact := "{\n  \"keys\" : [\n    { \"kty\": \"RSA\", \"e\": \"" + e2048 + "\", \"n\": \"" + n2048 + "\" }\n  ]\n}\n"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(exact))
		}))
		defer srv.Close()

		client := &http.Client{Transport: StrongJWKSTransport{Base: srv.Client().Transport}}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte(exact)) {
			t.Fatalf("bytes were modified:\ngot:  %q\nwant: %q", string(got), exact)
		}
		var check map[string]any
		if err := json.Unmarshal(got, &check); err != nil {
			t.Fatal(err)
		}
	})
}
