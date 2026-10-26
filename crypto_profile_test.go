package kyprimitives

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// Runtime TLS policy is fixed at process startup. Exercise real verified HTTPS in
// both modes, including weak keys in trusted roots/intermediates, without changing
// any production client's hostname, trust, redirect or destination rules.
func TestStrongTLSProfile(t *testing.T) {
	mode := os.Getenv("KY_TEST_TLS_PROFILE")
	if mode == "" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"off", "on"} {
			t.Run(mode, func(t *testing.T) {
				cmd := exec.Command(binary, "-test.run=^TestStrongTLSProfile$", "-test.v")
				cmd.Env = append(os.Environ(), "GODEBUG=fips140="+mode, "KY_TEST_TLS_PROFILE="+mode)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("TLS profile %s: %v\n%s", mode, err, out)
				}
				t.Logf("%s", out)
			})
		}
		return
	}
	if fips140.Enabled() != (mode == "on") {
		t.Fatalf("fips140.Enabled() = %v, requested %s", fips140.Enabled(), mode)
	}
	rsaKey := func(bits int) *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	ecKey := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	strongRSA, weakRSA, boundaryRSA := rsaKey(2048), rsaKey(1024), rsaKey(2047)
	strongEC, smallEC := ecKey(elliptic.P256()), ecKey(elliptic.P224())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                       string
		root, intermediate, leaf   crypto.Signer
		weak, wrongName, untrusted bool
	}{
		{name: "RSA2048", root: strongRSA, leaf: strongRSA},
		{name: "P256", root: strongRSA, leaf: strongEC},
		{name: "Ed25519", root: strongRSA, leaf: edKey},
		{name: "RSA1024 leaf", root: strongRSA, leaf: weakRSA, weak: true},
		{name: "RSA2047 leaf", root: strongRSA, leaf: boundaryRSA, weak: true},
		{name: "RSA1024 trusted root", root: weakRSA, leaf: strongRSA, weak: true},
		{name: "RSA1024 intermediate", root: strongRSA, intermediate: weakRSA, leaf: strongRSA, weak: true},
		{name: "P224 trusted root", root: smallEC, leaf: strongEC, weak: true},
		{name: "hostname still checked", root: strongRSA, leaf: strongRSA, wrongName: true},
		{name: "trust still checked", root: strongRSA, leaf: strongRSA, untrusted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, roots := tlsProfileChain(t, tc.root, tc.intermediate, tc.leaf)
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					var requests atomic.Int32
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						requests.Add(1)
						w.WriteHeader(http.StatusNoContent)
					}))
					server.Config.ErrorLog = log.New(io.Discard, "", 0)
					server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version}
					server.StartTLS()
					defer server.Close()
					cfg := &tls.Config{RootCAs: roots, MinVersion: version, MaxVersion: version}
					if tc.wrongName {
						cfg.ServerName = "wrong.example.invalid"
					}
					if tc.untrusted {
						cfg.RootCAs = x509.NewCertPool()
					}
					transport := &http.Transport{TLSClientConfig: cfg}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
					req, err := http.NewRequest(http.MethodGet, server.URL, nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Authorization", "Bearer synthetic-test-credential")
					response, err := client.Do(req)
					refuse := tc.wrongName || tc.untrusted || (tc.weak && mode == "on")
					if refuse {
						if err == nil {
							response.Body.Close()
							t.Fatal("HTTPS accepted a certificate outside the configured policy")
						}
						if requests.Load() != 0 {
							t.Fatal("sent an authenticated request before refusing the peer")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					if response.StatusCode != http.StatusNoContent || requests.Load() != 1 {
						t.Fatal("verified HTTPS request did not reach the fixture")
					}
				})
			}
		})
	}
}

func tlsProfileChain(t *testing.T, root, intermediate, leaf crypto.Signer) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	issue := func(serial int64, ca bool, key crypto.Signer, parent *x509.Certificate, signer crypto.Signer) ([]byte, *x509.Certificate) {
		t.Helper()
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "local TLS profile fixture"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if ca {
			cert.KeyUsage |= x509.KeyUsageCertSign
		} else {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		if parent == nil {
			parent, signer = cert, key
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return der, parsed
	}
	_, rootCert := issue(1, true, root, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	parent, signer := rootCert, root
	var chain [][]byte
	if intermediate != nil {
		der, cert := issue(2, true, intermediate, rootCert, root)
		parent, signer, chain = cert, intermediate, [][]byte{der}
	}
	der, _ := issue(3, false, leaf, parent, signer)
	return tls.Certificate{Certificate: append([][]byte{der}, chain...), PrivateKey: leaf}, roots
}
