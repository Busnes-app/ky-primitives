package pqtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// CI runs this package with and without GODEBUG=fips140=on (separate go test
// invocations); both modes must negotiate the hybrid by default.
func TestDefaultConfigsNegotiateHybrid(t *testing.T) {
	t.Logf("fips140 enabled: %v", fips140.Enabled())
	server, client := fixture(t)
	cs, ss, err := handshake(server, client)
	if err != nil {
		t.Fatal(err)
	}
	RequireHybrid(t, cs)
	RequireHybrid(t, ss)
}

func TestHybridOnly(t *testing.T) {
	for _, tc := range []struct {
		name           string
		server, client func(*tls.Config)
		refused        bool
	}{
		{name: "both hybrid-only", server: hybrid, client: hybrid},
		{name: "hybrid-only server, default client", server: hybrid, client: none},
		{name: "default server, hybrid-only client", server: none, client: hybrid},
		{name: "hybrid-only server refuses X25519-only client", server: hybrid, client: x25519, refused: true},
		{name: "hybrid-only client refuses X25519-only server", server: x25519, client: hybrid, refused: true},
		{name: "hybrid-only server refuses P-256-only client", server: hybrid, client: p256, refused: true},
		{name: "hybrid-only server refuses TLS 1.2 client", server: hybrid, client: tls12, refused: true},
		// RSA key exchange needs no curve, so only the TLS 1.3 floor refuses it.
		{name: "hybrid-only server refuses TLS 1.2 RSA key exchange", server: rsaKex(hybrid), client: rsaKex(tls12), refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := fixture(t)
			tc.server(server)
			tc.client(client)
			cs, ss, err := handshake(server, client)
			if tc.refused {
				if err == nil {
					t.Fatalf("handshake succeeded with %v, want refusal", cs.CurveID)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			RequireHybrid(t, cs)
			RequireHybrid(t, ss)
		})
	}
}

func TestRequireHybridFailsClassical(t *testing.T) {
	for _, state := range []tls.ConnectionState{
		{HandshakeComplete: true, CurveID: tls.X25519},
		{HandshakeComplete: true, CurveID: tls.CurveP256},
		{HandshakeComplete: true},
		{CurveID: tls.X25519MLKEM768},
	} {
		var f fakeTB
		RequireHybrid(&f, state)
		if !f.failed {
			t.Errorf("RequireHybrid accepted %v (complete %v)", state.CurveID, state.HandshakeComplete)
		}
	}
	var f fakeTB
	RequireHybrid(&f, tls.ConnectionState{HandshakeComplete: true, CurveID: tls.X25519MLKEM768})
	if f.failed {
		t.Error("RequireHybrid refused X25519MLKEM768")
	}
}

type fakeTB struct{ failed bool }

func (*fakeTB) Helper()                 {}
func (f *fakeTB) Fatalf(string, ...any) { f.failed = true }

func none(*tls.Config)     {}
func hybrid(c *tls.Config) { HybridOnly(c) }
func x25519(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} }
func p256(c *tls.Config)   { c.CurvePreferences = []tls.CurveID{tls.CurveP256} }
func tls12(c *tls.Config)  { c.MaxVersion = tls.VersionTLS12 }

// rsaKex applies f and then enables classical TLS 1.2 RSA key exchange, with an
// RSA certificate on the server side.
func rsaKex(f func(*tls.Config)) func(*tls.Config) {
	return func(c *tls.Config) {
		f(c)
		c.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
		if c.Certificates != nil {
			c.Certificates = []tls.Certificate{rsaCert}
		} else {
			c.RootCAs = x509.NewCertPool()
			c.RootCAs.AddCert(rsaCert.Leaf)
		}
	}
}

var rsaCert = func() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return selfSigned(key)
}()

// fixture returns default server and client configs sharing a fresh P-256
// certificate for 127.0.0.1, permitted with and without fips140=on.
func fixture(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(key)
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}
}

func selfSigned(key crypto.Signer) tls.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pqtls fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// handshake runs a real TLS handshake over loopback TCP and returns both
// sides' connection state.
func handshake(server, client *tls.Config) (cs, ss tls.ConnectionState, err error) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		return cs, ss, err
	}
	defer ln.Close()
	type result struct {
		state tls.ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		tc := c.(*tls.Conn)
		err = tc.Handshake()
		done <- result{tc.ConnectionState(), err}
	}()
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, cerr := tls.DialWithDialer(d, "tcp", ln.Addr().String(), client)
	if cerr == nil {
		cs = conn.ConnectionState()
		conn.Close()
	}
	r := <-done
	if cerr != nil || r.err != nil {
		return cs, r.state, fmt.Errorf("client: %v, server: %v", cerr, r.err)
	}
	return cs, r.state, nil
}
