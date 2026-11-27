//go:build go1.27

package pinnedca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/pqtls"
)

func mustURI(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URI %q: %v", raw, err)
	}
	return u
}

func mustCA(t *testing.T, cn string) *CA {
	t.Helper()
	ca, err := GenerateCA(cn, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA(%q): %v", cn, err)
	}
	return ca
}

func mustServerLeaf(t *testing.T, ca *CA) tls.Certificate {
	t.Helper()
	cert, err := ca.IssueLeaf(LeafSpec{
		CommonName:  "broker.internal",
		DNSNames:    []string{"broker.internal"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueLeaf(server): %v", err)
	}
	return cert
}

func mustClientLeaf(t *testing.T, ca *CA) tls.Certificate {
	t.Helper()
	cert, err := ca.IssueLeaf(LeafSpec{
		CommonName:  "broker-client",
		URIs:        []*url.URL{mustURI(t, "urn:uuid:11111111-2222-3333-4444-555555555555")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueLeaf(client): %v", err)
	}
	return cert
}

// handshakePair runs a real loopback TCP TLS handshake and exchanges a ping/pong
// message so TLS 1.3 post-handshake client-auth alerts are always observed by both sides.
func handshakePair(t *testing.T, serverCfg, clientCfg *tls.Config) (serverState, clientState tls.ConnectionState, serverErr, clientErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type srvResult struct {
		state tls.ConnectionState
		err   error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvCh <- srvResult{err: err}
			return
		}
		defer func() { _ = raw.Close() }()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, serverCfg)
		if err := conn.Handshake(); err != nil {
			srvCh <- srvResult{err: err}
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			srvCh <- srvResult{state: conn.ConnectionState(), err: err}
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			srvCh <- srvResult{state: conn.ConnectionState(), err: err}
			return
		}
		srvCh <- srvResult{state: conn.ConnectionState()}
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn := tls.Client(raw, clientCfg)
	if err := conn.Handshake(); err != nil {
		clientErr = err
	} else if _, err := conn.Write([]byte("ping")); err != nil {
		clientErr = err
	} else {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			clientErr = err
		} else if string(buf) != "pong" {
			clientErr = errors.New("unexpected response: " + string(buf))
		}
		clientState = conn.ConnectionState()
	}
	_ = conn.Close()

	res := <-srvCh
	return res.state, clientState, res.err, clientErr
}

func TestGenerateCAAndPEMRoundTrip(t *testing.T) {
	ca1 := mustCA(t, "ky-internal-ca-1")
	ca2 := mustCA(t, "ky-internal-ca-2")

	if ca1.Cert.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("CA SignatureAlgorithm = %v, want MLDSA65", ca1.Cert.SignatureAlgorithm)
	}
	pub, ok := ca1.Cert.PublicKey.(*mldsa.PublicKey)
	if !ok || pub.Parameters() != mldsa.MLDSA65() {
		t.Fatalf("CA PublicKey = %T, want ML-DSA-65", ca1.Cert.PublicKey)
	}
	if !ca1.Cert.IsCA || !ca1.Cert.BasicConstraintsValid || !ca1.Cert.MaxPathLenZero {
		t.Fatalf("CA basic constraints not properly constrained: IsCA=%v Basic=%v MaxPathLenZero=%v",
			ca1.Cert.IsCA, ca1.Cert.BasicConstraintsValid, ca1.Cert.MaxPathLenZero)
	}
	if ca1.Cert.SerialNumber.Sign() <= 0 || ca1.Cert.SerialNumber.BitLen() > 128 {
		t.Fatalf("CA serial out of positive 128-bit range: %v", ca1.Cert.SerialNumber)
	}
	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) == 0 {
		t.Fatal("two generated CAs produced identical serial numbers")
	}
	if !ValidPin(ca1.SPKIPin()) || !ValidPin(ca1.CertSHA256()) {
		t.Fatalf("invalid pin/digest format: spki=%q cert=%q", ca1.SPKIPin(), ca1.CertSHA256())
	}
	pubPin, err := PublicKeySPKIPin(pub)
	if err != nil {
		t.Fatalf("PublicKeySPKIPin: %v", err)
	}
	if pubPin != ca1.SPKIPin() {
		t.Fatalf("PublicKeySPKIPin = %s, want %s", pubPin, ca1.SPKIPin())
	}

	certPEM, keyPEM, err := ca1.PEM()
	if err != nil {
		t.Fatalf("CA.PEM: %v", err)
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") || !strings.Contains(string(keyPEM), "BEGIN PRIVATE KEY") {
		t.Fatal("unexpected PEM block headers")
	}

	reloaded, err := ParseCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ParseCA: %v", err)
	}
	if !bytes.Equal(reloaded.Cert.Raw, ca1.Cert.Raw) {
		t.Fatal("reloaded CA cert bytes differ")
	}
	if !reloaded.PrivateKey().Equal(ca1.PrivateKey()) {
		t.Fatal("reloaded CA private key differs")
	}
	if reloaded.SPKIPin() != ca1.SPKIPin() {
		t.Fatal("reloaded CA SPKI pin differs")
	}
}

func TestGenerateIdentityAndPEMRoundTrip(t *testing.T) {
	id, err := GenerateIdentity(LeafSpec{
		CommonName:  "kypost-receiving",
		DNSNames:    []string{"mx1.internal"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		URIs:        []*url.URL{mustURI(t, "spiffe://ky.internal/mx/1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		Lifetime:    30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.Cert.IsCA {
		t.Fatal("identity certificate must not be a CA")
	}
	if id.Cert.SerialNumber.Sign() <= 0 || id.Cert.SerialNumber.BitLen() > 128 {
		t.Fatalf("identity serial out of positive 128-bit range: %v", id.Cert.SerialNumber)
	}
	if !ValidPin(id.SPKIPin()) {
		t.Fatalf("invalid SPKI pin: %q", id.SPKIPin())
	}

	certPEM, keyPEM, err := id.PEM()
	if err != nil {
		t.Fatalf("Identity.PEM: %v", err)
	}
	reloaded, err := ParseIdentity(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ParseIdentity: %v", err)
	}
	if !bytes.Equal(reloaded.Cert.Raw, id.Cert.Raw) || !reloaded.PrivateKey().Equal(id.PrivateKey()) {
		t.Fatal("reloaded identity does not match original")
	}
}

func TestParseRejectsBadPEMAndNonMLDSAKeys(t *testing.T) {
	ca := mustCA(t, "ca")
	certPEM, keyPEM, err := ca.PEM()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseCertPEM(append(bytes.Clone(certPEM), []byte("trailing")...)); !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf("trailing cert PEM: got %v, want ErrInvalidPEM", err)
	}
	if _, err := ParsePrivateKeyPEM(append(bytes.Clone(keyPEM), []byte("trailing")...)); !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf("trailing key PEM: got %v, want ErrInvalidPEM", err)
	}
	if _, err := ParseCertPEM(keyPEM); !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf("wrong cert block type: got %v, want ErrInvalidPEM", err)
	}
	if _, err := ParsePrivateKeyPEM(certPEM); !errors.Is(err, ErrInvalidPEM) {
		t.Fatalf("wrong key block type: got %v, want ErrInvalidPEM", err)
	}

	// Non-ML-DSA-65 PKCS#8 keys must be rejected with ErrNotMLDSA65.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ml44Priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	ml87Priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]any{
		"ed25519":    edPriv,
		"ecdsa-p256": ecPriv,
		"mldsa-44":   ml44Priv,
		"mldsa-87":   ml87Priv,
	} {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, err := ParsePrivateKeyPEM(raw); !errors.Is(err, ErrNotMLDSA65) {
			t.Fatalf("ParsePrivateKeyPEM(%s): got %v, want ErrNotMLDSA65", name, err)
		}
	}

	// Mismatched key and wrong role.
	otherCA := mustCA(t, "other-ca")
	if _, err := NewCA(ca.Cert, otherCA.PrivateKey()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("NewCA mismatched key: got %v, want ErrKeyMismatch", err)
	}
	id, err := GenerateIdentity(LeafSpec{
		CommonName:  "leaf",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA(id.Cert, id.PrivateKey()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("NewCA non-CA cert: got %v, want ErrKeyMismatch", err)
	}
	if _, err := NewIdentity(ca.Cert, ca.PrivateKey()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("NewIdentity CA cert: got %v, want ErrKeyMismatch", err)
	}
	if _, err := NewIdentity(id.Cert, ca.PrivateKey()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("NewIdentity mismatched key: got %v, want ErrKeyMismatch", err)
	}
}

func TestIssueCSRAndValidation(t *testing.T) {
	ca := mustCA(t, "broker-ca")

	// Valid ML-DSA-65 CSR whose embedded Subject/DNS should be ignored by IssueCSR.
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker-requested-cn"},
		DNSNames: []string{"evil.example"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	wantURI := mustURI(t, "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	cert, err := ca.IssueCSR(csrDER, LeafSpec{
		CommonName:  "broker-42",
		URIs:        []*url.URL{wantURI},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueCSR: %v", err)
	}
	if cert.Subject.CommonName != "broker-42" || len(cert.DNSNames) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != wantURI.String() {
		t.Fatalf("IssueCSR leaked CSR attributes: CN=%q DNS=%v URIs=%v", cert.Subject.CommonName, cert.DNSNames, cert.URIs)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify CSR-issued cert: %v", err)
	}

	// Non-ML-DSA-65 CSRs must be rejected.
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ml44Priv, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	spec := LeafSpec{
		CommonName:  "client",
		URIs:        []*url.URL{wantURI},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	}
	for name, priv := range map[string]any{
		"ed25519":    edPriv,
		"ecdsa-p256": ecPriv,
		"mldsa-44":   ml44Priv,
	} {
		badCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: name},
		}, priv)
		if err != nil {
			t.Fatalf("create %s CSR: %v", name, err)
		}
		if _, err := ca.IssueCSR(badCSR, spec); !errors.Is(err, ErrNotMLDSA65) {
			t.Fatalf("IssueCSR(%s): got %v, want ErrNotMLDSA65", name, err)
		}
	}

	// Tampered CSR signature must be rejected.
	tamperedCSR := bytes.Clone(csrDER)
	tamperedCSR[len(tamperedCSR)-1] ^= 0xff
	if _, err := ca.IssueCSR(tamperedCSR, spec); err == nil {
		t.Fatal("IssueCSR accepted tampered CSR")
	}

	// Invalid LeafSpecs must be rejected.
	badSpecs := []LeafSpec{
		{CommonName: "x", DNSNames: []string{"a.internal"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Lifetime: 0},
		{CommonName: "x", DNSNames: []string{"a.internal"}, ExtKeyUsage: nil, Lifetime: time.Hour},
		{CommonName: "x", DNSNames: []string{"a.internal"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, Lifetime: time.Hour},
		{CommonName: "no-san", ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, Lifetime: time.Hour},
		{CommonName: "uri-only-server", URIs: []*url.URL{wantURI}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Lifetime: time.Hour},
	}
	for i, bs := range badSpecs {
		if _, err := ca.IssueLeaf(bs); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("badSpecs[%d]: got %v, want ErrInvalidSpec", i, err)
		}
	}
}

func makeSelfSignedNonMLDSACert(t *testing.T, priv any, pub any, ekus []x509.ExtKeyUsage) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "non-mldsa"},
		DNSNames:              []string{"peer.internal"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate(non-mldsa): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        cert,
	}
}

// tamperCertSignature flips the last byte of an X.509 certificate's DER signature
// BIT STRING while preserving valid ASN.1 structure and identical SPKI bytes.
func tamperCertSignature(t *testing.T, der []byte) []byte {
	t.Helper()
	mutated := bytes.Clone(der)
	mutated[len(mutated)-1] ^= 0x01
	parsed, err := x509.ParseCertificate(mutated)
	if err != nil {
		t.Fatalf("tampered cert failed to parse as X.509: %v", err)
	}
	orig, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse original cert: %v", err)
	}
	if SPKIPin(parsed) != SPKIPin(orig) {
		t.Fatal("test bug: tampering signature changed SPKI pin")
	}
	return mutated
}

func TestVerifyPeerPin(t *testing.T) {
	id, err := GenerateIdentity(LeafSpec{
		CommonName:  "peer",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateIdentity(LeafSpec{
		CommonName:  "other",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPeerPin(id.Cert, id.SPKIPin()); err != nil {
		t.Fatalf("VerifyPeerPin exact match: %v", err)
	}
	if err := VerifyPeerPin(id.Cert, other.SPKIPin(), id.SPKIPin()); err != nil {
		t.Fatalf("VerifyPeerPin multi-pin match: %v", err)
	}
	if err := VerifyPeerPin(id.Cert, other.SPKIPin()); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("VerifyPeerPin mismatch: got %v, want ErrPinMismatch", err)
	}
	if err := VerifyPeerPin(id.Cert, strings.ToUpper(id.SPKIPin())); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("VerifyPeerPin uppercase pin: got %v, want ErrPinMismatch", err)
	}
	if err := VerifyPeerPin(id.Cert); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("VerifyPeerPin empty pins: got %v, want ErrPinMismatch", err)
	}

	// Non-ML-DSA-65 certs must be rejected EVEN when their exact SPKI pin is listed.
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edCert, _ := makeSelfSignedNonMLDSACert(t, edPriv, edPub, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := VerifyPeerPin(edCert, SPKIPin(edCert)); !errors.Is(err, ErrNotMLDSA65) {
		t.Fatalf("VerifyPeerPin(Ed25519): got %v, want ErrNotMLDSA65", err)
	}

	ml44Priv, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	ml44Cert, _ := makeSelfSignedNonMLDSACert(t, ml44Priv, ml44Priv.Public(), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := VerifyPeerPin(ml44Cert, SPKIPin(ml44Cert)); !errors.Is(err, ErrNotMLDSA65) {
		t.Fatalf("VerifyPeerPin(ML-DSA-44): got %v, want ErrNotMLDSA65", err)
	}
}

func TestCAVerifiedMTLSSucceeds(t *testing.T) {
	ca := mustCA(t, "ky-broker-ca")
	srvCert := mustServerLeaf(t, ca)
	cliCert := mustClientLeaf(t, ca)

	srvCfg, err := ServerTLS(ca.Cert, srvCert)
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	cliCfg, err := ClientTLS(ca.Cert, "broker.internal", &cliCert)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}

	srvState, cliState, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("mTLS handshake failed: server=%v client=%v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srvState)
	pqtls.RequireHybrid(t, cliState)

	if len(srvState.PeerCertificates) == 0 || srvState.PeerCertificates[0].SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("server did not observe ML-DSA-65 client cert")
	}
	if len(cliState.PeerCertificates) == 0 || cliState.PeerCertificates[0].SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("client did not observe ML-DSA-65 server cert")
	}
}

func TestPinnedCAClientMTLSSucceeds(t *testing.T) {
	ca := mustCA(t, "ky-broker-ca")
	srvCert := mustServerLeaf(t, ca)
	cliCert := mustClientLeaf(t, ca)

	srvCfg, err := ServerTLS(ca.Cert, srvCert)
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	cliCfg, err := PinnedCAClientTLS(ca.SPKIPin(), "broker.internal", &cliCert)
	if err != nil {
		t.Fatalf("PinnedCAClientTLS: %v", err)
	}

	srvState, cliState, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("pinned-CA mTLS handshake failed: server=%v client=%v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srvState)
	pqtls.RequireHybrid(t, cliState)
}

func TestSPKIPinnedMTLSSucceeds(t *testing.T) {
	srvID, err := GenerateIdentity(LeafSpec{
		CommonName:  "replica-a",
		DNSNames:    []string{"replica-a.internal"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := GenerateIdentity(LeafSpec{
		CommonName:  "replica-b",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoy := hex.EncodeToString(sha256.New().Sum(nil))

	cliTLSCert := cliID.TLSCertificate()
	srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), []string{decoy, cliID.SPKIPin()})
	if err != nil {
		t.Fatalf("PinnedServerTLS: %v", err)
	}
	cliCfg, err := PinnedClientTLS([]string{decoy, srvID.SPKIPin()}, "replica-a.internal", &cliTLSCert)
	if err != nil {
		t.Fatalf("PinnedClientTLS: %v", err)
	}

	srvState, cliState, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("SPKI-pinned mTLS handshake failed: server=%v client=%v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srvState)
	pqtls.RequireHybrid(t, cliState)

	// Direct SPKI-pinned mTLS without DNS hostname (e.g. KyPost receiving host).
	cliCfgNoHost, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "", &cliTLSCert)
	if err != nil {
		t.Fatalf("PinnedClientTLS(empty serverName): %v", err)
	}
	srvState2, cliState2, srvErr, cliErr := handshakePair(t, srvCfg, cliCfgNoHost)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("SPKI-pinned mTLS (no serverName) failed: server=%v client=%v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srvState2)
	pqtls.RequireHybrid(t, cliState2)

	// SPKI-pinned mTLS also works when peers present CA-issued ML-DSA-65 chains.
	ca := mustCA(t, "chain-ca")
	caSrv := mustServerLeaf(t, ca)
	caCli := mustClientLeaf(t, ca)
	srvChainCfg, err := PinnedServerTLS(caSrv, []string{SPKIPin(caCli.Leaf)})
	if err != nil {
		t.Fatalf("PinnedServerTLS(chain): %v", err)
	}
	cliChainCfg, err := PinnedClientTLS([]string{SPKIPin(caSrv.Leaf)}, "broker.internal", &caCli)
	if err != nil {
		t.Fatalf("PinnedClientTLS(chain): %v", err)
	}
	srvState3, cliState3, srvErr, cliErr := handshakePair(t, srvChainCfg, cliChainCfg)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("SPKI-pinned chain mTLS failed: server=%v client=%v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srvState3)
	pqtls.RequireHybrid(t, cliState3)
}

func TestCAVerifiedMTLSRejects(t *testing.T) {
	ca1 := mustCA(t, "ca-1")
	ca2 := mustCA(t, "ca-2")
	goodSrv := mustServerLeaf(t, ca1)
	goodCli := mustClientLeaf(t, ca1)

	t.Run("wrong server CA", func(t *testing.T) {
		wrongSrv := mustServerLeaf(t, ca2)
		srvCfg, err := ServerTLS(ca1.Cert, wrongSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("client accepted server signed by wrong CA")
		}
	})

	t.Run("wrong client CA", func(t *testing.T) {
		wrongCli := mustClientLeaf(t, ca2)
		srvCfg, err := ServerTLS(ca1.Cert, goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &wrongCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
		if srvErr == nil && cliErr == nil {
			t.Fatal("server accepted client signed by wrong CA")
		}
	})

	t.Run("missing client cert", func(t *testing.T) {
		srvCfg, err := ServerTLS(ca1.Cert, goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
		if srvErr == nil && cliErr == nil {
			t.Fatal("mTLS server accepted client without certificate")
		}
	})

	t.Run("expired server cert", func(t *testing.T) {
		expiredSrv, err := ca1.IssueLeaf(LeafSpec{
			CommonName:  "broker.internal",
			DNSNames:    []string{"broker.internal"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			NotBefore:   time.Now().Add(-2 * time.Hour),
			Lifetime:    time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		srvCfg, err := ServerTLS(ca1.Cert, expiredSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("client accepted expired server certificate")
		}
	})

	t.Run("expired client cert", func(t *testing.T) {
		expiredCli, err := ca1.IssueLeaf(LeafSpec{
			CommonName:  "expired-client",
			URIs:        []*url.URL{mustURI(t, "urn:uuid:expired")},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			NotBefore:   time.Now().Add(-2 * time.Hour),
			Lifetime:    time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		srvCfg, err := ServerTLS(ca1.Cert, goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &expiredCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
		if srvErr == nil && cliErr == nil {
			t.Fatal("server accepted expired client certificate")
		}
	})

	t.Run("tampered server cert signature", func(t *testing.T) {
		tampered := goodSrv
		tampered.Certificate = [][]byte{tamperCertSignature(t, goodSrv.Certificate[0]), ca1.Cert.Raw}
		tampered.Leaf = nil
		srvCfg := pqtls.HybridOnly(&tls.Config{
			Certificates: []tls.Certificate{tampered},
		})
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("client accepted tampered server certificate")
		}
	})

	t.Run("wrong hostname", func(t *testing.T) {
		srvCfg, err := ServerTLS(ca1.Cert, goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "wrong.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("client accepted mismatched server hostname")
		}
	})

	t.Run("wrong EKU server presents client cert", func(t *testing.T) {
		clientOnlyWithDNS, err := ca1.IssueLeaf(LeafSpec{
			CommonName:  "broker.internal",
			DNSNames:    []string{"broker.internal"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			Lifetime:    time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		srvCfg, err := ServerTLS(ca1.Cert, clientOnlyWithDNS)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("client accepted server certificate with ClientAuth-only EKU")
		}
	})

	t.Run("wrong EKU client presents server cert", func(t *testing.T) {
		srvCfg, err := ServerTLS(ca1.Cert, goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
		if srvErr == nil && cliErr == nil {
			t.Fatal("server accepted client certificate with ServerAuth-only EKU")
		}
	})

	t.Run("empty EKU leaf signed by CA rejected", func(t *testing.T) {
		leafKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(99),
			Subject:               pkix.Name{CommonName: "no-eku"},
			DNSNames:              []string{"broker.internal"},
			NotBefore:             now.Add(-time.Minute),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca1.Cert, leafKey.Public(), ca1.PrivateKey())
		if err != nil {
			t.Fatal(err)
		}
		noEKUCert := tls.Certificate{Certificate: [][]byte{der, ca1.Cert.Raw}, PrivateKey: leafKey}
		srvCfg := pqtls.HybridOnly(&tls.Config{Certificates: []tls.Certificate{noEKUCert}})
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrWrongEKU) {
			t.Fatalf("empty EKU leaf: got %v, want ErrWrongEKU", cliErr)
		}
	})

	t.Run("non-ML-DSA Ed25519 leaf signed by ML-DSA-65 CA rejected", func(t *testing.T) {
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(100),
			Subject:               pkix.Name{CommonName: "ed-leaf"},
			DNSNames:              []string{"broker.internal"},
			NotBefore:             now.Add(-time.Minute),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca1.Cert, edPub, ca1.PrivateKey())
		if err != nil {
			t.Fatal(err)
		}
		edSrvCert := tls.Certificate{Certificate: [][]byte{der, ca1.Cert.Raw}, PrivateKey: edPriv}
		srvCfg := pqtls.HybridOnly(&tls.Config{Certificates: []tls.Certificate{edSrvCert}})
		cliCfg, err := ClientTLS(ca1.Cert, "broker.internal", &goodCli)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrNotMLDSA65) {
			t.Fatalf("Ed25519 leaf under ML-DSA-65 CA: got %v, want ErrNotMLDSA65", cliErr)
		}
	})

	t.Run("classical X25519-only client rejected", func(t *testing.T) {
		srvCfg, err := ServerTLS(ca1.Cert, goodSrv)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg := &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519},
			RootCAs:          ca1.CertPool(),
			ServerName:       "broker.internal",
			Certificates:     []tls.Certificate{goodCli},
		}
		_, _, srvErr, cliErr := handshakePair(t, srvCfg, cliCfg)
		if srvErr == nil && cliErr == nil {
			t.Fatal("server accepted classical X25519-only peer")
		}
	})
}

func TestPinnedCAClientRejects(t *testing.T) {
	ca1 := mustCA(t, "ca-1")
	ca2 := mustCA(t, "ca-2")
	srvCert := mustServerLeaf(t, ca1)
	cliCert := mustClientLeaf(t, ca1)

	t.Run("wrong CA SPKI pin", func(t *testing.T) {
		srvCfg, err := ServerTLS(ca1.Cert, srvCert)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedCAClientTLS(ca2.SPKIPin(), "broker.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrPinnedCA) {
			t.Fatalf("wrong CA pin: got %v, want ErrPinnedCA", cliErr)
		}
	})

	t.Run("server omits CA from chain", func(t *testing.T) {
		leafOnly := srvCert
		leafOnly.Certificate = [][]byte{srvCert.Certificate[0]}
		srvCfg, err := ServerTLS(ca1.Cert, leafOnly)
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedCAClientTLS(ca1.SPKIPin(), "broker.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrPinnedCA) {
			t.Fatalf("missing CA in chain: got %v, want ErrPinnedCA", cliErr)
		}
	})

	t.Run("tampered CA cert signature with matching SPKI pin", func(t *testing.T) {
		tamperedChain := srvCert
		tamperedChain.Certificate = [][]byte{srvCert.Certificate[0], tamperCertSignature(t, ca1.Cert.Raw)}
		srvCfg := pqtls.HybridOnly(&tls.Config{
			Certificates: []tls.Certificate{tamperedChain},
		})
		cliCfg, err := PinnedCAClientTLS(ca1.SPKIPin(), "broker.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("PinnedCAClientTLS accepted tampered CA certificate")
		}
	})
}

func TestSPKIPinnedMTLSRejects(t *testing.T) {
	srvID, err := GenerateIdentity(LeafSpec{
		CommonName:  "srv",
		DNSNames:    []string{"srv.internal"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := GenerateIdentity(LeafSpec{
		CommonName:  "cli",
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := GenerateIdentity(LeafSpec{
		CommonName:  "other",
		DNSNames:    []string{"srv.internal"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cliCert := cliID.TLSCertificate()

	t.Run("wrong server SPKI pin", func(t *testing.T) {
		srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), []string{cliID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{otherID.SPKIPin()}, "srv.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrPinMismatch) {
			t.Fatalf("wrong server pin: got %v, want ErrPinMismatch", cliErr)
		}
	})

	t.Run("wrong client SPKI pin", func(t *testing.T) {
		srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), []string{otherID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "srv.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, _ := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(srvErr, ErrPinMismatch) {
			t.Fatalf("wrong client pin: got %v, want ErrPinMismatch", srvErr)
		}
	})

	t.Run("mutating caller pin slice after config creation has no effect", func(t *testing.T) {
		pins := []string{otherID.SPKIPin()}
		srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), pins)
		if err != nil {
			t.Fatal(err)
		}
		// Mutate caller slice after construction; server must still reject cliID.
		pins[0] = cliID.SPKIPin()
		cliCfg, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "srv.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, _ := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(srvErr, ErrPinMismatch) {
			t.Fatalf("post-construction slice mutation bypassed pin check: got %v", srvErr)
		}
	})

	t.Run("tampered self-signed server cert signature with matching SPKI pin", func(t *testing.T) {
		tampered := srvID.TLSCertificate()
		tampered.Certificate = [][]byte{tamperCertSignature(t, srvID.Cert.Raw)}
		tampered.Leaf = nil
		srvCfg := pqtls.HybridOnly(&tls.Config{
			Certificates: []tls.Certificate{tampered},
		})
		cliCfg, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "srv.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("client accepted tampered self-signed certificate despite invalid self-signature")
		}
	})

	t.Run("tampered self-signed client cert signature with matching SPKI pin", func(t *testing.T) {
		tampered := cliID.TLSCertificate()
		tampered.Certificate = [][]byte{tamperCertSignature(t, cliID.Cert.Raw)}
		tampered.Leaf = nil
		srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), []string{cliID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg := pqtls.HybridOnly(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test peer sending tampered client cert
			Certificates:       []tls.Certificate{tampered},
		})
		_, _, srvErr, _ := handshakePair(t, srvCfg, cliCfg)
		if srvErr == nil {
			t.Fatal("server accepted tampered self-signed client certificate")
		}
	})

	t.Run("expired self-signed server cert", func(t *testing.T) {
		expiredSrv, err := GenerateIdentity(LeafSpec{
			CommonName:  "expired-srv",
			DNSNames:    []string{"srv.internal"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			NotBefore:   time.Now().Add(-2 * time.Hour),
			Lifetime:    time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		srvCfg, err := PinnedServerTLS(expiredSrv.TLSCertificate(), []string{cliID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{expiredSrv.SPKIPin()}, "srv.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		var certErr x509.CertificateInvalidError
		if !errors.As(cliErr, &certErr) || certErr.Reason != x509.Expired {
			t.Fatalf("expired pinned server cert: got %v, want x509.Expired", cliErr)
		}
	})

	t.Run("not-yet-valid self-signed client cert", func(t *testing.T) {
		futureCli, err := GenerateIdentity(LeafSpec{
			CommonName:  "future-cli",
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			NotBefore:   time.Now().Add(time.Hour),
			Lifetime:    time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		futureCert := futureCli.TLSCertificate()
		srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), []string{futureCli.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "srv.internal", &futureCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, _ := handshakePair(t, srvCfg, cliCfg)
		var certErr x509.CertificateInvalidError
		if !errors.As(srvErr, &certErr) || certErr.Reason != x509.Expired {
			t.Fatalf("future pinned client cert: got %v, want x509.Expired", srvErr)
		}
	})

	t.Run("non-ML-DSA Ed25519 peer rejected even when its pin is allowed", func(t *testing.T) {
		edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		edCert, edTLS := makeSelfSignedNonMLDSACert(t, edPriv, edPub, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		srvCfg := pqtls.HybridOnly(&tls.Config{Certificates: []tls.Certificate{edTLS}})
		cliCfg, err := PinnedClientTLS([]string{SPKIPin(edCert)}, "", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrNotMLDSA65) {
			t.Fatalf("pinned Ed25519 server: got %v, want ErrNotMLDSA65", cliErr)
		}
	})

	t.Run("wrong EKU server presents ClientAuth-only identity", func(t *testing.T) {
		srvCfg, err := PinnedServerTLS(cliID.TLSCertificate(), []string{cliID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{cliID.SPKIPin()}, "", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(cliErr, ErrWrongEKU) {
			t.Fatalf("wrong server EKU: got %v, want ErrWrongEKU", cliErr)
		}
	})

	t.Run("wrong EKU client presents ServerAuth-only identity", func(t *testing.T) {
		srvTLSCert := srvID.TLSCertificate()
		srvCfg, err := PinnedServerTLS(srvTLSCert, []string{srvID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "srv.internal", &srvTLSCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, srvErr, _ := handshakePair(t, srvCfg, cliCfg)
		if !errors.Is(srvErr, ErrWrongEKU) {
			t.Fatalf("wrong client EKU: got %v, want ErrWrongEKU", srvErr)
		}
	})

	t.Run("wrong serverName when specified", func(t *testing.T) {
		srvCfg, err := PinnedServerTLS(srvID.TLSCertificate(), []string{cliID.SPKIPin()})
		if err != nil {
			t.Fatal(err)
		}
		cliCfg, err := PinnedClientTLS([]string{srvID.SPKIPin()}, "other.internal", &cliCert)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, cliErr := handshakePair(t, srvCfg, cliCfg)
		if cliErr == nil {
			t.Fatal("PinnedClientTLS accepted mismatched serverName")
		}
	})
}

func TestTLSConfigBuildersRejectBadInputs(t *testing.T) {
	ca := mustCA(t, "ca")
	srv := mustServerLeaf(t, ca)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, edTLS := makeSelfSignedNonMLDSACert(t, edPriv, edPub, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	if _, err := ServerTLS(ca.Cert, edTLS); !errors.Is(err, ErrNotMLDSA65) {
		t.Fatalf("ServerTLS(Ed25519): got %v, want ErrNotMLDSA65", err)
	}
	if _, err := ServerTLS(srv.Leaf, srv); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("ServerTLS(non-CA): got %v, want ErrInvalidSpec", err)
	}
	if _, err := ClientTLS(ca.Cert, "", nil); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("ClientTLS(empty serverName): got %v, want ErrInvalidSpec", err)
	}
	if _, err := ClientTLS(ca.Cert, "broker.internal", &edTLS); !errors.Is(err, ErrNotMLDSA65) {
		t.Fatalf("ClientTLS(Ed25519 client): got %v, want ErrNotMLDSA65", err)
	}
	if _, err := PinnedCAClientTLS("not-a-pin", "broker.internal", nil); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("PinnedCAClientTLS(bad pin): got %v, want ErrInvalidSpec", err)
	}
	if _, err := PinnedServerTLS(srv, nil); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("PinnedServerTLS(empty pins): got %v, want ErrInvalidSpec", err)
	}
	if _, err := PinnedServerTLS(srv, []string{"bad"}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("PinnedServerTLS(bad pin): got %v, want ErrInvalidSpec", err)
	}
	if _, err := PinnedClientTLS(nil, "", nil); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("PinnedClientTLS(empty pins): got %v, want ErrInvalidSpec", err)
	}
	if _, err := PinnedClientTLS([]string{ca.SPKIPin()}, "", &edTLS); !errors.Is(err, ErrNotMLDSA65) {
		t.Fatalf("PinnedClientTLS(Ed25519 client): got %v, want ErrNotMLDSA65", err)
	}
}
