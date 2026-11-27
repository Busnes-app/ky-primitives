//go:build go1.27

// Package pinnedca provides an ML-DSA-65 (RFC 9881) internal certificate authority,
// self-signed pinned identities, SPKI-SHA256 pin verification, and hardened TLS 1.3
// (X25519MLKEM768-only via pqtls.HybridOnly) mTLS configurations for Ky-to-Ky links.
//
// It requires Go 1.27 for crypto/mldsa and RFC 9881 ML-DSA-65 X.509 certificates.
// Every certificate and private key accepted or produced by this package uses
// ML-DSA-65 exclusively; classical keys (Ed25519, ECDSA, RSA) and other ML-DSA
// parameter sets are rejected, and pins never waive key-algorithm checks.
package pinnedca

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"time"
)

const (
	clockSkew = time.Minute
	pinHexLen = sha256.Size * 2
)

var (
	// ErrNotMLDSA65 reports a key, CSR, or certificate that does not use ML-DSA-65.
	ErrNotMLDSA65 = errors.New("pinnedca: key or certificate is not ML-DSA-65")
	// ErrKeyMismatch reports a private key that does not match its certificate,
	// or a certificate whose CA flag does not match the requested role.
	ErrKeyMismatch = errors.New("pinnedca: private key does not match certificate")
	// ErrInvalidPEM reports PEM input that does not contain exactly one expected block.
	ErrInvalidPEM = errors.New("pinnedca: invalid PEM encoding")
	// ErrPinMismatch reports a peer certificate whose SPKI-SHA256 does not match any allowed pin.
	ErrPinMismatch = errors.New("pinnedca: peer SPKI pin does not match")
	// ErrPinnedCA reports a server certificate chain that does not terminate at the pinned CA.
	ErrPinnedCA = errors.New("pinnedca: certificate chain does not lead to pinned CA")
	// ErrInvalidSpec reports missing or invalid certificate or TLS configuration parameters.
	ErrInvalidSpec = errors.New("pinnedca: invalid specification")
	// ErrWrongEKU reports a peer certificate missing the required Extended Key Usage or Key Usage.
	ErrWrongEKU = errors.New("pinnedca: certificate lacks required key usage")
)

var maxSerial = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

// randomSerial generates a uniformly random positive 128-bit X.509 serial number
// in [1, 2^128-1], conforming to RFC 5280 Section 4.1.2.2.
func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: generate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// requireMLDSA65PrivateKey verifies that key is a non-nil ML-DSA-65 private key.
func requireMLDSA65PrivateKey(key *mldsa.PrivateKey) error {
	if key == nil || key.PublicKey().Parameters() != mldsa.MLDSA65() {
		return ErrNotMLDSA65
	}
	return nil
}

// requireMLDSA65PublicKey verifies that pub is a non-nil *mldsa.PublicKey with ML-DSA-65 parameters.
func requireMLDSA65PublicKey(pub any) (*mldsa.PublicKey, error) {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok || pk == nil || pk.Parameters() != mldsa.MLDSA65() {
		return nil, ErrNotMLDSA65
	}
	return pk, nil
}

// requireMLDSA65Cert verifies that cert carries an ML-DSA-65 public key and an ML-DSA-65 signature.
func requireMLDSA65Cert(cert *x509.Certificate) error {
	if cert == nil {
		return ErrNotMLDSA65
	}
	if cert.SignatureAlgorithm != x509.MLDSA65 {
		return ErrNotMLDSA65
	}
	if _, err := requireMLDSA65PublicKey(cert.PublicKey); err != nil {
		return err
	}
	return nil
}

// EncodeCertPEM encodes a DER certificate as a single CERTIFICATE PEM block.
func EncodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ParseCertPEM parses exactly one CERTIFICATE PEM block with no trailing non-whitespace data.
func ParseCertPEM(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: expected one CERTIFICATE block", ErrInvalidPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: parse certificate: %w", err)
	}
	return cert, nil
}

// EncodePrivateKeyPEM encodes an ML-DSA-65 private key as a PKCS #8 PRIVATE KEY PEM block.
func EncodePrivateKeyPEM(key *mldsa.PrivateKey) ([]byte, error) {
	if err := requireMLDSA65PrivateKey(key); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: marshal PKCS#8 key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM parses exactly one PKCS #8 PRIVATE KEY PEM block and enforces ML-DSA-65.
func ParsePrivateKeyPEM(raw []byte) (*mldsa.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: expected one PRIVATE KEY block", ErrInvalidPEM)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: parse PKCS#8 key: %w", err)
	}
	key, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		return nil, ErrNotMLDSA65
	}
	if err := requireMLDSA65PrivateKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// SPKIPin returns the lowercase hex SHA-256 of cert's DER SubjectPublicKeyInfo,
// or "" if cert is nil or lacks RawSubjectPublicKeyInfo.
func SPKIPin(cert *x509.Certificate) string {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// PublicKeySPKIPin returns the lowercase hex SHA-256 of pub's PKIX SubjectPublicKeyInfo.
func PublicKeySPKIPin(pub *mldsa.PublicKey) (string, error) {
	if _, err := requireMLDSA65PublicKey(pub); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("pinnedca: marshal PKIX public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// CertSHA256 returns the lowercase hex SHA-256 of cert's DER encoding,
// or "" if cert is nil or lacks Raw bytes.
func CertSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ValidPin reports whether pin is a well-formed 64-character lowercase hex SHA-256 digest.
func ValidPin(pin string) bool {
	if len(pin) != pinHexLen {
		return false
	}
	for i := range len(pin) {
		c := pin[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// VerifyPeerPin verifies that cert is an ML-DSA-65 certificate whose SPKI-SHA256
// matches at least one valid entry in allowedPins using constant-time comparison.
func VerifyPeerPin(cert *x509.Certificate, allowedPins ...string) error {
	if err := requireMLDSA65Cert(cert); err != nil {
		return err
	}
	got := SPKIPin(cert)
	if got == "" || len(allowedPins) == 0 {
		return ErrPinMismatch
	}
	gotBytes := []byte(got)
	matched := 0
	for _, pin := range allowedPins {
		if !ValidPin(pin) {
			continue
		}
		matched |= subtle.ConstantTimeCompare(gotBytes, []byte(pin))
	}
	if matched != 1 {
		return ErrPinMismatch
	}
	return nil
}

// LeafSpec describes a leaf certificate issued by a CA or a self-signed pinned Identity.
type LeafSpec struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	URIs        []*url.URL
	ExtKeyUsage []x509.ExtKeyUsage
	Lifetime    time.Duration
	// NotBefore optionally overrides the start of the validity window.
	// When zero, NotBefore is time.Now().Add(-time.Minute) and NotAfter is time.Now().Add(Lifetime).
	// When non-zero, NotAfter is NotBefore.Add(Lifetime).
	NotBefore time.Time
}

func validateLeafSpec(spec LeafSpec, requireSAN bool) error {
	if spec.Lifetime <= 0 {
		return fmt.Errorf("%w: lifetime must be positive", ErrInvalidSpec)
	}
	if len(spec.ExtKeyUsage) == 0 {
		return fmt.Errorf("%w: at least one explicit ExtKeyUsage is required", ErrInvalidSpec)
	}
	hasServerAuth := false
	for _, eku := range spec.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny {
			return fmt.Errorf("%w: ExtKeyUsageAny is not permitted", ErrInvalidSpec)
		}
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	for _, dns := range spec.DNSNames {
		if dns == "" {
			return fmt.Errorf("%w: empty DNS SAN", ErrInvalidSpec)
		}
	}
	for _, ip := range spec.IPAddresses {
		if len(ip) == 0 {
			return fmt.Errorf("%w: empty IP SAN", ErrInvalidSpec)
		}
	}
	for _, u := range spec.URIs {
		if u == nil || u.String() == "" {
			return fmt.Errorf("%w: empty URI SAN", ErrInvalidSpec)
		}
	}
	hasSAN := len(spec.DNSNames) > 0 || len(spec.IPAddresses) > 0 || len(spec.URIs) > 0
	if requireSAN && !hasSAN {
		return fmt.Errorf("%w: CA-issued leaf requires at least one SAN", ErrInvalidSpec)
	}
	if requireSAN && hasServerAuth && len(spec.DNSNames) == 0 && len(spec.IPAddresses) == 0 {
		return fmt.Errorf("%w: CA-issued server certificate requires a DNS or IP SAN", ErrInvalidSpec)
	}
	if !requireSAN && spec.CommonName == "" && !hasSAN {
		return fmt.Errorf("%w: identity requires a CommonName or SAN", ErrInvalidSpec)
	}
	return nil
}

func buildLeafTemplate(spec LeafSpec) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var notBefore, notAfter time.Time
	if spec.NotBefore.IsZero() {
		now := time.Now()
		notBefore = now.Add(-clockSkew)
		notAfter = now.Add(spec.Lifetime)
	} else {
		notBefore = spec.NotBefore
		notAfter = spec.NotBefore.Add(spec.Lifetime)
	}
	ips := make([]net.IP, len(spec.IPAddresses))
	for i, ip := range spec.IPAddresses {
		ips[i] = bytes.Clone(ip)
	}
	uris := make([]*url.URL, len(spec.URIs))
	for i, u := range spec.URIs {
		cp := *u
		uris[i] = &cp
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spec.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           slices.Clone(spec.ExtKeyUsage),
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              slices.Clone(spec.DNSNames),
		IPAddresses:           ips,
		URIs:                  uris,
	}, nil
}

// CA is an internal ML-DSA-65 certificate authority for Ky-to-Ky mTLS.
type CA struct {
	Cert *x509.Certificate
	key  *mldsa.PrivateKey
}

// GenerateCA creates a fresh self-signed ML-DSA-65 internal CA certificate and private key.
func GenerateCA(commonName string, lifetime time.Duration) (*CA, error) {
	if commonName == "" {
		return nil, fmt.Errorf("%w: CA commonName is required", ErrInvalidSpec)
	}
	if lifetime <= 0 {
		return nil, fmt.Errorf("%w: CA lifetime must be positive", ErrInvalidSpec)
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("pinnedca: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: parse generated CA certificate: %w", err)
	}
	return &CA{Cert: cert, key: key}, nil
}

// NewCA validates an ML-DSA-65 CA certificate and matching private key and returns a CA.
func NewCA(cert *x509.Certificate, key *mldsa.PrivateKey) (*CA, error) {
	if err := requireMLDSA65PrivateKey(key); err != nil {
		return nil, err
	}
	if err := requireMLDSA65Cert(cert); err != nil {
		return nil, err
	}
	pub := cert.PublicKey.(*mldsa.PublicKey)
	if !cert.IsCA || !pub.Equal(key.Public()) {
		return nil, ErrKeyMismatch
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("pinnedca: verify CA self-signature: %w", err)
	}
	return &CA{Cert: cert, key: key}, nil
}

// ParseCA parses a PEM-encoded ML-DSA-65 CA certificate and PKCS #8 private key.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return NewCA(cert, key)
}

// PEM encodes the CA certificate (CERTIFICATE) and private key (PKCS #8 PRIVATE KEY).
func (ca *CA) PEM() (certPEM, keyPEM []byte, err error) {
	if ca == nil || ca.Cert == nil || ca.key == nil {
		return nil, nil, ErrInvalidSpec
	}
	keyPEM, err = EncodePrivateKeyPEM(ca.key)
	if err != nil {
		return nil, nil, err
	}
	return EncodeCertPEM(ca.Cert.Raw), keyPEM, nil
}

// PrivateKey returns the CA's ML-DSA-65 private key.
func (ca *CA) PrivateKey() *mldsa.PrivateKey {
	if ca == nil {
		return nil
	}
	return ca.key
}

// SPKIPin returns the lowercase hex SHA-256 of the CA certificate's SubjectPublicKeyInfo.
func (ca *CA) SPKIPin() string {
	if ca == nil {
		return ""
	}
	return SPKIPin(ca.Cert)
}

// CertSHA256 returns the lowercase hex SHA-256 of the CA certificate's DER encoding.
func (ca *CA) CertSHA256() string {
	if ca == nil {
		return ""
	}
	return CertSHA256(ca.Cert)
}

// CertPool returns a fresh x509.CertPool containing only this CA certificate.
func (ca *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if ca != nil && ca.Cert != nil {
		pool.AddCert(ca.Cert)
	}
	return pool
}

// IssueLeaf generates a fresh ML-DSA-65 keypair and signs a leaf certificate with this CA.
// The returned tls.Certificate carries [leaf, ca] in Certificate so pinned-CA clients can
// locate the CA in the presented chain.
func (ca *CA) IssueLeaf(spec LeafSpec) (tls.Certificate, error) {
	if ca == nil || ca.Cert == nil || ca.key == nil {
		return tls.Certificate{}, fmt.Errorf("%w: nil CA", ErrInvalidSpec)
	}
	if err := validateLeafSpec(spec, true); err != nil {
		return tls.Certificate{}, err
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pinnedca: generate leaf key: %w", err)
	}
	tmpl, err := buildLeafTemplate(spec)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pinnedca: issue leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("pinnedca: parse issued leaf certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// IssueCSR verifies a DER-encoded PKCS #10 certificate signing request and signs a leaf
// certificate for its ML-DSA-65 public key using the caller-controlled spec.
// Any Subject, SANs, or extensions in the CSR are ignored; only its verified ML-DSA-65
// public key is bound into the issued certificate.
func (ca *CA) IssueCSR(csrDER []byte, spec LeafSpec) (*x509.Certificate, error) {
	if ca == nil || ca.Cert == nil || ca.key == nil {
		return nil, fmt.Errorf("%w: nil CA", ErrInvalidSpec)
	}
	if err := validateLeafSpec(spec, true); err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pinnedca: verify CSR signature: %w", err)
	}
	if csr.SignatureAlgorithm != x509.MLDSA65 {
		return nil, ErrNotMLDSA65
	}
	pub, err := requireMLDSA65PublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	tmpl, err := buildLeafTemplate(spec)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: sign CSR: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: parse signed certificate: %w", err)
	}
	return cert, nil
}

// Identity is a self-signed ML-DSA-65 certificate and private key for SPKI-pinned mTLS.
type Identity struct {
	Cert *x509.Certificate
	key  *mldsa.PrivateKey
}

// GenerateIdentity creates a fresh self-signed ML-DSA-65 identity certificate and private key.
func GenerateIdentity(spec LeafSpec) (*Identity, error) {
	if err := validateLeafSpec(spec, false); err != nil {
		return nil, err
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("pinnedca: generate identity key: %w", err)
	}
	tmpl, err := buildLeafTemplate(spec)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: create identity certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pinnedca: parse generated identity certificate: %w", err)
	}
	return &Identity{Cert: cert, key: key}, nil
}

// NewIdentity validates a self-signed ML-DSA-65 identity certificate and matching private key.
func NewIdentity(cert *x509.Certificate, key *mldsa.PrivateKey) (*Identity, error) {
	if err := requireMLDSA65PrivateKey(key); err != nil {
		return nil, err
	}
	if err := requireMLDSA65Cert(cert); err != nil {
		return nil, err
	}
	pub := cert.PublicKey.(*mldsa.PublicKey)
	if cert.IsCA || !pub.Equal(key.Public()) {
		return nil, ErrKeyMismatch
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, ErrKeyMismatch
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, fmt.Errorf("pinnedca: verify identity self-signature: %w", err)
	}
	return &Identity{Cert: cert, key: key}, nil
}

// ParseIdentity parses a PEM-encoded self-signed ML-DSA-65 identity certificate and PKCS #8 private key.
func ParseIdentity(certPEM, keyPEM []byte) (*Identity, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return NewIdentity(cert, key)
}

// PEM encodes the identity certificate (CERTIFICATE) and private key (PKCS #8 PRIVATE KEY).
func (id *Identity) PEM() (certPEM, keyPEM []byte, err error) {
	if id == nil || id.Cert == nil || id.key == nil {
		return nil, nil, ErrInvalidSpec
	}
	keyPEM, err = EncodePrivateKeyPEM(id.key)
	if err != nil {
		return nil, nil, err
	}
	return EncodeCertPEM(id.Cert.Raw), keyPEM, nil
}

// PrivateKey returns the identity's ML-DSA-65 private key.
func (id *Identity) PrivateKey() *mldsa.PrivateKey {
	if id == nil {
		return nil
	}
	return id.key
}

// SPKIPin returns the lowercase hex SHA-256 of the identity certificate's SubjectPublicKeyInfo.
func (id *Identity) SPKIPin() string {
	if id == nil {
		return ""
	}
	return SPKIPin(id.Cert)
}

// TLSCertificate returns a tls.Certificate carrying this identity for use in TLS configs.
func (id *Identity) TLSCertificate() tls.Certificate {
	if id == nil || id.Cert == nil || id.key == nil {
		return tls.Certificate{}
	}
	return tls.Certificate{
		Certificate: [][]byte{id.Cert.Raw},
		PrivateKey:  id.key,
		Leaf:        id.Cert,
	}
}
