//go:build go1.27

package pinnedca

import (
	"bytes"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/Busnes-app/ky-primitives/pqtls"
)

func validateCACert(caCert *x509.Certificate) error {
	if err := requireMLDSA65Cert(caCert); err != nil {
		return err
	}
	if !caCert.IsCA {
		return fmt.Errorf("%w: certificate is not a CA", ErrInvalidSpec)
	}
	if err := caCert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("pinnedca: verify CA self-signature: %w", err)
	}
	return nil
}

func validateLocalTLSCert(cert tls.Certificate) error {
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return fmt.Errorf("%w: TLS certificate and private key are required", ErrInvalidSpec)
	}
	priv, ok := cert.PrivateKey.(*mldsa.PrivateKey)
	if !ok {
		return ErrNotMLDSA65
	}
	if err := requireMLDSA65PrivateKey(priv); err != nil {
		return err
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("pinnedca: parse TLS leaf certificate: %w", err)
		}
	}
	if err := requireMLDSA65Cert(leaf); err != nil {
		return err
	}
	pub := leaf.PublicKey.(*mldsa.PublicKey)
	if !pub.Equal(priv.Public()) {
		return ErrKeyMismatch
	}
	return nil
}

func validateAllowedPins(pins []string) ([]string, error) {
	if len(pins) == 0 {
		return nil, fmt.Errorf("%w: at least one SPKI pin is required", ErrInvalidSpec)
	}
	for _, p := range pins {
		if !ValidPin(p) {
			return nil, fmt.Errorf("%w: invalid SPKI pin", ErrInvalidSpec)
		}
	}
	return slices.Clone(pins), nil
}

func hasExplicitEKU(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	return slices.Contains(cert.ExtKeyUsage, want)
}

func verifyMLDSA65VerifiedChains(chains [][]*x509.Certificate, wantEKU x509.ExtKeyUsage) error {
	if len(chains) == 0 {
		return ErrNotMLDSA65
	}
	sawMLDSAChain := false
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		allMLDSA := true
		for _, c := range chain {
			if requireMLDSA65Cert(c) != nil {
				allMLDSA = false
				break
			}
		}
		if !allMLDSA {
			continue
		}
		sawMLDSAChain = true
		leaf := chain[0]
		if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasExplicitEKU(leaf, wantEKU) {
			continue
		}
		return nil
	}
	if sawMLDSAChain {
		return ErrWrongEKU
	}
	return ErrNotMLDSA65
}

func verifyPinnedPeer(chain []*x509.Certificate, allowedPins []string, wantEKU x509.ExtKeyUsage, serverName string, now time.Time) error {
	if len(chain) == 0 {
		return ErrPinMismatch
	}
	leaf := chain[0]
	if err := VerifyPeerPin(leaf, allowedPins...); err != nil {
		return err
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasExplicitEKU(leaf, wantEKU) {
		return ErrWrongEKU
	}
	if len(chain) == 1 {
		if !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
			return ErrKeyMismatch
		}
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
			return fmt.Errorf("pinnedca: verify peer self-signature: %w", err)
		}
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired}
		}
		if serverName != "" {
			if err := leaf.VerifyHostname(serverName); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range chain[1:] {
		if err := requireMLDSA65Cert(c); err != nil {
			return err
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	var intermediates *x509.CertPool
	if len(chain) > 2 {
		intermediates = x509.NewCertPool()
		for _, c := range chain[1 : len(chain)-1] {
			intermediates.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{wantEKU},
	})
	return err
}

// ServerTLS returns a hardened CA-verified mTLS server configuration restricted
// to TLS 1.3 and X25519MLKEM768 via pqtls.HybridOnly. Clients must present a
// valid ML-DSA-65 certificate signed by caCert with ExtKeyUsageClientAuth.
func ServerTLS(caCert *x509.Certificate, serverCert tls.Certificate) (*tls.Config, error) {
	if err := validateCACert(caCert); err != nil {
		return nil, err
	}
	if err := validateLocalTLSCert(serverCert); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pqtls.HybridOnly(&tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyMLDSA65VerifiedChains(cs.VerifiedChains, x509.ExtKeyUsageClientAuth)
		},
	}), nil
}

// ClientTLS returns a hardened CA-verified TLS client configuration restricted
// to TLS 1.3 and X25519MLKEM768 via pqtls.HybridOnly. The server must present a
// valid ML-DSA-65 certificate for serverName signed by caCert with
// ExtKeyUsageServerAuth. If clientCert is non-nil, it is validated as ML-DSA-65
// and presented for mTLS.
func ClientTLS(caCert *x509.Certificate, serverName string, clientCert *tls.Certificate) (*tls.Config, error) {
	if err := validateCACert(caCert); err != nil {
		return nil, err
	}
	if serverName == "" {
		return nil, fmt.Errorf("%w: serverName is required", ErrInvalidSpec)
	}
	if clientCert != nil {
		if err := validateLocalTLSCert(*clientCert); err != nil {
			return nil, err
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cfg := pqtls.HybridOnly(&tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyMLDSA65VerifiedChains(cs.VerifiedChains, x509.ExtKeyUsageServerAuth)
		},
	})
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return cfg, nil
}

// PinnedCAClientTLS returns a hardened TLS client configuration restricted to
// TLS 1.3 and X25519MLKEM768 via pqtls.HybridOnly for clients that know only the
// internal CA's SPKI-SHA256 pin (for example during initial pairing).
//
// The server must present its leaf certificate together with the CA certificate.
// Go's system-root verification is replaced (not skipped) by VerifyConnection,
// which matches the presented ML-DSA-65 CA certificate against caSPKIPin in
// constant time and verifies the leaf's chain, validity window, serverName SAN,
// ML-DSA-65 algorithm, and ExtKeyUsageServerAuth.
func PinnedCAClientTLS(caSPKIPin, serverName string, clientCert *tls.Certificate) (*tls.Config, error) {
	if !ValidPin(caSPKIPin) {
		return nil, fmt.Errorf("%w: invalid CA SPKI pin", ErrInvalidSpec)
	}
	if serverName == "" {
		return nil, fmt.Errorf("%w: serverName is required", ErrInvalidSpec)
	}
	if clientCert != nil {
		if err := validateLocalTLSCert(*clientCert); err != nil {
			return nil, err
		}
	}
	cfg := pqtls.HybridOnly(&tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinnedCAChain(cs.PeerCertificates, caSPKIPin, serverName, time.Now())
		},
	})
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return cfg, nil
}

func verifyPinnedCAChain(chain []*x509.Certificate, caSPKIPin, serverName string, now time.Time) error {
	if len(chain) < 2 {
		return ErrPinnedCA
	}
	var matchedCA *x509.Certificate
	for _, c := range chain[1:] {
		if c.IsCA && VerifyPeerPin(c, caSPKIPin) == nil {
			matchedCA = c
		}
	}
	if matchedCA == nil {
		return ErrPinnedCA
	}
	if err := matchedCA.CheckSignatureFrom(matchedCA); err != nil {
		return fmt.Errorf("pinnedca: verify pinned CA self-signature: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(matchedCA)
	chains, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:     serverName,
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}
	return verifyMLDSA65VerifiedChains(chains, x509.ExtKeyUsageServerAuth)
}

// PinnedServerTLS returns a hardened SPKI-pinned mTLS server configuration
// restricted to TLS 1.3 and X25519MLKEM768 via pqtls.HybridOnly. Every client
// must present a valid, unexpired ML-DSA-65 certificate with ExtKeyUsageClientAuth
// whose SPKI-SHA256 matches one of allowedClientPins in constant time.
func PinnedServerTLS(serverCert tls.Certificate, allowedClientPins []string) (*tls.Config, error) {
	if err := validateLocalTLSCert(serverCert); err != nil {
		return nil, err
	}
	pins, err := validateAllowedPins(allowedClientPins)
	if err != nil {
		return nil, err
	}
	return pqtls.HybridOnly(&tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinnedPeer(cs.PeerCertificates, pins, x509.ExtKeyUsageClientAuth, "", time.Now())
		},
	}), nil
}

// PinnedClientTLS returns a hardened SPKI-pinned TLS client configuration
// restricted to TLS 1.3 and X25519MLKEM768 via pqtls.HybridOnly. The server
// must present a valid, unexpired ML-DSA-65 certificate with ExtKeyUsageServerAuth
// whose SPKI-SHA256 matches one of allowedServerPins in constant time. If
// serverName is non-empty, it is also verified against the server certificate's
// SANs. If clientCert is non-nil, it is validated as ML-DSA-65 and presented for mTLS.
func PinnedClientTLS(allowedServerPins []string, serverName string, clientCert *tls.Certificate) (*tls.Config, error) {
	pins, err := validateAllowedPins(allowedServerPins)
	if err != nil {
		return nil, err
	}
	if clientCert != nil {
		if err := validateLocalTLSCert(*clientCert); err != nil {
			return nil, err
		}
	}
	cfg := pqtls.HybridOnly(&tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinnedPeer(cs.PeerCertificates, pins, x509.ExtKeyUsageServerAuth, serverName, time.Now())
		},
	})
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return cfg, nil
}
