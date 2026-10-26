package offsite

import (
	"context"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startSFTPPolicyPeer(t *testing.T, cfg *ssh.ServerConfig) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSFTP(conn, cfg)
		}
	}()
	return listener.Addr().String()
}

func policyRSAKey(t *testing.T, bits int) (*rsa.PrivateKey, ssh.Signer) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func TestSFTPRejectsLegacyAlgorithmOnlyPeers(t *testing.T) {
	_, host := policyRSAKey(t, 2048)
	for _, which := range []string{"key exchange", "host signature", "MAC"} {
		t.Run(which, func(t *testing.T) {
			cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
			cfg.AddHostKey(host)
			switch which {
			case "key exchange":
				cfg.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1}
			case "host signature":
				legacy, err := ssh.NewSignerWithAlgorithms(host.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
				if err != nil {
					t.Fatal(err)
				}
				cfg.AddHostKey(legacy)
			case "MAC":
				cfg.Ciphers = []string{ssh.CipherAES128CTR}
				cfg.MACs = []string{ssh.InsecureHMACSHA196}
			}
			target := &sftpTarget{addr: startSFTPPolicyPeer(t, cfg), user: "ky", secret: "password", hostKey: ssh.FingerprintSHA256(host.PublicKey()), dir: t.TempDir(), timeout: 3 * time.Second}
			if err := target.Test(context.Background()); err == nil {
				t.Fatal("legacy-only SSH peer was accepted")
			}
		})
	}
}

func TestSFTPRejectsUndersizedHostKeys(t *testing.T) {
	for _, bits := range []int{1024, 2047} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			_, host := policyRSAKey(t, bits)
			var authentications atomic.Int32
			cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
				authentications.Add(1)
				return nil, nil
			}}
			cfg.AddHostKey(host)
			target := &sftpTarget{addr: startSFTPPolicyPeer(t, cfg), user: "ky", secret: "password", hostKey: ssh.FingerprintSHA256(host.PublicKey()), dir: t.TempDir(), timeout: 3 * time.Second}
			if err := target.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "2048") {
				t.Fatalf("weak pinned host result = %v; want minimum-key error", err)
			}
			if authentications.Load() != 0 {
				t.Fatal("credentials were offered to an undersized host key")
			}
		})
	}
}

func TestSFTPCertificateAuthorityPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bits      int
		algorithm string
		accepted  bool
	}{
		{"strong CA", 2048, ssh.KeyAlgoRSASHA512, true},
		{"undersized CA", 1024, ssh.KeyAlgoRSASHA512, false},
		{"SHA-1 CA signature", 2048, ssh.KeyAlgoRSA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			host, err := ssh.NewSignerFromKey(hostPrivate)
			if err != nil {
				t.Fatal(err)
			}
			_, ca := policyRSAKey(t, tc.bits)
			authority, err := ssh.NewSignerWithAlgorithms(ca.(ssh.AlgorithmSigner), []string{tc.algorithm})
			if err != nil {
				t.Fatal(err)
			}
			cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity}
			if err := cert.SignCert(rand.Reader, authority); err != nil {
				// In this runtime mode x/crypto refuses the legacy signature even
				// while creating the adversarial fixture. The default-mode suite
				// still proves that our pinned-host handshake refuses that cert.
				if fips140.Enabled() && tc.algorithm == ssh.KeyAlgoRSA &&
					strings.Contains(err.Error(), "not allowed in FIPS 140 mode") {
					t.Logf("runtime refused the SHA-1 certificate fixture: %v", err)
					return
				}
				t.Fatal(err)
			}
			certSigner, err := ssh.NewCertSigner(cert, host)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
			cfg.AddHostKey(certSigner)
			target := &sftpTarget{addr: startSFTPPolicyPeer(t, cfg), user: "ky", secret: "password", hostKey: ssh.FingerprintSHA256(certSigner.PublicKey()), dir: t.TempDir(), timeout: 3 * time.Second}
			if err := target.Test(context.Background()); (err == nil) != tc.accepted {
				t.Fatalf("certificate connection = %v; accepted should be %v", err, tc.accepted)
			}
		})
	}
}

func TestSFTPRejectsUndersizedClientKeys(t *testing.T) {
	for _, bits := range []int{1024, 2047} {
		key, _ := policyRSAKey(t, bits)
		block, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			t.Fatal(err)
		}
		target := &sftpTarget{secret: string(pem.EncodeToMemory(block))}
		if _, err := target.auth(); err == nil || !strings.Contains(err.Error(), "2048") {
			t.Errorf("%d-bit client result = %v; want minimum-key error", bits, err)
		}
	}
}

func TestSFTPStrongPublicKeyAuthentication(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := policyRSAKey(t, 2048)
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}, PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(host)
	target := &sftpTarget{addr: startSFTPPolicyPeer(t, cfg), user: "ky", secret: string(pem.EncodeToMemory(block)), hostKey: ssh.FingerprintSHA256(host.PublicKey()), dir: t.TempDir(), timeout: 3 * time.Second}
	if err := target.Test(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A strong RSA key must not fall back to SHA-1 user authentication, even
	// when transport algorithms and the pinned server key are otherwise strong.
	legacy := *cfg
	legacy.PublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSA}
	target.addr = startSFTPPolicyPeer(t, &legacy)
	if err := target.Test(context.Background()); err == nil {
		t.Fatal("SHA-1-only public-key authentication was accepted")
	}
}
