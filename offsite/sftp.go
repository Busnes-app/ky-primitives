package offsite

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// UnknownHostKeyError reports the fingerprint an operator must verify and pin.
type UnknownHostKeyError struct{ Fingerprint string }

func (e *UnknownHostKeyError) Error() string {
	return "offsite: host key not pinned; server presented " + e.Fingerprint
}

type sftpTarget struct {
	addr, user, secret, dir, hostKey string
	timeout                          time.Duration
}

func (t *sftpTarget) auth() (ssh.AuthMethod, error) {
	// Anything that looks like key material is a key, even when pem.Decode cannot read it
	// (a missing END line): sending it as a password would hand the key to the server.
	if block, _ := pem.Decode([]byte(t.secret)); block != nil || strings.Contains(t.secret, "-----BEGIN ") {
		signer, err := ssh.ParsePrivateKey([]byte(t.secret))
		if err != nil {
			return nil, fmt.Errorf("offsite: private key: %w", err)
		}
		if err := strongSFTPKey(signer.PublicKey()); err != nil {
			return nil, err
		}
		if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
			// Without an explicit signer policy an older server can request the
			// ssh-rsa SHA-1 fallback even when transport negotiation is strong.
			algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
			if !ok {
				return nil, fmt.Errorf("offsite: RSA signer does not support SHA-2")
			}
			signer, err = ssh.NewSignerWithAlgorithms(algorithmSigner, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
			if err != nil {
				return nil, fmt.Errorf("offsite: RSA signing algorithms: %w", err)
			}
		}
		return ssh.PublicKeys(signer), nil
	}
	return ssh.Password(t.secret), nil
}

func (t *sftpTarget) dial(ctx context.Context) (*sftp.Client, func(), error) {
	auth, err := t.auth()
	if err != nil {
		return nil, nil, err
	}
	algorithms := ssh.SupportedAlgorithms()
	cfg := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
		HostKeyAlgorithms: algorithms.HostKeys,
		User:              t.user,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if err := strongSFTPKey(key); err != nil {
				return err
			}
			fingerprint := ssh.FingerprintSHA256(key)
			if t.hostKey == "" {
				return &UnknownHostKeyError{Fingerprint: fingerprint}
			}
			if fingerprint != t.hostKey {
				return fmt.Errorf("offsite: host key mismatch: pinned %s, server presented %s", t.hostKey, fingerprint)
			}
			return nil
		},
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	sconn, chans, reqs, err := ssh.NewClientConn(conn, t.addr, cfg)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	sshClient := ssh.NewClient(sconn, chans, reqs)
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		cleanup()
		return nil, nil, err
	}
	return client, func() { _ = client.Close(); _ = sshClient.Close(); cleanup() }, nil
}

// strongSFTPKey validates parsed network or configured keys before they can
// authenticate a peer. A matching pin never exempts an undersized key.
func strongSFTPKey(key ssh.PublicKey) error {
	if cert, ok := key.(*ssh.Certificate); ok {
		if !slices.Contains(ssh.SupportedAlgorithms().PublicKeyAuths, cert.Signature.Format) {
			return fmt.Errorf("offsite: SSH certificate uses an unsupported signature algorithm")
		}
		if err := strongSFTPKey(cert.SignatureKey); err != nil {
			return err
		}
		key = cert.Key
	}
	public, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("offsite: unsupported SSH public key type %q", key.Type())
	}
	switch public := public.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		if public.N.BitLen() < 2048 {
			return fmt.Errorf("offsite: RSA SSH keys must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if public.Curve.Params().BitSize < 224 {
			return fmt.Errorf("offsite: EC SSH keys must be at least 224 bits")
		}
	case ed25519.PublicKey:
		// The SSH parser fixes the key size at 256 bits.
	default:
		return fmt.Errorf("offsite: unsupported SSH public key type %q", key.Type())
	}
	return nil
}

func (t *sftpTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	ctx, cancel, touch := budget(ctx, t.timeout)
	defer cancel()
	client, cleanup, err := t.dial(ctx)
	if err != nil {
		return expired(ctx, err)
	}
	defer cleanup()
	return expired(ctx, t.put(ctx, client, name, &contextReader{ctx: ctx, r: r, touch: touch}))
}

// put stages and publishes one object over an open session; Put and Test share it so a
// passing Test means the server accepts the rename every Put depends on.
func (t *sftpTarget) put(ctx context.Context, client *sftp.Client, name string, r io.Reader) error {
	if t.dir != "" {
		if err := client.MkdirAll(t.dir); err != nil {
			return err
		}
	}
	final := path.Join(t.dir, name)
	tmp, err := stagingName(final)
	if err != nil {
		return err
	}
	if err := client.MkdirAll(path.Dir(final)); err != nil {
		return err
	}
	f, err := client.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		_ = client.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = client.Remove(tmp)
		return err
	}
	if err := client.PosixRename(tmp, final); err != nil {
		_ = client.Remove(tmp)
		return fmt.Errorf("offsite: SFTP publish by posix-rename@openssh.com: %w", err)
	}
	return nil
}

func (t *sftpTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel, touch := budget(ctx, t.timeout)
	client, cleanup, err := t.dial(ctx)
	if err != nil {
		err = expired(ctx, err)
		cancel()
		return nil, err
	}
	f, err := client.Open(path.Join(t.dir, name))
	if err != nil {
		err = expired(ctx, err)
		cleanup()
		cancel()
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &sessionReadCloser{ReadCloser: f, ctx: ctx, cleanup: cleanup, cancel: cancel, touch: touch}, nil
}

func (t *sftpTarget) Test(ctx context.Context) error {
	ctx, cancel, _ := budget(ctx, t.timeout)
	defer cancel()
	client, cleanup, err := t.dial(ctx)
	if err != nil {
		return expired(ctx, err)
	}
	defer cleanup()
	if err := t.put(ctx, client, pingName, &contextReader{ctx: ctx, r: strings.NewReader("ping")}); err != nil {
		return expired(ctx, err)
	}
	return expired(ctx, client.Remove(path.Join(t.dir, pingName)))
}

type sessionReadCloser struct {
	io.ReadCloser
	ctx           context.Context
	cleanup       func()
	cancel, touch func()
	once          sync.Once
}

func (c *sessionReadCloser) Read(p []byte) (int, error) {
	if len(p) > maxTransferRead {
		p = p[:maxTransferRead]
	}
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, expired(c.ctx, err)
}

func (c *sessionReadCloser) Close() (err error) {
	c.once.Do(func() {
		err = c.ReadCloser.Close()
		c.cleanup()
		c.cancel()
	})
	return err
}
