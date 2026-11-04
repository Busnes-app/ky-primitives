package offsite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const testSFTPUser, testSFTPPass = "ky", "correct-horse"

var (
	passwordsMu sync.Mutex
	passwords   []string
)

func startSFTPServer(t *testing.T) (addr, fingerprint string) {
	t.Helper()
	return startSFTPServerWith(t, nil)
}

// startSFTPServerWith serves handlers through the SFTP request server, or the plain
// filesystem server when handlers is nil.
func startSFTPServerWith(t *testing.T, handlers *sftp.Handlers) (addr, fingerprint string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		passwordsMu.Lock()
		passwords = append(passwords, string(password))
		passwordsMu.Unlock()
		if string(password) == testSFTPPass {
			return nil, nil
		}
		return nil, errors.New("bad credentials")
	}}
	cfg.AddHostKey(signer)
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
			go serveSFTP(conn, cfg, handlers)
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func serveSFTP(conn net.Conn, cfg *ssh.ServerConfig, handlers *sftp.Handlers) {
	sconn, channels, requests, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		ch, channelRequests, err := channel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for request := range channelRequests {
				ok := request.Type == "subsystem" && len(request.Payload) >= 4 && string(request.Payload[4:]) == "sftp"
				_ = request.Reply(ok, nil)
				if ok {
					if handlers != nil {
						_ = sftp.NewRequestServer(ch, *handlers).Serve()
					} else if server, err := sftp.NewServer(ch); err == nil {
						_ = server.Serve()
					}
					return
				}
			}
		}()
	}
}

func TestSFTPTargetContractAndHostPin(t *testing.T) {
	addr, fingerprint := startSFTPServer(t)
	dir := filepath.Join(t.TempDir(), "vault")
	target := &sftpTarget{addr: addr, user: testSFTPUser, secret: testSFTPPass, dir: dir, hostKey: fingerprint, timeout: 3 * time.Second}
	ctx := context.Background()
	if err := target.Put(ctx, "nested/object", strings.NewReader("first"), 5); err != nil {
		t.Fatal(err)
	}
	if err := target.Put(ctx, "nested/object", strings.NewReader("second"), 6); err != nil {
		t.Fatal(err)
	}
	r, err := target.Get(ctx, "nested/object")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(raw) != "second" {
		t.Fatalf("Get = %q, %v", raw, err)
	}
	if _, err := target.Get(ctx, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing error = %v", err)
	}
	if err := target.Test(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, pingName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("probe remained: %v", err)
	}

	unpinned := *target
	unpinned.hostKey = ""
	err = unpinned.Test(ctx)
	var unknown *UnknownHostKeyError
	if !errors.As(err, &unknown) || unknown.Fingerprint != fingerprint {
		t.Fatalf("unknown host error = %#v, %v", unknown, err)
	}
	mismatch := *target
	mismatch.hostKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := mismatch.Test(ctx); err == nil {
		t.Fatal("mismatched host key accepted")
	}
}

func TestSFTPStagingDoesNotMutatePartObject(t *testing.T) {
	addr, fingerprint := startSFTPServer(t)
	target := &sftpTarget{addr: addr, user: testSFTPUser, secret: testSFTPPass, dir: filepath.Join(t.TempDir(), "vault"), hostKey: fingerprint, timeout: 3 * time.Second}
	ctx := context.Background()
	if err := target.Put(ctx, "victim.part", strings.NewReader("important"), 9); err != nil {
		t.Fatal(err)
	}
	if err := target.Put(ctx, "victim", strings.NewReader("replacement"), 11); err != nil {
		t.Fatal(err)
	}
	r, err := target.Get(ctx, "victim.part")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(raw) != "important" {
		t.Fatalf("victim.part = %q, %v", raw, err)
	}
}

func TestSFTPNeverOffersPEMAsPassword(t *testing.T) {
	addr, fingerprint := startSFTPServer(t)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	full := string(pem.EncodeToMemory(block))
	// The second is a paste that lost its END line, which pem.Decode cannot read.
	for _, secret := range []string{"\n" + full, full[:strings.Index(full, "-----END")]} {
		passwordsMu.Lock()
		passwords = nil
		passwordsMu.Unlock()
		target := &sftpTarget{addr: addr, user: testSFTPUser, secret: secret, dir: t.TempDir(), hostKey: fingerprint, timeout: time.Second}
		_ = target.Test(context.Background())
		passwordsMu.Lock()
		for _, password := range passwords {
			if strings.Contains(password, "PRIVATE KEY") {
				t.Error("private key was offered as a password")
			}
		}
		passwordsMu.Unlock()
	}
}

func stalledAddress(t *testing.T) string {
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
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return listener.Addr().String()
}

func TestSFTPStallHonorsBudget(t *testing.T) {
	target := &sftpTarget{addr: stalledAddress(t), user: "ky", secret: "pw", dir: "/x", hostKey: "SHA256:x", timeout: 200 * time.Millisecond}
	start := time.Now()
	if err := target.Put(context.Background(), "object", strings.NewReader("x"), 1); err == nil {
		t.Fatal("stalled server returned no error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("operation took %s", elapsed)
	}
}

// noPosixRename is an SFTP filesystem that allows create and write but refuses the
// posix-rename extension, as some appliance servers do.
type noPosixRename struct{ sftp.FileCmder }

func (noPosixRename) PosixRename(*sftp.Request) error { return sftp.ErrSSHFxOpUnsupported }

// Test used to write its probe directly, so it passed on a server where every Put then
// failed at the rename that publishes the object.
func TestSFTPTestFailsWhenPutCannotPublish(t *testing.T) {
	h := sftp.InMemHandler()
	h.FileCmd = noPosixRename{h.FileCmd}
	addr, fingerprint := startSFTPServerWith(t, &h)
	target := &sftpTarget{addr: addr, user: testSFTPUser, secret: testSFTPPass, dir: "/vault", hostKey: fingerprint, timeout: 3 * time.Second}
	ctx := context.Background()
	if err := target.Put(ctx, "object", strings.NewReader("x"), 1); err == nil {
		t.Fatal("Put published without posix-rename")
	}
	if err := target.Test(ctx); err == nil {
		t.Fatal("Test passed on a server that refuses every Put")
	}
}

// A caller's large buffer must not hide progress from the idle budget for longer than one
// bounded Read, on the download side and on the upload source (SMB writes what one source
// Read returned, up to its maximum write size, before reading again).
func TestTransferReadsAreBounded(t *testing.T) {
	src := strings.Repeat("x", 3<<20)
	r := &sessionReadCloser{ReadCloser: io.NopCloser(strings.NewReader(src)), ctx: context.Background(), cleanup: func() {}, cancel: func() {}, touch: func() {}}
	n, err := r.Read(make([]byte, 4<<20))
	if err != nil || n > maxTransferRead {
		t.Fatalf("download Read returned %d bytes (%v), want at most %d", n, err, maxTransferRead)
	}
	up := &contextReader{ctx: context.Background(), r: strings.NewReader(src)}
	n, err = up.Read(make([]byte, 4<<20))
	if err != nil || n > maxTransferRead {
		t.Fatalf("upload source Read returned %d bytes (%v), want at most %d", n, err, maxTransferRead)
	}
}

// stalledWrites is an SFTP filesystem whose file writes never complete.
type stalledWrites struct {
	sftp.FileWriter
	release chan struct{}
}

func (s stalledWrites) Filewrite(*sftp.Request) (io.WriterAt, error) { return s, nil }

func (s stalledWrites) WriteAt(p []byte, _ int64) (int, error) {
	<-s.release
	return 0, io.ErrClosedPipe
}

// slowSource yields one small chunk per tick: steady progress, slower in total than the
// idle budget.
type slowSource struct{ left int }

func (s *slowSource) Read(p []byte) (int, error) {
	if s.left == 0 {
		return 0, io.EOF
	}
	time.Sleep(100 * time.Millisecond)
	s.left--
	return copy(p, "chunk"), nil
}

// With no Timeout the default bounds time without progress, not the whole transfer, and a
// write that stops moving ends as context.DeadlineExceeded, not a bare closed connection.
func TestSFTPDefaultBudgetAllowsSlowPutsAndStopsStalledWrites(t *testing.T) {
	saved := defaultTransferBudget
	defaultTransferBudget = 400 * time.Millisecond
	defer func() { defaultTransferBudget = saved }()
	ctx := context.Background()

	mem := sftp.InMemHandler()
	addr, fingerprint := startSFTPServerWith(t, &mem)
	target := &sftpTarget{addr: addr, user: testSFTPUser, secret: testSFTPPass, dir: "/vault", hostKey: fingerprint}
	if err := target.Put(ctx, "slow", &slowSource{left: 10}, 50); err != nil {
		t.Fatalf("slow but steady Put: %v", err)
	}

	h := sftp.InMemHandler()
	release := make(chan struct{})
	defer close(release)
	h.FilePut = stalledWrites{FileWriter: h.FilePut, release: release}
	addr, fingerprint = startSFTPServerWith(t, &h)
	target = &sftpTarget{addr: addr, user: testSFTPUser, secret: testSFTPPass, dir: "/vault", hostKey: fingerprint}
	start := time.Now()
	err := target.Put(ctx, "stalled", strings.NewReader("x"), 1)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("stalled Put: err %v after %s, want context.DeadlineExceeded", err, time.Since(start))
	}
}
