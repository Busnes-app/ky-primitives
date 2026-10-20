package applysetup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalSetupAndReadOnlyInspection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(shortDir(t), "private", "setup.sock")
	var writes atomic.Int32
	restarted := make(chan struct{})
	c := Common{Service: "example", SetupID: "271333e2-c221-4601-b249-563b3d828530"}
	closeServer, err := StartLocal(ctx, socket, func(_ context.Context, raw []byte, check bool) (Report, error) {
		if string(raw) != "{}" {
			return Report{}, errors.New("secret-error-must-not-leak")
		}
		if !check {
			writes.Add(1)
		}
		return NewReport(c), nil
	}, func() { close(restarted) })
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions", err)
	}
	if _, err := CallLocal(ctx, socket, []byte("{}"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := CallLocal(ctx, socket, []byte("{}"), true); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal("inspection mutated")
	}
	if _, err := CallLocal(ctx, socket, []byte("secret"), false); err == nil || err.Error() == "secret-error-must-not-leak" {
		t.Fatal("unredacted refusal", err)
	}
	if _, err := StartLocal(ctx, socket, func(context.Context, []byte, bool) (Report, error) { return Report{}, nil }, nil); err == nil {
		t.Fatal("live socket taken over")
	}
	if err := RequestRestart(ctx, socket); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restarted:
	case <-time.After(time.Second):
		t.Fatal("activation callback not invoked")
	}
}
func TestLocalSetupRefusesOccupiedAndPermissivePaths(t *testing.T) {
	dir := shortDir(t)
	socket := filepath.Join(dir, "occupied")
	if err := os.WriteFile(socket, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	callback := func(context.Context, []byte, bool) (Report, error) { return Report{}, nil }
	if _, err := StartLocal(context.Background(), socket, callback, nil); err == nil {
		t.Fatal("ordinary file replaced")
	}
	if b, _ := os.ReadFile(socket); string(b) != "preserve" {
		t.Fatal("existing file damaged")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := StartLocal(context.Background(), filepath.Join(dir, "socket"), callback, nil); err == nil {
		t.Fatal("shared setup directory accepted")
	}
}

func TestLocalSetupNamesTheSocketPathLimit(t *testing.T) {
	socket := filepath.Join(shortDir(t), strings.Repeat("d", maxSocketPath), "setup.sock")
	if _, err := StartLocal(context.Background(), socket, nil, nil); err == nil || !strings.Contains(err.Error(), "byte Unix limit") {
		t.Fatal("overlong socket path not named", err)
	}
	if _, err := os.Stat(filepath.Dir(socket)); !os.IsNotExist(err) {
		t.Fatal("refused socket created its directory")
	}
}

// shortDir keeps socket paths under macOS's 103-byte limit; its t.TempDir is too long.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kyq")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir) // macOS /tmp is a symlink
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestLocalSetupRefusesASharedAncestor(t *testing.T) {
	shared := filepath.Join(shortDir(t), "shared")
	private := filepath.Join(shared, "private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil { // writable by others, not sticky
		t.Fatal(err)
	}
	callback := func(context.Context, []byte, bool) (Report, error) { return Report{}, nil }
	if _, err := StartLocal(context.Background(), filepath.Join(private, "setup.sock"), callback, nil); err == nil {
		t.Fatal("socket bound beneath an ancestor other users can modify")
	}
	if _, err := os.Lstat(filepath.Join(private, "setup.sock")); !os.IsNotExist(err) {
		t.Fatal("refused socket was created")
	}
}

func TestLocalSetupRefusesNoncanonicalSocketPaths(t *testing.T) {
	dir := shortDir(t)
	callback := func(context.Context, []byte, bool) (Report, error) { return Report{}, nil }
	for _, socket := range []string{
		filepath.Join(dir, "a") + "/../b/setup.sock",
		dir + "//b/setup.sock",
		dir + "/./b/setup.sock",
	} {
		if _, err := StartLocal(context.Background(), socket, callback, nil); err == nil {
			t.Fatal("noncanonical socket path accepted", socket)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("refused socket path created directories")
	}
}

func TestLocalSafeRefusal(t *testing.T) {
	socket := filepath.Join(shortDir(t), "setup.sock")
	for _, reason := range []string{"SSO issuer differs from installer configuration", "unsafe\nterminal", strings.Repeat("x", 513)} {
		closeServer, err := StartLocal(context.Background(), socket, func(context.Context, []byte, bool) (Report, error) {
			return Report{}, fmt.Errorf("internal context: %w", &Refusal{Reason: reason})
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = CallLocal(context.Background(), socket, nil, true)
		closeServer()
		if err == nil {
			t.Fatal("refusal succeeded")
		}
		if validReason(reason) && !strings.Contains(err.Error(), reason) {
			t.Fatal(err)
		}
		if !validReason(reason) && strings.Contains(err.Error(), reason) {
			t.Fatal("unsafe reason leaked")
		}
	}
}
