package applysetup

import (
	"context"
	"errors"
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
	socket := filepath.Join(t.TempDir(), "private", "setup.sock")
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
	dir := t.TempDir()
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
	socket := filepath.Join(t.TempDir(), strings.Repeat("d", 100), "setup.sock")
	if _, err := StartLocal(context.Background(), socket, nil, nil); err == nil || !strings.Contains(err.Error(), "107-byte") {
		t.Fatal("overlong socket path not named", err)
	}
	if _, err := os.Stat(filepath.Dir(socket)); !os.IsNotExist(err) {
		t.Fatal("refused socket created its directory")
	}
}
