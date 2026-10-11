package keyfile

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadPrivateRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadPrivate(path, 64); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsafe) {
			t.Fatal("FIFO accepted as a private file", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
