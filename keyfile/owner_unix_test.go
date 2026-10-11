//go:build unix

package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnershipIsVerifiedOnEveryUnix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the probe")
	}
	root, err := os.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	if ownedByCurrentUser(root) {
		t.Fatal("root-owned directory reported as owned by the current user")
	}
	// /etc/hosts is a root-owned regular file on Linux and macOS.
	hosts, err := filepath.EvalSymlinks("/etc/hosts")
	if err != nil {
		t.Skip("no /etc/hosts")
	}
	if _, err := ReadPrivate(hosts, 1<<20); !errors.Is(err, ErrUnsafe) && !errors.Is(err, ErrPermissive) {
		t.Fatal("foreign-owned file accepted", err)
	}
}
