package capsule_test

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// A capsule this package wrote, committed, and opened on every run. If it stops opening, a
// backup already on disk has stopped opening.
//
// It replaces the kycap/1 and tar fixtures, which were real output from kysignon-server
// and kyrecovery-server. Those containers are gone: both authenticated their ciphertext
// and left the manifest forgeable, and neither server needs its old capsules read. What
// the fixture is for did not change — a golden capsule whose key is withheld cannot prove
// anything, which is why the key is committed beside it.
func TestOpensEveryPersistedCapsule(t *testing.T) {
	paths := fixturePaths(t)

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, with := loadFixture(t, p)

			_, files, err := capsule.Open(raw, with, filepath.Join(t.TempDir(), "restore"))
			if err != nil {
				t.Fatalf("a capsule written by an earlier version of this package failed to open: %v", err)
			}
			if len(files) == 0 {
				t.Fatal("opened but produced no files")
			}
			for _, f := range files {
				t.Logf("%s: %s (%d bytes, mode %o)", filepath.Base(p), f.Path, len(f.Content), f.Mode)
			}
		})
	}
}

// A wrong key must fail loudly. AES-GCM authenticates, so this should never reach the
// payload hash — but the hash is the backstop if it ever does.
func TestOpenRejectsWrongKey(t *testing.T) {
	for _, p := range fixturePaths(t) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, _ := loadFixture(t, p)
			wrong := testRecoveryKey(t)

			if _, _, err := capsule.Open(raw, wrong, ""); err == nil {
				t.Fatal("a capsule opened with the wrong key")
			}
		})
	}
}

// The README tells a caller to errors.Is a failed Open against ErrCorruptCapsule to tell a
// malformed container from a bad key. A wrong key fails at AES-GCM's tag check, which
// wraps its own error, not ErrCorruptCapsule — pin that half of the distinction here, since
// it is exactly the kind of thing a refactor reverses silently.
func TestOpenRejectsWrongKeyWithoutErrCorruptCapsule(t *testing.T) {
	for _, p := range fixturePaths(t) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, _ := loadFixture(t, p)
			wrong := testRecoveryKey(t)

			_, _, err := capsule.Open(raw, wrong, "")
			if err == nil {
				t.Fatal("a capsule opened with the wrong key")
			}
			if errors.Is(err, capsule.ErrCorruptCapsule) {
				t.Fatalf("a wrong key was reported as ErrCorruptCapsule: %v", err)
			}
		})
	}
}

// The other half: a malformed container — here, a manifest field that is not the object
// Open expects — does wrap ErrCorruptCapsule. It never reaches AES-GCM at all.
func TestOpenReportsAnUnreadableManifestAsErrCorruptCapsule(t *testing.T) {
	priv := testRecoveryKey(t)
	raw := []byte(`{"format":"kycap/3","manifest":"not an object","ciphertext":"AAAA"}`)
	if _, _, err := capsule.Open(raw, priv, ""); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("got %v, want ErrCorruptCapsule for an unreadable manifest", err)
	}
}

// Corrupting the container must not produce plaintext.
func TestOpenRejectsTamperedContainer(t *testing.T) {
	for _, p := range fixturePaths(t) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, with := loadFixture(t, p)
			raw[len(raw)/2] ^= 0xFF

			if _, _, err := capsule.Open(raw, with, ""); err == nil {
				t.Fatal("a tampered capsule opened cleanly")
			}
		})
	}
}

// The containers this package used to read are now refused rather than half-trusted. A
// kycap/1 capsule's manifest was forgeable by anyone who could reach the file, so opening
// one and handing back its files told the caller nothing about whether the manifest
// describing them was real.
func TestOpenRejectsRetiredContainers(t *testing.T) {
	priv := testRecoveryKey(t)
	for name, raw := range map[string][]byte{
		"kycap/1": []byte(`{"format":"kycap/1","manifest":{"payload_hash":"00"},"ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}`),
		"tar":     append([]byte("manifest.json\x00"), make([]byte, 1024)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := capsule.Open(raw, priv, ""); err == nil {
				t.Fatalf("a retired %s container opened", name)
			}
		})
	}
}

func TestOpenRejectsUnknownContainer(t *testing.T) {
	priv := testRecoveryKey(t)
	for name, raw := range map[string][]byte{
		"empty":      {},
		"whitespace": []byte("   \n\t "),
		"plain text": []byte("this is not a capsule"),
		"wrong json": []byte(`{"format":"kycap/99","manifest":{},"ciphertext":"AAAA"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := capsule.Open(raw, priv, ""); err == nil {
				t.Fatalf("%q opened as a capsule", name)
			}
		})
	}
}

func fixturePaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../testdata/capsules/*.kycap")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no capsule fixture on disk, so nothing here proves a capsule still opens")
	}
	return paths
}

func loadFixture(t *testing.T, path string) (raw []byte, with recoverykey.PrivateKey) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seedHex, err := os.ReadFile(strings.TrimSuffix(path, ".kycap") + ".seed")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil {
		t.Fatalf("fixture seed is not hex: %v", err)
	}
	with, err = recoverykey.FromSeed(seed)
	if err != nil {
		t.Fatalf("fixture seed does not rebuild a key: %v", err)
	}
	return raw, with
}

// The kycap/2 capsule this package used to write is refused at the format check. It is
// kept so that refusal is measured against a real container, not a hand-typed one.
func TestRetiredKycap2FixtureIsRefused(t *testing.T) {
	raw, err := os.ReadFile("../testdata/capsules/retired/kycap2.kycap")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := capsule.Open(raw, testRecoveryKey(t), ""); !errors.Is(err, capsule.ErrUnknownContainer) {
		t.Fatalf("got %v, want ErrUnknownContainer", err)
	}
}
