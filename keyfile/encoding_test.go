package keyfile_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

func TestEachEncodingRoundTrips(t *testing.T) {
	for name, enc := range map[string]keyfile.Encoding{
		"hex":    keyfile.Hex,
		"raw":    keyfile.Raw,
		"base64": keyfile.Base64,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "k")
			made, err := keyfile.LoadOrCreateEncoded(path, 32, enc)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if len(made) != 32 {
				t.Fatalf("len = %d, want 32", len(made))
			}
			again, err := keyfile.LoadOrCreateEncoded(path, 32, enc)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if !bytes.Equal(made, again) {
				t.Error("reload returned a different key")
			}
		})
	}
}

func TestRawEncodingWritesTheBytesThemselves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_key")
	key, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Raw)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(onDisk, key) {
		t.Error("raw encoding did not write the key bytes verbatim")
	}
}

func TestEncodingsDoNotReadEachOther(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if _, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Hex); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 64 hex characters are not 32 raw bytes, and must be refused rather than
	// truncated into a key nobody chose.
	if _, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Raw); err == nil {
		t.Error("Raw read a hex file")
	}
	// The file on disk must survive the refusal untouched.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(onDisk) != 65 { // 64 hex chars + trailing newline
		t.Errorf("hex key file was modified: %d bytes", len(onDisk))
	}
}

func TestRawWrongSizeIsRefusedAndLeftUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node_key")
	content := bytes.Repeat([]byte{0xAB}, 16) // half the requested size
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Raw); !errors.Is(err, keyfile.ErrUnreadable) {
		t.Fatalf("got %v, want ErrUnreadable", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Error("a wrong-sized raw key file was truncated or padded")
	}
}

func TestLoadNeverCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if _, err := keyfile.Load(path, 32); err == nil {
		t.Fatal("Load created or accepted a missing file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("Load wrote a file it was only asked to read")
	}
}

func TestLoadReadsWhatLoadOrCreateWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	made, err := keyfile.LoadOrCreate(path, 32)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	read, err := keyfile.Load(path, 32)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(made, read) {
		t.Error("Load returned a different key")
	}
}

func TestFromEnvValidatesLikeAFile(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)

	t.Run("hex", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", hex.EncodeToString(key))
		got, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32)
		if err != nil || !ok {
			t.Fatalf("FromEnv: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(got, key) {
			t.Error("wrong key")
		}
	})

	t.Run("base64", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", base64.StdEncoding.EncodeToString(key))
		got, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32)
		if err != nil || !ok {
			t.Fatalf("FromEnv: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(got, key) {
			t.Error("wrong key")
		}
	})

	t.Run("absent", func(t *testing.T) {
		os.Unsetenv("KY_TEST_KEY")
		if _, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32); ok || err != nil {
			t.Errorf("absent gave ok=%v err=%v, want false, nil", ok, err)
		}
	})

	t.Run("blank is treated as unset", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", "   \n")
		if _, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32); ok || err != nil {
			t.Errorf("blank gave ok=%v err=%v, want false, nil", ok, err)
		}
	})

	t.Run("wrong length is an error, not a miss", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", hex.EncodeToString(key[:16]))
		if _, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32); err == nil {
			t.Errorf("a 16-byte value gave ok=%v err=nil; a set-but-wrong key must fail loudly", ok)
		}
	})

	t.Run("garbage is an error", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", "not a key")
		if _, _, err := keyfile.FromEnv("KY_TEST_KEY", 32); err == nil {
			t.Error("garbage was accepted")
		}
	})
}

// The hex file format is 64 lowercase hex characters and exactly one trailing newline.
// Pinned here because it changed once already (the pre-encoding code wrote no newline)
// without anyone saying so; this stops it drifting again unnoticed.
func TestHexFileFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	key, err := keyfile.LoadOrCreate(path, 32)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(key) + "\n"
	if string(onDisk) != want {
		t.Fatalf("on-disk hex file = %q, want %q", onDisk, want)
	}
	if len(onDisk) != 65 {
		t.Fatalf("on-disk hex file is %d bytes, want 65 (64 hex chars + newline)", len(onDisk))
	}
	if onDisk[64] != '\n' {
		t.Fatalf("on-disk hex file does not end with a newline: %q", onDisk[64])
	}

	again, err := keyfile.Load(path, 32)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(again, key) {
		t.Error("round trip through the pinned format returned a different key")
	}
}

// An out-of-range Encoding must fail loudly on first boot rather than writing a key under
// an encoding encode() and decode() disagree about — that disagreement used to make the
// package permanently refuse the very file it had just written, orphaning whatever the
// caller sealed under the returned key.
func TestUnknownEncodingIsRejectedNotBricked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	bad := keyfile.Encoding(99)

	if _, err := keyfile.LoadOrCreateEncoded(path, 32, bad); err == nil {
		t.Fatal("an unknown encoding was accepted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an unknown encoding still wrote a key file")
	}

	if _, err := keyfile.LoadEncoded(path, 32, bad); err == nil {
		t.Fatal("LoadEncoded accepted an unknown encoding")
	}
}
