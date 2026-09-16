package recoveryclient

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func TestStoreRecoveryKeyIsWriteOnce(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	if err := StoreRecoveryKey(dir, s, k); err != nil {
		t.Fatal(err)
	}
	_, other := testKey(t)
	err := StoreRecoveryKey(dir, s, other)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second key: %v", err)
	}
	if got, _ := LoadRecoveryKey(dir, s); got.Public.ID() != k.Public.ID() {
		t.Fatal("pin moved")
	}
	// Removing the file does not unpin: the settings row decides.
	if err := os.Remove(RecoveryKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := StoreRecoveryKey(dir, s, other); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second key with no file: %v", err)
	}
}

func TestStoreRecoveryKeyRecreatesMissingFile(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	if err := StoreRecoveryKey(dir, s, k); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(RecoveryKeyPath(dir))
	if _, err := LoadRecoveryKey(dir, s); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("missing file: %v", err)
	}
	if err := StoreRecoveryKey(dir, s, k); err != nil {
		t.Fatalf("same key again: %v", err)
	}
	if _, err := os.Stat(RecoveryKeyPath(dir)); err != nil {
		t.Fatal("file not recreated")
	}
}

func TestStoreRecoveryKeyRefusesBadTopology(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	for _, tc := range [][2]int{{1, 3}, {3, 2}, {0, 0}, {2, 256}} {
		k.Threshold, k.TotalShares = tc[0], tc[1]
		if err := StoreRecoveryKey(dir, s, k); err == nil {
			t.Errorf("%d-of-%d accepted", tc[0], tc[1])
		}
	}
	if len(s) != 0 {
		t.Errorf("settings written: %v", s)
	}
}

func TestLoadRecoveryKeyDetectsSwappedFile(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	if err := StoreRecoveryKey(dir, s, k); err != nil {
		t.Fatal(err)
	}
	_, other := testKey(t)
	if err := os.WriteFile(RecoveryKeyPath(dir), other.Public.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryKey(dir, s); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("swapped file: %v", err)
	}
}

func TestLoadRecoveryKeyHalfPairingIsNotPaired(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	if err := StoreRecoveryKey(dir, s, k); err != nil {
		t.Fatal(err)
	}
	delete(s, "kyrecovery_threshold")
	if _, err := LoadRecoveryKey(dir, s); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("no topology: %v", err)
	}
}

func TestParsePinRequest(t *testing.T) {
	_, k := testKey(t)
	b64 := base64.StdEncoding.EncodeToString(k.Public.Bytes())
	spaced := b64[:100] + "\n  " + b64[100:]
	got, err := ParsePinRequest(spaced, 2, 3)
	if err != nil || got.Public.ID() != k.Public.ID() || got.Threshold != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := ParsePinRequest(b64, 1, 1); err == nil {
		t.Error("1-of-1 accepted")
	}
	if _, err := ParsePinRequest("AAAA", 2, 3); err == nil {
		t.Error("short key accepted")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, recoverykey.PublicKeyBytes-1))
	if _, err := ParsePinRequest(short, 2, 3); err == nil {
		t.Error("wrong-length key accepted")
	}
	if _, err := ParsePinRequest(b64+"!", 2, 3); err == nil {
		t.Error("invalid base64 accepted")
	}
}
