package recoveryclient

import (
	"encoding/base64"
	"errors"
	"io/fs"
	"maps"
	"os"
	"strconv"
	"strings"
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

func TestLoadRecoveryKeyRefusesCorruptTopologyWithoutRepair(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	if err := StoreRecoveryKey(dir, s, k); err != nil {
		t.Fatal(err)
	}
	for _, topology := range [][2]int{{0, 1}, {1, 3}, {3, 2}, {2, 256}, {-2, 3}} {
		s[settingThreshold] = strconv.Itoa(topology[0])
		s[settingTotalShares] = strconv.Itoa(topology[1])
		before := maps.Clone(s)
		if _, err := LoadRecoveryKey(dir, s); err == nil {
			t.Fatal("accepted corrupt topology", topology)
		}
		if !maps.Equal(before, s) {
			t.Fatal("read repaired retained topology")
		}
	}
}

// repinFixture pins old and returns a new key, the confirmation an operator holding the new
// cards would type, and an audit recorder.
func repinFixture(t *testing.T) (string, memSettings, RecoveryKey, RecoveryKey, RepinConfirmation, *[][2]string) {
	t.Helper()
	dir, s := t.TempDir(), memSettings{}
	_, old := testKey(t)
	if err := StoreRecoveryKey(dir, s, old); err != nil {
		t.Fatal(err)
	}
	_, next := testKey(t)
	next.Threshold, next.TotalShares = 3, 5
	return dir, s, old, next, RepinConfirmation{ReplacesKeyID: old.Public.ID(), NewKeyID: next.Public.ID()}, &[][2]string{}
}

func recorder(log *[][2]string) func(string, string) error {
	return func(from, to string) error { *log = append(*log, [2]string{from, to}); return nil }
}

func requirePinned(t *testing.T, dir string, s Settings, want RecoveryKey) {
	t.Helper()
	got, err := LoadRecoveryKey(dir, s)
	if err != nil || got.Public.ID() != want.Public.ID() || got.Threshold != want.Threshold || got.TotalShares != want.TotalShares {
		t.Fatalf("pinned %+v, %v; want %s %d-of-%d", got, err, want.Public.ID(), want.Threshold, want.TotalShares)
	}
}

func TestPairingADifferentKeyIsRecoveryKeyPinned(t *testing.T) {
	dir, s, old, next, _, _ := repinFixture(t)
	err := StoreRecoveryKey(dir, s, next)
	var pe *PinnedError
	if !errors.As(err, &pe) || pe.Code() != "recovery_key_pinned" || pe.PinnedKeyID != old.Public.ID() || pe.OfferedKeyID != next.Public.ID() {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Fatal("PinnedError no longer satisfies fs.ErrExist")
	}
	requirePinned(t, dir, s, old)
}

func TestRepinRefusedWithoutConfirmation(t *testing.T) {
	dir, s, old, next, ok, log := repinFixture(t)
	snapshot := maps.Clone(s)
	for name, c := range map[string]RepinConfirmation{
		"empty":          {},
		"no current key": {NewKeyID: ok.NewKeyID},
		"no new key":     {ReplacesKeyID: ok.ReplacesKeyID},
		"prefix of new":  {ReplacesKeyID: ok.ReplacesKeyID, NewKeyID: ok.NewKeyID[:16]},
		"prefix of old":  {ReplacesKeyID: ok.ReplacesKeyID[:16], NewKeyID: ok.NewKeyID},
		"swapped":        {ReplacesKeyID: ok.NewKeyID, NewKeyID: ok.ReplacesKeyID},
	} {
		if err := RepinRecoveryKey(dir, s, next, c, recorder(log)); !errors.Is(err, ErrRepinNotConfirmed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := RepinRecoveryKey(dir, s, next, ok, nil); err == nil {
		t.Error("re-pin without an audit recorder accepted")
	}
	if len(*log) != 0 || !maps.Equal(s, snapshot) {
		t.Fatalf("refused re-pin left traces: audit %v, settings %v", *log, s)
	}
	requirePinned(t, dir, s, old)
}

func TestRepinAuthorisedMovesThePin(t *testing.T) {
	dir, s, old, next, c, log := repinFixture(t)
	// Typed off a card: upper case, grouped with spaces.
	c.NewKeyID = strings.ToUpper(c.NewKeyID[:32]) + "  " + c.NewKeyID[32:]
	if err := RepinRecoveryKey(dir, s, next, c, recorder(log)); err != nil {
		t.Fatal(err)
	}
	requirePinned(t, dir, s, next)
	if len(*log) != 1 || (*log)[0] != [2]string{old.Public.ID(), next.Public.ID()} {
		t.Fatalf("audit %v", *log)
	}
	// The old key is now the one a pairing gets refused for.
	var pe *PinnedError
	if err := StoreRecoveryKey(dir, s, old); !errors.As(err, &pe) {
		t.Fatalf("old key after re-pin: %v", err)
	}
}

// An attacker who can reach the product sees the pinned ID, but the operator types the new
// ID from their own cards; a key that is not the one on the cards is refused.
func TestRepinRefusesAForgedKey(t *testing.T) {
	dir, s, old, _, c, log := repinFixture(t)
	_, attacker := testKey(t)
	if err := RepinRecoveryKey(dir, s, attacker, c, recorder(log)); !errors.Is(err, ErrRepinNotConfirmed) {
		t.Fatalf("forged key: %v", err)
	}
	// A wrong current-key claim (a tab left open across another re-pin) is refused too.
	_, stale := testKey(t)
	c2 := RepinConfirmation{ReplacesKeyID: stale.Public.ID(), NewKeyID: attacker.Public.ID()}
	if err := RepinRecoveryKey(dir, s, attacker, c2, recorder(log)); !errors.Is(err, ErrRepinNotConfirmed) {
		t.Fatalf("wrong current key: %v", err)
	}
	if len(*log) != 0 {
		t.Fatalf("forged re-pin audited as accepted: %v", *log)
	}
	requirePinned(t, dir, s, old)
}

func TestRepinRefusedWhenAuditFails(t *testing.T) {
	dir, s, old, next, c, _ := repinFixture(t)
	snapshot := maps.Clone(s)
	fail := func(string, string) error { return errors.New("ledger full") }
	if err := RepinRecoveryKey(dir, s, next, c, fail); err == nil {
		t.Fatal("re-pin accepted with no audit record")
	}
	if !maps.Equal(s, snapshot) {
		t.Fatalf("settings changed: %v", s)
	}
	requirePinned(t, dir, s, old)
}

func TestRepinNeedsAnExistingPin(t *testing.T) {
	_, next := testKey(t)
	err := RepinRecoveryKey(t.TempDir(), memSettings{}, next, RepinConfirmation{NewKeyID: next.Public.ID()}, func(string, string) error { return nil })
	if !errors.Is(err, ErrNotPaired) {
		t.Fatalf("got %v", err)
	}
}

func TestRepinRerunIsIdempotent(t *testing.T) {
	dir, s, _, next, c, log := repinFixture(t)
	for range 3 {
		if err := RepinRecoveryKey(dir, s, next, c, recorder(log)); err != nil {
			t.Fatal(err)
		}
		requirePinned(t, dir, s, next)
	}
	if len(*log) != 1 {
		t.Fatalf("a re-run that moved nothing was audited: %v", *log)
	}
	// A finished re-pin with recovery.pub lost is refreshed the same way.
	_ = os.Remove(RecoveryKeyPath(dir))
	if err := RepinRecoveryKey(dir, s, next, c, recorder(log)); err != nil {
		t.Fatal(err)
	}
	requirePinned(t, dir, s, next)
}

// failAt is a store that dies at the nth Set, standing in for a crash between steps.
type failAt struct {
	memSettings
	n *int
}

func (f failAt) Set(k, v string) error {
	if *f.n == 0 {
		return errors.New("crash")
	}
	*f.n--
	return f.memSettings.Set(k, v)
}

func TestRepinInterruptedFailsClosedThenCompletesOrRollsBack(t *testing.T) {
	// Crash points: after the file is gone, and after each Set but the commit.
	for crash := -1; crash < 3; crash++ {
		for _, finish := range []bool{true, false} {
			dir, s, old, next, c, log := repinFixture(t)
			if crash < 0 {
				_ = os.Remove(RecoveryKeyPath(dir))
			} else {
				n := crash
				if err := RepinRecoveryKey(dir, failAt{s, &n}, next, c, recorder(log)); err == nil {
					t.Fatalf("crash %d: no error", crash)
				}
			}
			// Mid-flight: the pin has not moved, and nothing seals to either key.
			if got, _ := s.Get(settingRecoveryKeyID); got != old.Public.ID() {
				t.Fatalf("crash %d: pin moved before commit", crash)
			}
			if _, err := LoadRecoveryKey(dir, s); err == nil {
				t.Fatalf("crash %d: a half re-pin loaded as paired", crash)
			}
			if finish {
				if err := RepinRecoveryKey(dir, s, next, c, recorder(log)); err != nil {
					t.Fatalf("crash %d: finish: %v", crash, err)
				}
				requirePinned(t, dir, s, next)
			} else {
				back := RepinConfirmation{NewKeyID: old.Public.ID()}
				if err := RepinRecoveryKey(dir, s, old, back, recorder(log)); err != nil {
					t.Fatalf("crash %d: roll back: %v", crash, err)
				}
				requirePinned(t, dir, s, old)
			}
		}
	}
}
