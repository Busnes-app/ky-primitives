package recoveryclient

import (
	"context"
	"errors"
	"os"
	"testing"
)

type fatalSealer struct{ t *testing.T }

func (f fatalSealer) Seal(b []byte) (string, error) { return string(b), nil }
func (f fatalSealer) Open(string) ([]byte, error)   { f.t.Fatal("Open called"); return nil, nil }

func TestStorePairingRefusesEmptyToken(t *testing.T) {
	for _, tok := range []string{"", "  ", "\n\t"} {
		if err := StorePairing(memSettings{}, testSealer(t), "https://r.test", tok); err == nil {
			t.Fatalf("token %q stored", tok)
		}
	}
}

func TestStorePairingTrimsToken(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, key := testKey(t)
	if err := StoreRecoveryKey(dir, s, key); err != nil {
		t.Fatal(err)
	}
	if err := StorePairing(s, testSealer(t), "https://r.test", " tok\n"); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPairing(dir, s, testSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.Token != "tok" {
		t.Fatalf("token = %q, want trimmed token", p.Token)
	}
}

func TestHasPairingNeverDecrypts(t *testing.T) {
	s := memSettings{}
	if err := StorePairing(s, fatalSealer{t}, "https://r.test", "tok"); err != nil {
		t.Fatal(err)
	}
	if !HasPairing(s) {
		t.Fatal("not paired")
	}
}

func TestLoadPairingReportsKeyPinMissing(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	if _, err := LoadPairing(dir, s, testSealer(t)); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(RecoveryKeyPath(dir))
	_, err := LoadPairing(dir, s, testSealer(t))
	if !errors.Is(err, ErrKeyPinMissing) || errors.Is(err, ErrNotPaired) {
		t.Fatalf("lost pin: %v", err)
	}
}

func TestLoadPairingWrongSealerFails(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	other, _ := NewAESGCMSealer(make([]byte, 32), "other-label")
	if _, err := LoadPairing(dir, s, other); err == nil {
		t.Fatal("token opened under another sealer")
	}
	p, err := LoadPairing(dir, s, testSealer(t))
	if err != nil || p.Token != "kyrec_live_t" || p.URL != "https://recovery.example.test" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestClearPairingKeepsKeyPinAndReceipt(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	priv := pair(t, dir, s)
	s[settingLastDeposit] = `{"capsule_id":"cap-1"}`
	if err := ClearPairing(s); err != nil {
		t.Fatal(err)
	}
	if HasPairing(s) {
		t.Error("still paired")
	}
	if _, ok := s[settingRecoveryToken]; ok {
		t.Error("token row survived")
	}
	if k, err := LoadRecoveryKey(dir, s); err != nil || k.Public.ID() != priv.Public().ID() {
		t.Errorf("key pin lost: %v", err)
	}
	if last, ok, _ := LastDeposit(s); !ok || last.CapsuleID != "cap-1" {
		t.Error("receipt lost")
	}
	if err := ClearPairing(s); !errors.Is(err, ErrNotPaired) {
		t.Errorf("second clear: %v", err)
	}
}

func TestClearPairingHalfClearedStillClears(t *testing.T) {
	s := memSettings{settingRecoveryURL: "https://r.test"}
	if err := ClearPairing(s); err != nil {
		t.Fatal(err)
	}
	if len(s) != 0 {
		t.Errorf("rows left: %v", s)
	}
}

// flakySettings fails Get of one key, the way a busy database does now and then.
type flakySettings struct {
	memSettings
	failGet string
}

var errFlaky = errors.New("database is locked")

func (f flakySettings) Get(k string) (string, error) {
	if k == f.failGet {
		return "", errFlaky
	}
	return f.memSettings.Get(k)
}

// A settings read that fails is not "unpaired": Run must not skip KyRecovery and report success.
func TestRunReportsAPairingReadFailure(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	cfg := runCfg(dir, testSealer(t))
	cfg.BackupDir = t.TempDir()
	fake := &fakeDepositor{}
	flaky := flakySettings{memSettings: s, failGet: settingRecoveryToken}
	res, err := Run(context.Background(), cfg, flaky, func() (Payload, error) { return testPayload(), nil }, fake)
	if !errors.Is(err, errFlaky) {
		t.Fatalf("want the read error, got %v (deposits %d)", err, fake.calls)
	}
	// The local destination does not depend on the pairing rows and still gets its copy.
	if res.LocalPath == "" || fake.calls != 0 {
		t.Fatalf("local copy %q, deposits %d", res.LocalPath, fake.calls)
	}
	if _, outcome, _ := Outcome(res, err); outcome != "failure" {
		t.Fatalf("outcome %s", outcome)
	}
}
