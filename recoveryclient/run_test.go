package recoveryclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
)

func runCfg(dir string, s Sealer) RunConfig {
	return RunConfig{DataDir: dir, AppName: "Svc", AppVersion: "1.0.0", Keep: 7, Sealer: s}
}

func TestRunNeedsAKeyThenADestination(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	fake := &fakeDepositor{}
	if _, err := Run(context.Background(), runCfg(dir, testSealer(t)), s, func() (Payload, error) { return testPayload(), nil }, fake); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("no key: %v", err)
	}
	_, k := testKey(t)
	_ = StoreRecoveryKey(dir, s, k)
	collected := false
	_, err := Run(context.Background(), runCfg(dir, testSealer(t)), s, func() (Payload, error) { collected = true; return testPayload(), nil }, fake)
	if !errors.Is(err, ErrNoDestination) || collected || fake.calls != 0 {
		t.Fatalf("key only: %v collected=%v calls=%d", err, collected, fake.calls)
	}
}

func TestRunLocalOnlyWithoutKyRecovery(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	priv, k := testKey(t)
	_ = StoreRecoveryKey(dir, s, k)
	cfg := runCfg(dir, testSealer(t))
	cfg.BackupDir = filepath.Join(t.TempDir(), "capsules")
	fake := &fakeDepositor{}
	res, err := Run(context.Background(), cfg, s, func() (Payload, error) { return testPayload(), nil }, fake)
	if err != nil || res.Receipt != nil || res.LocalPath == "" || fake.calls != 0 {
		t.Fatalf("%+v %v calls=%d", res, err, fake.calls)
	}
	raw, _ := os.ReadFile(res.LocalPath)
	if _, files, err := capsule.Open(raw, priv, t.TempDir()); err != nil || len(files) != 2 {
		t.Fatalf("local copy does not open with the suite key: %v", err)
	}
}

func TestRunPairedDeliversToBothAndRecordsReceipt(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	priv := pair(t, dir, s)
	cfg := runCfg(dir, testSealer(t))
	cfg.BackupDir = t.TempDir()
	fake := &fakeDepositor{}
	res, err := Run(context.Background(), cfg, s, func() (Payload, error) { return testPayload(), nil }, fake)
	if err != nil || res.Receipt == nil || res.LocalPath == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if fake.url != "https://recovery.example.test" || fake.token != "kyrec_live_t" {
		t.Errorf("sent to %s with %s", fake.url, fake.token)
	}
	if _, _, err := capsule.Open(fake.container, priv, t.TempDir()); err != nil {
		t.Fatalf("what the store holds does not open: %v", err)
	}
	if last, ok, _ := LastDeposit(s); !ok || last.CapsuleID != res.Manifest.CapsuleID {
		t.Errorf("receipt %+v %v", last, ok)
	}
	if res.Manifest.Threshold != 2 || res.Manifest.TotalShares != 3 || res.Manifest.ServiceName != "Svc" {
		t.Errorf("manifest %+v", res.Manifest)
	}
}

func TestRunLocalFailureDoesNotCancelTheDeposit(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	cfg := runCfg(dir, testSealer(t))
	cfg.BackupDir = filepath.Join(t.TempDir(), "file-not-dir")
	_ = os.WriteFile(cfg.BackupDir, nil, 0600)
	fake := &fakeDepositor{}
	res, err := Run(context.Background(), cfg, s, func() (Payload, error) { return testPayload(), nil }, fake)
	if err != nil || res.Receipt == nil || res.LocalError == "" || res.LocalPath != "" {
		t.Fatalf("%+v %v", res, err)
	}
	_, outcome, details := Outcome(res, err)
	if outcome != "success" || details["local_error"] == nil || details["deposited"] != true {
		t.Errorf("%s %v", outcome, details)
	}
}

func TestRunRefusesAPayloadForAnotherService(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	p := testPayload()
	p.ServiceName = "Other"
	fake := &fakeDepositor{}
	if _, err := Run(context.Background(), runCfg(dir, testSealer(t)), s, func() (Payload, error) { return p, nil }, fake); err == nil || fake.calls != 0 {
		t.Fatalf("%v calls=%d", err, fake.calls)
	}
}

func TestRunReceiptForOtherCapsuleIsRemoteAndUnrecorded(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	lying := &lyingDepositor{}
	res, err := Run(context.Background(), runCfg(dir, testSealer(t)), s, func() (Payload, error) { return testPayload(), nil }, lying)
	if !errors.Is(err, ErrRemote) || res.Receipt != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if _, ok, _ := LastDeposit(s); ok {
		t.Error("a mismatched receipt was recorded")
	}
	_, outcome, details := Outcome(res, err)
	if outcome != "failure" || !strings.Contains(fmt.Sprint(details["error"]), "names capsule") {
		t.Errorf("%s %v", outcome, details)
	}
}

type lyingDepositor struct{}

func (lyingDepositor) Deposit(context.Context, string, string, []byte) (Receipt, error) {
	return Receipt{CapsuleID: "cap-somebody-else", Digest: "x", SizeBytes: 1}, nil
}

func TestRunIsSingleFlight(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	runMu.Lock()
	_, err := Run(context.Background(), runCfg(dir, testSealer(t)), s, func() (Payload, error) { return testPayload(), nil }, &fakeDepositor{})
	runMu.Unlock()
	if !errors.Is(err, ErrInProgress) {
		t.Fatalf("%v", err)
	}
}

func TestOutcomeBoundsEveryField(t *testing.T) {
	m := capsule.Manifest{UnverifiedManifest: capsule.UnverifiedManifest{CapsuleID: "cap-1"}}
	res := Result{Manifest: m, SizeBytes: 3, Receipt: &Receipt{CapsuleID: "cap-1", Digest: "abc"}}
	action, outcome, details := Outcome(res, fmt.Errorf("%w: cap-1: disk full", ErrReceiptUnrecorded))
	if action != "admin.backup_run" || outcome != "success" || details["deposited"] != true || !strings.Contains(fmt.Sprint(details["receipt_unrecorded"]), "disk full") {
		t.Errorf("%s %s %v", action, outcome, details)
	}
	_, outcome, details = Outcome(Result{Manifest: m}, errors.New("deposit rejected (503): "+strings.Repeat("x\n", 5000)))
	if outcome != "failure" || len(fmt.Sprint(details["error"])) > 300 || strings.Contains(fmt.Sprint(details["error"]), "\n") {
		t.Errorf("%s %v", outcome, details)
	}
}

func TestRunRefusesABadKeepBeforeCollecting(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	_, k := testKey(t)
	_ = StoreRecoveryKey(dir, s, k)
	cfg := runCfg(dir, testSealer(t))
	cfg.BackupDir = t.TempDir()
	cfg.Keep = 0
	collected := false
	if _, err := Run(context.Background(), cfg, s, func() (Payload, error) { collected = true; return testPayload(), nil }, &fakeDepositor{}); !errors.Is(err, ErrBadKeep) || collected {
		t.Fatalf("%v collected=%v", err, collected)
	}
}
