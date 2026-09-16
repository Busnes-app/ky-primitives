package recoveryclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/Busnes-app/ky-primitives/capsule"
)

// ErrNoDestination means a key is pinned but there is nowhere to put a capsule: not paired
// with KyRecovery and no local backup directory.
var ErrNoDestination = errors.New("recoveryclient: no destination; pair with KyRecovery or set a backup directory")

// ErrInProgress answers a second run started while one is still working.
var ErrInProgress = errors.New("recoveryclient: a backup is already in progress")

// ErrReceiptUnrecorded means KyRecovery holds the capsule but this instance failed to write
// the receipt. The deposit happened; the caller must say so rather than report a refusal.
var ErrReceiptUnrecorded = errors.New("recoveryclient: deposit succeeded but the receipt was not recorded")

// runMu makes runs single-flight within one process: two at once would upload the same
// data twice and race on the receipt.
var runMu sync.Mutex

// RunConfig is what Run needs from the product's configuration.
type RunConfig struct {
	// DataDir holds recovery.pub.
	DataDir string
	// AppName is the service name KyRecovery pinned at pairing; the payload's ServiceName
	// must equal it, or KyRecovery refuses the deposit with 403.
	AppName    string
	AppVersion string
	// BackupDir, when set, receives a copy of every capsule. Keep is how many to retain.
	BackupDir string
	Keep      int
	// Sealer opens the stored KyRecovery token.
	Sealer Sealer
}

// Result is what one backup run produced. LocalPath is set when a copy landed in the local
// backup directory, LocalError when that destination failed; Receipt when KyRecovery
// confirmed the deposit. The destinations are independent: a full local disk does not stop
// the off-site copy, and the run is an error only when every configured destination failed.
type Result struct {
	Manifest   capsule.Manifest `json:"manifest"`
	SizeBytes  int              `json:"size_bytes"`
	LocalPath  string           `json:"local_path,omitempty"`
	LocalError string           `json:"local_error,omitempty"`
	Receipt    *Receipt         `json:"receipt,omitempty"`
}

// Run seals the instance once and sends the capsule everywhere it is configured to go: the
// local backup directory when one is set, KyRecovery when paired. collect produces the
// payload; it runs only after the key and a destination are known to exist. The receipt is
// what a restore is checked against, so it is written only after KyRecovery has confirmed
// the digest of the bytes sent. The attempt is stamped first, so a failing run is retried
// once per interval rather than on every scheduler tick.
func Run(ctx context.Context, cfg RunConfig, settings Settings, collect func() (Payload, error), client Depositor) (Result, error) {
	if !runMu.TryLock() {
		return Result{}, ErrInProgress
	}
	defer runMu.Unlock()
	if err := markAttempt(settings); err != nil {
		return Result{}, err
	}
	key, err := LoadRecoveryKey(cfg.DataDir, settings)
	if (errors.Is(err, ErrNotPaired) || errors.Is(err, ErrKeyMismatch)) && HasPairing(settings) {
		return Result{}, fmt.Errorf("%w: %v", ErrKeyPinMissing, err)
	}
	if err != nil {
		return Result{}, err
	}
	paired := HasPairing(settings)
	if !paired && cfg.BackupDir == "" {
		return Result{}, ErrNoDestination
	}
	if cfg.BackupDir != "" && cfg.Keep < 1 {
		return Result{}, ErrBadKeep
	}
	payload, err := collect()
	if err != nil {
		return Result{}, err
	}
	if payload.ServiceName != cfg.AppName {
		return Result{}, fmt.Errorf("recoveryclient: payload names service %q, this instance is %q", payload.ServiceName, cfg.AppName)
	}
	raw, m, err := Seal(payload, key)
	if err != nil {
		return Result{}, err
	}
	res := Result{Manifest: m, SizeBytes: len(raw)}
	var localErr error
	if cfg.BackupDir != "" {
		if res.LocalPath, localErr = WriteLocalCopy(cfg.BackupDir, cfg.AppName, m.CapsuleID, raw, cfg.Keep); localErr != nil {
			localErr = fmt.Errorf("local copy: %w", localErr)
			res.LocalError = AuditSafe(localErr.Error())
		}
	}
	if !paired {
		return res, localErr
	}
	pairing, err := LoadPairing(cfg.DataDir, settings, cfg.Sealer)
	if err != nil {
		return res, err
	}
	rcpt, err := client.Deposit(ctx, pairing.URL, pairing.Token, raw)
	if err != nil {
		return res, err
	}
	if rcpt.CapsuleID != m.CapsuleID {
		return res, fmt.Errorf("%w: deposit receipt names capsule %s, sent %s", ErrRemote, rcpt.CapsuleID, m.CapsuleID)
	}
	res.Receipt = &rcpt
	b, _ := json.Marshal(rcpt)
	if err := settings.Set(settingLastDeposit, string(b)); err != nil {
		return res, fmt.Errorf("%w: %s: %w", ErrReceiptUnrecorded, rcpt.CapsuleID, err)
	}
	return res, nil
}

// Outcome classifies a Run result for the audit log, so every caller records the same
// event for the same result. A capsule KyRecovery holds is a success even when this side
// failed to write the receipt; the cause rides in the details. A local copy that was
// written before the deposit failed is named too. Every field is bounded here.
func Outcome(res Result, err error) (action, outcome string, details map[string]any) {
	details = map[string]any{"capsule_id": AuditSafe(res.Manifest.CapsuleID), "size_bytes": res.SizeBytes}
	if res.LocalPath != "" {
		details["local_path"] = AuditSafe(res.LocalPath)
	}
	if res.LocalError != "" {
		details["local_error"] = AuditSafe(res.LocalError)
	}
	if res.Receipt != nil {
		details["digest"] = AuditSafe(res.Receipt.Digest)
		details["deposited"] = true
	}
	switch {
	case err == nil:
		return "admin.backup_run", "success", details
	case errors.Is(err, ErrReceiptUnrecorded):
		details["receipt_unrecorded"] = AuditSafe(err.Error())
		return "admin.backup_run", "success", details
	default:
		details["error"] = AuditSafe(err.Error())
		return "admin.backup_run", "failure", details
	}
}
