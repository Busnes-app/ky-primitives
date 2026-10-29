package recoveryclient

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

var (
	ErrNotPaired   = errors.New("recoveryclient: no recovery public key; pair with KyRecovery first")
	ErrKeyMismatch = errors.New("recoveryclient: stored recovery public key does not match the pinned key ID")
)

const (
	settingRecoveryKeyID  = "kyrecovery_key_id"
	settingThreshold      = "kyrecovery_threshold"
	settingTotalShares    = "kyrecovery_total_shares"
	recoveryPublicKeyFile = "recovery.pub"
)

// RecoveryKey is what a product holds after pairing: the suite recovery public key and the
// custodian topology kyrecovery reported for it. There is no private half here, ever.
type RecoveryKey struct {
	Public      recoverykey.PublicKey
	Threshold   int
	TotalShares int
}

// RecoveryKeyPath is where the raw 1216-byte public key lives.
func RecoveryKeyPath(dataDir string) string {
	return filepath.Join(dataDir, recoveryPublicKeyFile)
}

// validTopology reports whether a k-of-n custodian split is one a suite can actually recover.
func validTopology(threshold, total int) bool {
	return threshold >= 2 && total >= threshold && total <= 255
}

// StoreRecoveryKey persists k. A second pairing to a different key fails with *PinnedError —
// whether or not recovery.pub still exists, because the settings pin is what decides; the
// same key again is an idempotent refresh that recreates a missing file.
func StoreRecoveryKey(dataDir string, settings Settings, k RecoveryKey) error {
	if k.Public.IsZero() {
		return errors.New("recoveryclient: refusing to store a zero recovery public key")
	}
	if !validTopology(k.Threshold, k.TotalShares) {
		return fmt.Errorf("recoveryclient: %d-of-%d is not a custodian topology", k.Threshold, k.TotalShares)
	}
	path := RecoveryKeyPath(dataDir)
	// The settings pin decides, not the file: recovery.pub is absent on every restored
	// instance and deletable by anyone with the data directory.
	pinned, perr := settings.Get(settingRecoveryKeyID)
	if perr != nil && !errors.Is(perr, ErrNotFound) {
		return perr
	}
	if perr == nil && pinned != k.Public.ID() {
		return &PinnedError{PinnedKeyID: pinned, OfferedKeyID: k.Public.ID()}
	}
	err := keyfile.Store(path, k.Public.Bytes(), keyfile.Raw)
	if errors.Is(err, fs.ErrExist) {
		existing, lerr := keyfile.LoadEncoded(path, recoverykey.PublicKeyBytes, keyfile.Raw)
		if lerr != nil {
			return lerr
		}
		if pk, pkerr := recoverykey.ParsePublicKey(existing); pkerr != nil || pk.ID() != k.Public.ID() {
			return fmt.Errorf("%w: %s holds recovery key %s; remove it to re-pair", err, path, pinnedID(existing))
		}
	} else if err != nil {
		return err
	}
	if err := settings.Set(settingRecoveryKeyID, k.Public.ID()); err != nil {
		return err
	}
	if err := settings.Set(settingThreshold, strconv.Itoa(k.Threshold)); err != nil {
		return err
	}
	return settings.Set(settingTotalShares, strconv.Itoa(k.TotalShares))
}

// CodeRecoveryKeyPinned is the stable error code for a pairing refused by the pin.
const CodeRecoveryKeyPinned = "recovery_key_pinned"

// PinnedError is a pairing offered a key other than the pinned one. It satisfies
// errors.Is(err, fs.ErrExist). Moving to the offered key is RepinRecoveryKey's job.
type PinnedError struct {
	PinnedKeyID, OfferedKeyID string
}

func (e *PinnedError) Error() string {
	return fmt.Sprintf("recoveryclient: %s: pinned to recovery key %s, offered %s; moving to a new key requires an explicit re-pin",
		CodeRecoveryKeyPinned, e.PinnedKeyID, e.OfferedKeyID)
}

// Code is CodeRecoveryKeyPinned, for the product's JSON error body.
func (e *PinnedError) Code() string { return CodeRecoveryKeyPinned }

func (e *PinnedError) Unwrap() error { return fs.ErrExist }

// ErrRepinNotConfirmed is a re-pin whose confirmation does not name both the pinned key and
// the offered key.
var ErrRepinNotConfirmed = errors.New("recoveryclient: re-pin not confirmed")

// RepinConfirmation is what the operator typed: the full ID of the key being replaced, as the
// product shows it, and the full ID of the new key, as printed on the new custodian cards.
type RepinConfirmation struct {
	ReplacesKeyID string
	NewKeyID      string
}

// RepinRecoveryKey moves the pin from the current key to k. The recovery key cannot sign, so
// nothing cryptographic links old to new: the proof is the operator matching k's ID to the
// cards they hold. The caller must gate this on an administrator with fresh step-up and must
// not prefill NewKeyID from k. audit records both IDs before anything changes; its failure
// refuses the re-pin.
//
// The key ID setting is written last and is the commit point: until it moves, the file and
// pin disagree and LoadRecoveryKey refuses to seal. Re-running the same call finishes an
// interrupted re-pin; naming the still-pinned key as k rolls it back instead. Rewriting the
// pinned key needs no audit, since the pin does not move.
func RepinRecoveryKey(dataDir string, settings Settings, k RecoveryKey, c RepinConfirmation, audit func(fromKeyID, toKeyID string) error) error {
	if k.Public.IsZero() {
		return errors.New("recoveryclient: refusing to store a zero recovery public key")
	}
	if !validTopology(k.Threshold, k.TotalShares) {
		return fmt.Errorf("recoveryclient: %d-of-%d is not a custodian topology", k.Threshold, k.TotalShares)
	}
	if audit == nil {
		return errors.New("recoveryclient: re-pin needs an audit recorder")
	}
	newID := k.Public.ID()
	if normalizeKeyID(c.NewKeyID) != newID {
		return fmt.Errorf("%w: the new key ID entered does not match the key offered (%s)", ErrRepinNotConfirmed, newID)
	}
	pinned, err := settings.Get(settingRecoveryKeyID)
	if errors.Is(err, ErrNotFound) {
		return ErrNotPaired
	}
	if err != nil {
		return err
	}
	if pinned != newID {
		if normalizeKeyID(c.ReplacesKeyID) != pinned {
			return fmt.Errorf("%w: the key being replaced must be the pinned key %s", ErrRepinNotConfirmed, pinned)
		}
		if err := audit(pinned, newID); err != nil {
			return fmt.Errorf("recoveryclient: re-pin not recorded, refused: %w", err)
		}
	}
	path := RecoveryKeyPath(dataDir)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := keyfile.Store(path, k.Public.Bytes(), keyfile.Raw); err != nil {
		return err
	}
	if err := settings.Set(settingThreshold, strconv.Itoa(k.Threshold)); err != nil {
		return err
	}
	if err := settings.Set(settingTotalShares, strconv.Itoa(k.TotalShares)); err != nil {
		return err
	}
	return settings.Set(settingRecoveryKeyID, newID)
}

// normalizeKeyID forgives what copying an ID off a card adds: case and whitespace.
func normalizeKeyID(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), ""))
}

func pinnedID(raw []byte) string {
	pk, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return "(unparseable)"
	}
	return pk.ID()
}

// LoadRecoveryKey reads the public key file and checks it against the pinned key ID in the
// settings table, so a swapped file is detected before anything is sealed to it.
func LoadRecoveryKey(dataDir string, settings Settings) (RecoveryKey, error) {
	raw, err := keyfile.LoadEncoded(RecoveryKeyPath(dataDir), recoverykey.PublicKeyBytes, keyfile.Raw)
	if errors.Is(err, fs.ErrNotExist) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	pk, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, err
	}
	id, err := settings.Get(settingRecoveryKeyID)
	if errors.Is(err, ErrNotFound) {
		return RecoveryKey{}, ErrNotPaired
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	if id != pk.ID() {
		return RecoveryKey{}, ErrKeyMismatch
	}
	k := RecoveryKey{Public: pk}
	if k.Threshold, err = intSetting(settings, settingThreshold); err != nil {
		return RecoveryKey{}, err
	}
	if k.TotalShares, err = intSetting(settings, settingTotalShares); err != nil {
		return RecoveryKey{}, err
	}
	if !validTopology(k.Threshold, k.TotalShares) {
		return RecoveryKey{}, errors.New("recoveryclient: retained custodian topology is invalid")
	}
	return k, nil
}

// intSetting reads a pinned integer. A key ID with no topology beside it is a pairing that
// died halfway, which is not paired.
func intSetting(settings Settings, key string) (int, error) {
	v, err := settings.Get(key)
	if errors.Is(err, ErrNotFound) {
		return 0, ErrNotPaired
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// ParsePinRequest turns the base64 public key from the ceremony page and its k-of-n into a
// RecoveryKey ready for StoreRecoveryKey. Whitespace inside the base64 is tolerated: the key
// is pasted from a browser.
func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(publicKeyB64), ""))
	if err != nil || len(raw) != recoverykey.PublicKeyBytes {
		return RecoveryKey{}, fmt.Errorf("recoveryclient: public_key must be the %d-byte suite recovery public key in base64", recoverykey.PublicKeyBytes)
	}
	pub, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, errors.New("recoveryclient: public_key is not a recovery public key")
	}
	if !validTopology(threshold, total) {
		return RecoveryKey{}, fmt.Errorf("recoveryclient: %d-of-%d is not a custodian topology", threshold, total)
	}
	return RecoveryKey{Public: pub, Threshold: threshold, TotalShares: total}, nil
}
