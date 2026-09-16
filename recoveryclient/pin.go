package recoveryclient

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
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

// StoreRecoveryKey persists k. A second pairing to a different key fails with fs.ErrExist —
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
		return fmt.Errorf("%w: already paired to recovery key %s; rotating requires clearing both %s and the %s, %s and %s settings",
			fs.ErrExist, pinned, path, settingRecoveryKeyID, settingThreshold, settingTotalShares)
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
