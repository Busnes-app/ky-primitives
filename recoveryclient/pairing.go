package recoveryclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Settings keys. The token lives under its own key so a value written by an older build,
// which stored it in the clear, is never mistaken for ciphertext.
const (
	settingRecoveryURL   = "kyrecovery_url"
	settingRecoveryToken = "kyrecovery_token_enc"
	settingLastDeposit   = "kyrecovery_last_deposit"
)

// ErrKeyPinMissing means the instance has a pairing record but the recovery public key it
// seals to cannot be resolved: recovery.pub is gone or disagrees with the pin. Unlike
// ErrNotPaired it is a failure to report, not a quiet skip, because scheduled backups have
// stopped on an instance the operator believes is covered.
var ErrKeyPinMissing = errors.New("recoveryclient: paired with KyRecovery but the recovery public key is missing or does not match the pin")

// Depositor is the deposit half of the KyRecovery client, narrowed so callers can stand in
// a fake without reaching the network.
type Depositor interface {
	Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error)
}

// Pairing is everything a deposit needs: where to send it, the bearer token, and the key
// the container is sealed to.
type Pairing struct {
	URL   string
	Token string
	Key   RecoveryKey
}

// StorePairing records the server URL and the bearer token after StoreRecoveryKey has pinned
// the key. The token is sealed by the product's Sealer before it reaches the row.
func StorePairing(settings Settings, sealer Sealer, serverURL, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("recoveryclient: refusing to store an empty KyRecovery token")
	}
	sealed, err := sealer.Seal([]byte(token))
	if err != nil {
		return fmt.Errorf("recoveryclient: failed to seal the KyRecovery token: %w", err)
	}
	if err := settings.Set(settingRecoveryURL, serverURL); err != nil {
		return err
	}
	return settings.Set(settingRecoveryToken, sealed)
}

// ClearPairing removes the KyRecovery URL and the sealed token from settings, so
// scheduled deposits stop and LoadPairing refuses. That is all it does: the rows are gone
// from the table, not scrubbed from the database file, and the credential itself is dead
// only once the KyRecovery admin revokes it there. The key pin stays: unpairing does not
// make a different key acceptable, and the local backup directory keeps working. Receipts
// stay as history. A pairing left half-cleared by an earlier failure is cleared too.
func ClearPairing(settings Settings) error {
	_, uerr := settings.Get(settingRecoveryURL)
	_, terr := settings.Get(settingRecoveryToken)
	if errors.Is(uerr, ErrNotFound) && errors.Is(terr, ErrNotFound) {
		return ErrNotPaired
	}
	if err := settings.Delete(settingRecoveryToken); err != nil {
		return err
	}
	return settings.Delete(settingRecoveryURL)
}

// HasPairing reports whether a URL and a token are stored. It never opens the token.
func HasPairing(settings Settings) bool {
	paired, err := pairingStored(settings)
	return paired && err == nil
}

// pairingStored is HasPairing with read failures reported: only a missing row means unpaired.
func pairingStored(settings Settings) (bool, error) {
	for _, k := range []string{settingRecoveryURL, settingRecoveryToken} {
		v, err := settings.Get(k)
		if errors.Is(err, ErrNotFound) || err == nil && v == "" {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// LoadPairing returns the pairing, or ErrNotPaired when any part is missing. A pairing
// record whose key will not resolve is ErrKeyPinMissing: it must be reported, not skipped.
func LoadPairing(dataDir string, settings Settings, sealer Sealer) (Pairing, error) {
	key, err := LoadRecoveryKey(dataDir, settings)
	if (errors.Is(err, ErrNotPaired) || errors.Is(err, ErrKeyMismatch)) && HasPairing(settings) {
		return Pairing{}, fmt.Errorf("%w: %v", ErrKeyPinMissing, err)
	}
	if err != nil {
		return Pairing{}, err
	}
	p := Pairing{Key: key}
	if p.URL, err = settings.Get(settingRecoveryURL); err != nil {
		return Pairing{}, notPaired(err)
	}
	sealed, err := settings.Get(settingRecoveryToken)
	if err != nil {
		return Pairing{}, notPaired(err)
	}
	if p.URL == "" || sealed == "" {
		return Pairing{}, ErrNotPaired
	}
	plain, err := sealer.Open(sealed)
	if err != nil {
		return Pairing{}, fmt.Errorf("recoveryclient: the stored KyRecovery token will not open under this deployment's key: %w", err)
	}
	p.Token = string(plain)
	return p, nil
}

func notPaired(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrNotPaired
	}
	return err
}

// LastDeposit is the most recent receipt, or ok=false when nothing has been deposited.
func LastDeposit(settings Settings) (Receipt, bool, error) {
	v, err := settings.Get(settingLastDeposit)
	if errors.Is(err, ErrNotFound) || (err == nil && v == "") {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	var r Receipt
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		return Receipt{}, false, err
	}
	return r, true, nil
}
