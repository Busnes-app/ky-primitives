# ky-primitives `kyrecovery` Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One stdlib-only package, `github.com/Busnes-app/ky-primitives/kyrecovery`, holding the product-side KyRecovery backup code that four products currently carry as divergent copies, so every product becomes a thin adapter.

**Architecture:** Lift `kysignon-server/internal/backup/{client,deposit,recoverykey,local,schedule,capsule,drill}.go` and `cmd/kysignon/main.go` (`restore`, `readShares`) into the package. Product-specific things become interfaces the product supplies: `Settings` (key-value rows), `Sealer` (AEAD under the deployment key), a `collect` callback (what to seal), a `checks` callback (drill assertions). Config, HTTP handlers, UI, audit API, compose and docs stay per product.

**Tech Stack:** Go 1.26 stdlib only (`crypto/aes`, `crypto/cipher`, `crypto/hkdf`, `net/http`, `go/ast`). Consumes sibling packages `capsule`, `recoverykey`, `shamir`, `keyfile`.

**Spec:** myslop folder `ky-primitives-kyrecovery-package`, post "Build the product-side KyRecovery package in ky-primitives (do this first)" (Yoshi's decision, 2026-09-04). Reference implementation: `kysignon-server` master `internal/backup/` and its `AGENTS.md`. Spec rows 1–7 and 11 of `ky_server_base/docs/superpowers/plans/2026-09-04-bring-suite-to-kysignon-spec.md`.

## Global Constraints

- **Stdlib only.** `nodeps_test.go` (`TestOnlyPasswordImportsADependency`) must stay green; no new `require` in `go.mod`.
- **Copy behaviour, not text.** Every function lifted from kysignon keeps its test; rename `kysignon` to a parameter, never hardcode a product name or env var.
- **Names in the spec are fixed:** `Settings`, `ErrNotFound`, `Sealer`, `NewAESGCMSealer`, `Client`, `Options{AllowPrivate}`, `ValidateURL`, `RecoveryKey`, `StoreRecoveryKey`, `LoadRecoveryKey`, `ParsePinRequest`, `StorePairing`, `LoadPairing`, `HasPairing`, `ClearPairing`, `WriteLocalCopy`, `ListLocalCopies`, `Interval`, `SetInterval`, `NextRun`, `MinInterval`, `MaxInterval`, `Run`, `RunConfig`, `Result`, `Outcome`, `Payload`, `File`, `Seal`, `AuditSafe`, `FilenameSafe`, `Drill`, `Check`, `ReadShares`, `Restore`, `guardtest.NoDecryptOutside`. Errors: `ErrNotPaired`, `ErrKeyMismatch`, `ErrKeyPinMissing`, `ErrNoDestination`, `ErrInProgress`, `ErrRemote`, `ErrReceiptUnrecorded`, `ErrBadInterval`.
- **Hazards the reviewer caught this week, all pinned by tests:** prune only own prefix; local failure never cancels deposit; interval bounded in seconds before Duration math; CGNAT exemption named; HTTPS always, loopback/link-local/multicast/unspecified/reserved never; `ClearPairing` claims only what it does and clears a half-cleared pairing; decrypt guard uses an absolute root, a file-count floor, and is proven by planting a forbidden call once.
- **Text from outside the process** (remote bodies, operator URLs) passes `AuditSafe` (printable, 200 chars) before any error string.
- Settings keys are the ones kysignon already stores, so kysignon's live pairing survives the swap: `kyrecovery_key_id`, `kyrecovery_threshold`, `kyrecovery_total_shares`, `kyrecovery_url`, `kyrecovery_token_enc`, `kyrecovery_last_deposit`, `backup_interval_sec`, `backup_last_attempt`. Key file `recovery.pub` in the data dir.
- Commit after every task with a conventional message; the package ships in one PR, tagged `v0.5.0`.

---

## File map

```
kyrecovery/
  doc.go          package comment: what lives here, what does not
  settings.go     Settings interface, ErrNotFound, intSetting helper
  sealer.go       Sealer interface, NewAESGCMSealer (HKDF-SHA256 label -> AES-256-GCM)
  pin.go          RecoveryKey, StoreRecoveryKey, LoadRecoveryKey, ParsePinRequest, ErrNotPaired, ErrKeyMismatch
  pairing.go      Pairing, StorePairing, LoadPairing, HasPairing, ClearPairing, ErrKeyPinMissing, LastDeposit
  client.go       Client, Options, NewClient, ValidateURL, allowedIP, ClaimPairing, Deposit, Receipt, ErrRemote, AuditSafe
  payload.go      Payload, File, Seal, FilenameSafe, TooLargeMessage
  local.go        LocalCopy, WriteLocalCopy, ListLocalCopies
  schedule.go     MinInterval, MaxInterval, ErrBadInterval, Interval, SetInterval, NextRun, markAttempt
  run.go          RunConfig, Result, Run, Outcome, ErrNoDestination, ErrInProgress
  drill.go        Check, DrillResult, Drill
  restore.go      ReadShares, Restore
  export_test.go  NewClientWithTransportForTest
  *_test.go       one test file per source file, lifted from kysignon backup_test.go
kyrecovery/guardtest/
  guardtest.go    NoDecryptOutside(t, repoRoot, allowed)
  guardtest_test.go
```

Everything in `kyrecovery` is `package kyrecovery`. `guardtest` is its own package so products import it only from tests.

---

### Task 1: `Settings`, `Sealer`, package skeleton

**Files:**
- Create: `kyrecovery/doc.go`, `kyrecovery/settings.go`, `kyrecovery/sealer.go`, `kyrecovery/sealer_test.go`

**Interfaces:**
- Produces: `type Settings interface { Get(key string) (string, error); Set(key, value string) error; Delete(key string) error }`, `var ErrNotFound`, `type Sealer interface { Seal(plain []byte) (string, error); Open(sealed string) ([]byte, error) }`, `func NewAESGCMSealer(key []byte, label string) (Sealer, error)`, `func intSetting(s Settings, key string) (int, error)`.

- [ ] **Step 1: Write the failing sealer test**

```go
package kyrecovery

import (
	"bytes"
	"testing"
)

func TestAESGCMSealerRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	s, err := NewAESGCMSealer(key, "app:setting:kyrecovery_token")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("token-value"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Open(sealed)
	if err != nil || string(plain) != "token-value" {
		t.Fatalf("open: %v %q", err, plain)
	}
}

func TestAESGCMSealerLabelSeparates(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a, _ := NewAESGCMSealer(key, "a")
	b, _ := NewAESGCMSealer(key, "b")
	sealed, _ := a.Seal([]byte("x"))
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("a ciphertext sealed under label a opened under label b")
	}
}

func TestAESGCMSealerRefusesShortKey(t *testing.T) {
	if _, err := NewAESGCMSealer(make([]byte, 16), "a"); err == nil {
		t.Fatal("16-byte deployment key accepted")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./kyrecovery/ -run AESGCM`
Expected: FAIL, `undefined: NewAESGCMSealer`

- [ ] **Step 3: Write settings.go, sealer.go, doc.go**

`doc.go`:

```go
// Package kyrecovery is the product side of the KySignOn backup contract: pin the suite
// recovery public key, pair with a KyRecovery server, seal the product's payload into a
// capsule, deliver it to a local directory and to KyRecovery on a schedule, drill a restore
// against a throwaway key, and restore from custodian shares.
//
// The product supplies what differs per product: a Settings row store, a Sealer under its
// deployment key, a collect func that says what to seal, and a checks func for the drill.
// Config, HTTP handlers, UI, audit and docs stay in the product.
package kyrecovery
```

`settings.go`:

```go
package kyrecovery

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrNotFound is what Settings.Get returns for a key never written. Products map their
// store's not-found error onto it; a key deliberately set to "" is not ErrNotFound.
var ErrNotFound = errors.New("kyrecovery: setting not found")

// Settings is the slice of the product's key-value store this package needs.
type Settings interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// intSetting reads a pinned integer. A key ID with no topology beside it is a pairing that
// died halfway, which is not paired.
func intSetting(s Settings, key string) (int, error) {
	v, err := s.Get(key)
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
```

`sealer.go`:

```go
package kyrecovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Sealer protects one settings value at rest under the product's deployment key. The
// product may supply its own (kysignon does, so its stored token keeps decrypting) or use
// NewAESGCMSealer.
type Sealer interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

type aesGCMSealer struct{ aead cipher.AEAD }

// NewAESGCMSealer derives a per-label AES-256-GCM key from the deployment key with
// HKDF-SHA256, so a value sealed for one setting will not open as another. key must be at
// least 32 bytes.
func NewAESGCMSealer(key []byte, label string) (Sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("kyrecovery: deployment key must be at least 32 bytes")
	}
	if label == "" {
		return nil, errors.New("kyrecovery: sealer label must not be empty")
	}
	sub, err := hkdf.Key(sha256.New, key, nil, label, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aesGCMSealer{aead: aead}, nil
}

func (s *aesGCMSealer) Seal(plain []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (s *aesGCMSealer) Open(sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("kyrecovery: sealed value is not base64: %w", err)
	}
	n := s.aead.NonceSize()
	if len(raw) < n {
		return nil, errors.New("kyrecovery: sealed value too short")
	}
	return s.aead.Open(nil, raw[:n], raw[n:], nil)
}
```

`ErrNotPaired` is defined in Task 2; add a temporary `var ErrNotPaired = errors.New("kyrecovery: not paired")` in `settings.go` now and move it in Task 2.

- [ ] **Step 4: Run tests**

Run: `go test ./kyrecovery/ && go test -run 'Nodeps|OnlyPassword|Allowlisted' .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add kyrecovery/
git commit -m "kyrecovery: Settings and Sealer interfaces, AES-GCM sealer"
```

---

### Task 2: Key pin (`pin.go`)

**Files:**
- Create: `kyrecovery/pin.go`, `kyrecovery/pin_test.go`
- Source: `kysignon-server/internal/backup/recoverykey.go` (152 lines), tests in `kysignon-server/internal/backup/backup_test.go` (the `StoreRecoveryKey`/`LoadRecoveryKey` cases: write-once, same key refresh, mismatch, missing topology).

**Interfaces:**
- Produces: `var ErrNotPaired, ErrKeyMismatch`, `type RecoveryKey struct { Public recoverykey.PublicKey; Threshold, TotalShares int }`, `func RecoveryKeyPath(dataDir string) string`, `func StoreRecoveryKey(dataDir string, s Settings, k RecoveryKey) error`, `func LoadRecoveryKey(dataDir string, s Settings) (RecoveryKey, error)`, `func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error)`.

- [ ] **Step 1: Write the failing tests**

Create a `memSettings` test helper in `pin_test.go` (every later test file uses it):

```go
package kyrecovery

type memSettings map[string]string

func (m memSettings) Get(k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (m memSettings) Set(k, v string) error { m[k] = v; return nil }
func (m memSettings) Delete(k string) error  { delete(m, k); return nil }

func testKey(t *testing.T) RecoveryKey {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}
}
```

Tests (port each kysignon case; the names below are the required set):

```go
func TestStoreRecoveryKeyIsWriteOnce(t *testing.T)        // second Store with a different key: errors.Is(err, fs.ErrExist); settings unchanged
func TestStoreRecoveryKeyRecreatesMissingFile(t *testing.T) // same key again after os.Remove(recovery.pub): file back, no error
func TestStoreRecoveryKeyRefusesBadTopology(t *testing.T)  // 1-of-3 and 3-of-2 both refused, nothing written
func TestLoadRecoveryKeyDetectsSwappedFile(t *testing.T)   // file replaced with another key's bytes: ErrKeyMismatch
func TestLoadRecoveryKeyHalfPairingIsNotPaired(t *testing.T) // key id set, threshold missing: ErrNotPaired
func TestParsePinRequest(t *testing.T)                     // whitespace inside base64 tolerated; wrong length, bad key, bad topology each refused
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/ -run 'RecoveryKey|PinRequest'`
Expected: FAIL, undefined symbols

- [ ] **Step 3: Write pin.go**

Copy `recoverykey.go` from kysignon with these edits, nothing else:
- `package kyrecovery`; drop the `store` import and the local `SettingsStore` type (use `Settings` from Task 1; `settings.GetSetting` → `s.Get`, `SetSetting` → `s.Set`, `store.ErrNotFound` → `ErrNotFound`).
- Rename `ErrRecoveryKeyMismatch` → `ErrKeyMismatch`. Error text prefix `backup:` → `kyrecovery:`. Move `ErrNotPaired` here from settings.go.
- Delete `intSetting` (it is in settings.go).
- Append:

```go
// ParsePinRequest turns the base64 public key from the ceremony page and its k-of-n into
// a RecoveryKey ready for StoreRecoveryKey. Whitespace inside the base64 is tolerated: the
// key is pasted from a browser.
func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(publicKeyB64), ""))
	if err != nil || len(raw) != recoverykey.PublicKeyBytes {
		return RecoveryKey{}, fmt.Errorf("kyrecovery: public_key must be the %d-byte suite recovery public key in base64", recoverykey.PublicKeyBytes)
	}
	pub, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, errors.New("kyrecovery: public_key is not a recovery public key")
	}
	if !validTopology(threshold, total) {
		return RecoveryKey{}, fmt.Errorf("kyrecovery: %d-of-%d is not a custodian topology", threshold, total)
	}
	return RecoveryKey{Public: pub, Threshold: threshold, TotalShares: total}, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./kyrecovery/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add kyrecovery/pin.go kyrecovery/pin_test.go
git commit -m "kyrecovery: recovery key pin, write-once, ParsePinRequest"
```

---

### Task 3: Client (`client.go`)

**Files:**
- Create: `kyrecovery/client.go`, `kyrecovery/client_test.go`, `kyrecovery/export_test.go`
- Source: `kysignon-server/internal/backup/client.go` lines 1–~330 (everything up to and excluding `Snapshotter`, `Payload`, `Members`, `CollectSealable`), `export_test.go`, and the client cases of `backup_test.go` (redirect refused, private refused by default, private admitted with the switch, loopback still refused with the switch, CGNAT, query/fragment refused, receipt digest/size/id mismatch refused, remote message bounded).

**Interfaces:**
- Produces: `type Options struct { AllowPrivate bool }`, `type Client struct`, `func NewClient(o Options) *Client`, `func ValidateURL(raw string, allowPrivate bool) error`, `type PairingResult struct { Key RecoveryKey; APIToken string; ServiceName string }` (keep kysignon's fields), `func (c *Client) ClaimPairing(ctx, serverURL, pairingCode, serviceName, appName string) (PairingResult, error)`, `type Receipt struct` (kysignon's fields, JSON tags unchanged), `type Depositor interface { Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error) }`, `func (c *Client) Deposit(...)`, `var ErrRemote`, `func AuditSafe(s string) string`.

- [ ] **Step 1: Port the client tests**

Copy the client cases into `client_test.go`, `package kyrecovery`, replacing `NewKyRecoveryClient(x)` with `NewClient(Options{AllowPrivate: x})` and `ValidateRecoveryURL` with `ValidateURL`. `export_test.go`:

```go
package kyrecovery

import "net/http"

func NewClientWithTransportForTest(rt http.RoundTripper, o Options) *Client {
	c := NewClient(o)
	c.http.Transport = rt
	return c
}
```

Required named tests: `TestClientRefusesRedirect`, `TestValidateURLRefusesPrivateByDefault`, `TestValidateURLAdmitsPrivateAndCGNATWithSwitch`, `TestValidateURLNeverAdmitsLoopbackLinkLocalMulticast`, `TestValidateURLRequiresHTTPS`, `TestValidateURLRefusesQueryAndFragment`, `TestDepositRefusesReceiptThatDoesNotDescribeBytesSent`, `TestRemoteMessageIsBounded`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/ -run 'Client|ValidateURL|Deposit|Remote'`
Expected: FAIL, undefined

- [ ] **Step 3: Write client.go**

Copy from kysignon with these edits:
- `package kyrecovery`; drop the `config` import. `KyRecoveryClient` → `Client`; `NewKyRecoveryClient(allowPrivate bool)` → `NewClient(o Options)` storing `o.AllowPrivate` in the struct field `allowPrivate`. `ValidateRecoveryURL` → `ValidateURL`.
- Keep `allowedIP`, `reservedRanges`, `cgnatRange` (named), `isPublicIP`, `refuseRedirect`, `endpoint`, `uploadTimeout = 15 * time.Minute`, `auditTextLimit = 200`, `remoteMessage`, `AuditSafe`, `ErrRemote`.
- `PairingResult.Key` is `RecoveryKey` (Task 2). Error text prefix `backup:` → `kyrecovery:`.
- Add the `Depositor` interface here (moved from kysignon `deposit.go`).
- Do not bring `Snapshotter`, `Payload`, `Members`, `CollectSealable`.

- [ ] **Step 4: Run tests**

Run: `go test ./kyrecovery/ && go test -run 'OnlyPassword' .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add kyrecovery/client.go kyrecovery/client_test.go kyrecovery/export_test.go
git commit -m "kyrecovery: KyRecovery client with private-destination opt-in"
```

---

### Task 4: Pairing record (`pairing.go`)

**Files:**
- Create: `kyrecovery/pairing.go`, `kyrecovery/pairing_test.go`
- Source: `kysignon-server/internal/backup/deposit.go` lines 1–160 (`StorePairing`, `ClearPairing`, `HasPairing`, `LoadPairing`, `notPaired`, `LastDeposit`) and their tests.

**Interfaces:**
- Produces: `type Pairing struct { URL, Token string; Key RecoveryKey }`, `var ErrKeyPinMissing`, `func StorePairing(s Settings, sealer Sealer, serverURL, token string) error`, `func ClearPairing(s Settings) error`, `func HasPairing(s Settings) bool`, `func LoadPairing(dataDir string, s Settings, sealer Sealer) (Pairing, error)`, `func LastDeposit(s Settings) (Receipt, bool, error)`, const keys `settingRecoveryURL = "kyrecovery_url"`, `settingRecoveryToken = "kyrecovery_token_enc"`, `settingLastDeposit = "kyrecovery_last_deposit"`.

- [ ] **Step 1: Port the tests**

Required: `TestStorePairingRefusesEmptyToken`, `TestHasPairingNeverDecrypts` (use a `Sealer` whose `Open` calls `t.Fatal`), `TestLoadPairingReportsKeyPinMissing` (pairing rows present, `recovery.pub` removed → `ErrKeyPinMissing`, not `ErrNotPaired`), `TestLoadPairingWrongSealerFails`, `TestClearPairingKeepsKeyPinAndReceipt`, `TestClearPairingHalfClearedStillClears` (only URL row present → cleared, nil error), `TestClearPairingNotPaired`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/ -run Pairing`
Expected: FAIL

- [ ] **Step 3: Write pairing.go**

Copy from kysignon with these edits:
- `StorePairing(s Settings, sealer Sealer, serverURL, token string)`: replace `crypto.EncryptAESGCM(crypto.DeriveKey(encryptionKey, recoveryTokenLabel), []byte(token))` with `sealer.Seal([]byte(token))`.
- `LoadPairing(dataDir string, s Settings, sealer Sealer)`: replace the decrypt with `sealer.Open(sealed)`; on error: `fmt.Errorf("kyrecovery: the stored KyRecovery token will not open under this deployment's key: %w", err)`.
- Drop `recoveryTokenLabel` (the product picks its label when it builds the Sealer; document in doc.go that kysignon uses `kysignon:setting:kyrecovery_token` and the scaffold uses `<module>:setting:kyrecovery_token`).
- `ErrRecoveryKeyMismatch` → `ErrKeyMismatch`. `store.ErrNotFound` → `ErrNotFound`.
- Keep `ClearPairing`'s doc comment verbatim (it is the contract text: rows removed, not scrubbed; credential dead only when KyRecovery revokes; key pin stays; half-cleared cleared).

- [ ] **Step 4: Run tests, commit**

Run: `go test ./kyrecovery/`
Expected: PASS

```bash
git add kyrecovery/pairing.go kyrecovery/pairing_test.go
git commit -m "kyrecovery: pairing record sealed at rest, ClearPairing, LastDeposit"
```

---

### Task 5: Payload, local copies, schedule

**Files:**
- Create: `kyrecovery/payload.go`, `kyrecovery/payload_test.go`, `kyrecovery/local.go`, `kyrecovery/local_test.go`, `kyrecovery/schedule.go`, `kyrecovery/schedule_test.go`
- Source: kysignon `capsule.go` (57 lines), `local.go` (102), `schedule.go` (83), and tests `TestPruneLeavesForeignCapsulesAlone`, the local-copy 0600/temp-rename test, `TestSetIntervalBoundsSeconds` (2^55 refused, 0 accepted, 15m-1s refused, 366d accepted), `TestNextRunCountsFromLastAttempt`.

**Interfaces:**
- Produces:
  - `type File struct { Path string; Data []byte; Mode int64 }`, `type Payload struct { ServiceName, AppVersion string; Files []File; Dependencies, VerificationRecipe map[string]any }`, `func Seal(p Payload, key RecoveryKey) ([]byte, capsule.Manifest, error)`, `func FilenameSafe(s string) string`, `var TooLargeMessage string`, `const MaxCapsuleFileBytes`, `MaxCapsuleTotalBytes`.
  - `type LocalCopy struct`, `func WriteLocalCopy(dir, appName, capsuleID string, raw []byte, keep int) (string, error)`, `func ListLocalCopies(dir, appName string) ([]LocalCopy, error)`.
  - `const MinInterval = 15 * time.Minute`, `const MaxInterval = 366 * 24 * time.Hour`, `var ErrBadInterval`, `func Interval(defaultInterval time.Duration, s Settings) (time.Duration, error)`, `func SetInterval(s Settings, sec int64) error`, `func NextRun(defaultInterval time.Duration, s Settings) (time.Time, bool, error)`, `func markAttempt(s Settings) error`.

- [ ] **Step 1: Port the tests**

Port each named test above into the matching `_test.go`. For `payload_test.go` add:

```go
func TestSealUsesPinnedTopology(t *testing.T) {
	k := testKey(t)
	raw, m, err := Seal(Payload{ServiceName: "svc", AppVersion: "1", Files: []File{{Path: "a", Data: []byte("x"), Mode: 0600}}}, k)
	if err != nil {
		t.Fatal(err)
	}
	if m.Threshold != 2 || m.TotalShares != 3 || m.ServiceName != "svc" || len(raw) == 0 {
		t.Fatalf("manifest %+v", m)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/ -run 'Seal|Local|Prune|Interval|NextRun'`
Expected: FAIL

- [ ] **Step 3: Write the three files**

`payload.go`: copy kysignon `capsule.go`; `BackupFile` → `File`; replace the loose-argument `Seal` with `Seal(p Payload, key RecoveryKey)` that calls `capsule.Seal(p.ServiceName, p.AppVersion, toCapsuleFiles(p.Files), p.Dependencies, p.VerificationRecipe, key.Threshold, key.TotalShares, key.Public)`. Add the `Payload` struct (fields above).

`local.go`: copy kysignon `local.go` verbatim, package name only.

`schedule.go`: copy kysignon `schedule.go`; replace `cfg *config.Config` with `defaultInterval time.Duration` in `Interval` and `NextRun`; `config.MinBackupDepositInterval` → `MinInterval` (declared here, `15 * time.Minute`); `store.ErrNotFound` → `ErrNotFound`. `ErrBadInterval` text: `"kyrecovery: interval must be 0 (off) or between 15m0s and 8784h0m0s"` built with `fmt.Errorf` from the constants as kysignon does.

- [ ] **Step 4: Run tests, commit**

Run: `go test ./kyrecovery/`
Expected: PASS

```bash
git add kyrecovery/payload.go kyrecovery/local.go kyrecovery/schedule.go kyrecovery/*_test.go
git commit -m "kyrecovery: payload seal, local copies with own-prefix prune, bounded schedule"
```

---

### Task 6: `Run` and `Outcome` (`run.go`)

**Files:**
- Create: `kyrecovery/run.go`, `kyrecovery/run_test.go`
- Source: kysignon `deposit.go` `RunBackup`, `Result`, `Outcome`, `ErrNoDestination`, `ErrDepositInProgress`, `depositMu`; tests `TestLocalFailureDoesNotCancelTheDeposit`, `TestRunNoDestinationIs412Shaped` (returns `ErrNoDestination` when key pinned, unpaired, no dir), `TestRunSingleFlight`, `TestRunReceiptMismatchIsRemote`, `TestOutcomeBoundsEveryField`.

**Interfaces:**
- Produces:

```go
type RunConfig struct {
	DataDir    string
	AppName    string // must equal Payload.ServiceName the collect func returns
	AppVersion string
	BackupDir  string // "" = no local destination
	Keep       int
	Sealer     Sealer // opens the stored KyRecovery token
}
type Result struct {
	Manifest   capsule.Manifest `json:"manifest"`
	SizeBytes  int              `json:"size_bytes"`
	LocalPath  string           `json:"local_path,omitempty"`
	LocalError string           `json:"local_error,omitempty"`
	Receipt    *Receipt         `json:"receipt,omitempty"`
}
var ErrNoDestination, ErrInProgress, ErrReceiptUnrecorded error
func Run(ctx context.Context, cfg RunConfig, s Settings, collect func() (Payload, error), client Depositor) (Result, error)
func Outcome(res Result, err error) (action, outcome string, details map[string]any)
```

- [ ] **Step 1: Port the tests**

Use `memSettings`, a `fakeDepositor` recording calls and returning a receipt whose `CapsuleID`/`Digest`/`SizeBytes` the test sets, and a `collect` returning a one-file payload. For the local-failure test set `BackupDir` to a path under a file (not a directory) so `WriteLocalCopy` fails, and assert the deposit still ran and `res.LocalError != ""`, `err == nil`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/ -run 'Run|Outcome'`
Expected: FAIL

- [ ] **Step 3: Write run.go**

Copy `RunBackup` as `Run` with these edits:
- `cfg.DataDir` → `cfg.DataDir`, `cfg.BackupDir`/`cfg.BackupKeep`/`cfg.AppName` → `RunConfig` fields, `cfg.EncryptionKey` → `cfg.Sealer`.
- `CollectSealable(cfg, snap, appVersion)` → `collect()`; then `if payload.ServiceName != cfg.AppName { return Result{}, fmt.Errorf("kyrecovery: payload names service %q, this instance is %q", ...) }` (KyRecovery pins the claimed name and refuses a mismatch; catch it before the upload).
- `Seal(payload.ServiceName, ...)` → `Seal(payload, key)`.
- `ErrDepositInProgress` → `ErrInProgress`, `depositMu` stays package-level.
- `ErrNoDestination` text: `"kyrecovery: no destination; pair with KyRecovery or set a backup directory"` (no product env var name in the lib).
- `Outcome` verbatim from kysignon (action `admin.backup_run`, every field through `AuditSafe`).

- [ ] **Step 4: Run tests, commit**

Run: `go test ./kyrecovery/`
Expected: PASS

```bash
git add kyrecovery/run.go kyrecovery/run_test.go
git commit -m "kyrecovery: Run seals once and delivers to every destination; Outcome"
```

---

### Task 7: `Drill` and `Restore`

**Files:**
- Create: `kyrecovery/drill.go`, `kyrecovery/drill_test.go`, `kyrecovery/restore.go`, `kyrecovery/restore_test.go`
- Source: kysignon `drill.go` lines 1–~110 (`RunRestoreDrill` up to and excluding the SQLite checks; `checkApplicationRecords`, `proveRestoreIsUsable`, `proveSecretDecryption` stay in kysignon as its `checks` func), `cmd/kysignon/main.go` `restore` and `readShares`, and `cmd/kysignon/restore_test.go` cases (wrong service refused before Combine, one share fails, non-empty target refused by `capsule.Open`).

**Interfaces:**
- Produces:

```go
type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}
type DrillResult struct {
	Passed       bool    `json:"passed"`
	Checks       []Check `json:"checks"`
	ErrorMessage string  `json:"error_message,omitempty"`
	DurationMs   int64   `json:"duration_ms"`
	SizeBytes    int     `json:"size_bytes"`
}
// Drill seals payload to a throwaway key generated and discarded inside this call, opens
// the capsule into a 0700 scratch directory wiped on return, and appends the product's
// checks. Checks that touch the plaintext get only the scratch directory path.
func Drill(ctx context.Context, payload Payload, checks func(dir string) []Check) (*DrillResult, error)
func ReadShares(r io.Reader) ([]string, error)
func Restore(capsulePath, targetDir, expectService string, shares []string, stdout io.Writer) error
```

- [ ] **Step 1: Write the tests**

```go
func TestDrillOpensWhatItSealedAndWipesScratch(t *testing.T) {
	var seen string
	res, err := Drill(context.Background(), Payload{ServiceName: "svc", AppVersion: "1",
		Files: []File{{Path: "db/app.db", Data: []byte("hello"), Mode: 0600}}},
		func(dir string) []Check {
			seen = dir
			b, err := os.ReadFile(filepath.Join(dir, "db", "app.db"))
			return []Check{{Name: "db", Passed: err == nil && string(b) == "hello"}}
		})
	if err != nil || !res.Passed {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := os.Stat(seen); !os.IsNotExist(err) {
		t.Fatalf("scratch dir %s survived", seen)
	}
}

func TestDrillFailsWhenAProductCheckFails(t *testing.T)   // checks returns one Passed:false → res.Passed false, err nil
func TestRestoreRefusesOtherServiceBeforeCombine(t *testing.T) // shares are garbage; error names the service, not the share
func TestRestoreNeedsThreshold(t *testing.T)                // 1 of 2-of-3 shares → error wraps shamir.ErrNotEnoughShares
func TestRestoreRoundTrip(t *testing.T)                     // split 2-of-3, seal, restore with 2 shares, file content back, manifest printed to stdout
func TestReadSharesSkipsBlankLines(t *testing.T)
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/ -run 'Drill|Restore|ReadShares'`
Expected: FAIL

- [ ] **Step 3: Write drill.go and restore.go**

`drill.go`: from kysignon `RunRestoreDrill` keep: timer, `recoverykey.Generate()` throwaway, `Seal(payload, RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3})`, `os.MkdirTemp("", "kyrecovery-drill-*")` + `os.Chmod(dir, 0700)` + `defer os.RemoveAll(dir)`, `capsule.Open(raw, priv, dir)`, the "Seal" and "Directory Unpack" checks, then `result.Checks = append(result.Checks, checks(dir)...)`, `result.Passed` = every check passed. Drop the `pinned RecoveryKey` parameter: the drill never uses the suite key, and the product reports pin status from `Status` instead. Drop the SQLite and env checks (product side).

`restore.go`: `restore` from `cmd/kysignon/main.go` verbatim as `Restore` (parameter `shareStrings []string` → `shares []string`), and `readShares` as `ReadShares`.

- [ ] **Step 4: Run tests, commit**

Run: `go test ./kyrecovery/`
Expected: PASS

```bash
git add kyrecovery/drill.go kyrecovery/restore.go kyrecovery/*_test.go
git commit -m "kyrecovery: Drill against a throwaway key, Restore from custodian shares"
```

---

### Task 8: `guardtest` and the package's own guard

**Files:**
- Create: `kyrecovery/guardtest/guardtest.go`, `kyrecovery/guardtest/guardtest_test.go`, `kyrecovery/nodecrypt_test.go`
- Source: kysignon `internal/backup/nodecrypt_test.go` (110 lines).

**Interfaces:**
- Produces: `func NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string)` where `allowed` maps a repo-relative file path to the function names inside it that may call a forbidden selector. Forbidden selectors: `capsule.Open`, `recoverykey.Combine`, `recoverykey.FromSeed`, `kyrecovery.Restore` (import aliases resolved). `kyrecovery.Drill` is not forbidden: it opens only a capsule sealed to a key it generated and dropped.

- [ ] **Step 1: Write the guardtest self-test**

```go
package guardtest_test

func TestGuardCatchesPlantedOpen(t *testing.T) {
	root := t.TempDir()
	// 11 innocent files clear the count floor; one caller plants capsule.Open outside the allowed func.
	for i := 0; i < 11; i++ {
		write(t, root, fmt.Sprintf("p%d/p.go", i), "package p\n")
	}
	write(t, root, "cmd/x/main.go", `package main
import "github.com/Busnes-app/ky-primitives/capsule"
func restore() { _ = capsule.Open }
func other()   { _ = capsule.Open }
`)
	rec := &recorder{}
	guardtest.NoDecryptOutside(rec, root, map[string][]string{"cmd/x/main.go": {"restore"}})
	if len(rec.errors) != 1 || !strings.Contains(rec.errors[0], "other") && !strings.Contains(rec.errors[0], "main.go:4") {
		t.Fatalf("expected exactly the planted call in other(), got %v", rec.errors)
	}
}

func TestGuardFailsOnRelativeRootOrTooFewFiles(t *testing.T) // relative root → Fatal; 3 files → Fatal("walked only 3")
```

`recorder` implements `testing.TB` by embedding `testing.TB` and overriding `Errorf`, `Fatalf`, `Fatal`, `Helper` to collect strings (Fatal panics with a sentinel the test recovers).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./kyrecovery/guardtest/`
Expected: FAIL, undefined

- [ ] **Step 3: Write guardtest.go**

Copy the body of kysignon's `TestNothingInTheServerDecrypts` into `NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string)` with these changes:
- `if !filepath.IsAbs(repoRoot) { t.Fatalf("guardtest: repo root must be absolute, got %q", repoRoot) }`.
- Watched imports: add `github.com/Busnes-app/ky-primitives/kyrecovery`; forbidden: `map[string]map[string]bool{"capsule": {"Open": true}, "recoverykey": {"Combine": true, "FromSeed": true}, "kyrecovery": {"Restore": true}}` keyed by the import's last path element, resolved through the file's alias table.
- Allowance check: `slices.Contains(allowed[rel], enclosing(sel.Pos()))`.
- Keep the skip list (`web`, `node_modules`, dot-dirs), `_test.go` skip, and `if seen < 10 { t.Fatalf(...) }`.

`kyrecovery/nodecrypt_test.go` runs the guard on the lib itself:

```go
func TestNothingOutsideRestoreAndDrillDecrypts(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("kyrecovery", "restore.go"): {"Restore"},
		filepath.Join("kyrecovery", "drill.go"):   {"Drill"},
		filepath.Join("cmd", "kyauditverify", "main.go"): {}, // none; listed so a future Open here is a deliberate edit
	})
}
```

Check what `cmd/` and `capsule/` legitimately call: `capsule.Open` is defined, not called, inside `capsule/`; `recoverykey.Combine` is defined inside `recoverykey/`. Definitions are `FuncDecl`, not `SelectorExpr`, so they do not trip the guard. If the walk finds another caller in the lib (run it and see), add it to the map with a one-line justification in the test.

- [ ] **Step 4: Prove it once by hand**

Add `_ = capsule.Open` inside `Seal` in `payload.go`, run `go test ./kyrecovery/ -run NothingOutside`, confirm it fails naming `payload.go`, remove the line, confirm it passes. Record the two outputs in the PR description.

- [ ] **Step 5: Run everything, commit**

Run: `go test ./... && go vet ./...`
Expected: PASS

```bash
git add kyrecovery/guardtest kyrecovery/nodecrypt_test.go
git commit -m "kyrecovery/guardtest: reusable decrypt-boundary guard"
```

---

### Task 9: README section, tag

**Files:**
- Modify: `README.md` (add a `## kyrecovery` section following the existing per-package pattern: rationale, usage snippet, invariants pinned by named tests)
- Modify: `go.mod` only if `go` directive is below 1.24 (it is 1.26.6; no change)

- [ ] **Step 1: Write the README section**

Rationale (one paragraph): four products carried divergent copies of the product-side backup code; an unscoped prune or a wrong key pin loses data, which is the admission bar. Usage snippet:

```go
settings := myStore{}                       // implements kyrecovery.Settings, maps not-found to kyrecovery.ErrNotFound
sealer, _ := kyrecovery.NewAESGCMSealer(cfg.EncryptionKey, "myapp:setting:kyrecovery_token")
client := kyrecovery.NewClient(kyrecovery.Options{AllowPrivate: cfg.AllowPrivateRecovery})
res, err := kyrecovery.Run(ctx, kyrecovery.RunConfig{
	DataDir: cfg.DataDir, AppName: cfg.AppName, AppVersion: version,
	BackupDir: cfg.BackupDir, Keep: cfg.BackupKeep, Sealer: sealer,
}, settings, collectPayload, client)
action, outcome, details := kyrecovery.Outcome(res, err)
```

Invariants list, each naming its test: own-prefix prune (`TestPruneLeavesForeignCapsulesAlone`), local failure carries (`TestLocalFailureDoesNotCancelTheDeposit`), interval bounded in seconds (`TestSetIntervalBoundsSeconds`), CGNAT/loopback rules (`TestValidateURLAdmitsPrivateAndCGNATWithSwitch`, `TestValidateURLNeverAdmitsLoopbackLinkLocalMulticast`), redirects (`TestClientRefusesRedirect`), receipt checked against bytes sent (`TestDepositRefusesReceiptThatDoesNotDescribeBytesSent`), half-cleared pairing (`TestClearPairingHalfClearedStillClears`), key pin missing reported (`TestLoadPairingReportsKeyPinMissing`), throwaway drill key and wiped scratch (`TestDrillOpensWhatItSealedAndWipesScratch`), guard proves itself (`TestGuardCatchesPlantedOpen`). What is not here: config, handlers, UI, audit, compose, docs.

- [ ] **Step 2: Run the whole module, commit, open the PR**

Run: `go test ./... && go vet ./... && gofmt -l .`
Expected: PASS, no gofmt output

```bash
git add README.md
git commit -m "docs: kyrecovery package"
```

Open the PR (`pull-request` skill), get CI green and a security review round, merge, then:

```bash
git tag v0.5.0 && git push origin v0.5.0
```

- [ ] **Step 3: Post to myslop** folder `ky-primitives-kyrecovery-package`: done, tag, and that product folders can proceed. Then execute `ky_server_base/docs/superpowers/plans/2026-09-04-scaffold-wires-kyrecovery.md`.

---

## Self-review notes

- Spec coverage: settings ✔ T1, pin ✔ T2, client ✔ T3, pairing ✔ T4, local/schedule/payload ✔ T5, run ✔ T6, drill/restore ✔ T7, guardtest ✔ T8, docs/tag ✔ T9. `kysignon` as first consumer (spec order step 2) is deliberately its own follow-up in `kysignon-server`, after the tag: kysignon supplies a `Sealer` wrapping its existing `crypto.DeriveKey` + `EncryptAESGCM` so its live pairing keeps decrypting.
- One deviation from the board post: the post named `derive` as the basis for `NewAESGCMSealer`; `derive` exposes only password-KDF helpers, so the sealer uses stdlib `crypto/hkdf`. Stdlib-only still holds.
- Type consistency: `RecoveryKey` (T2) is used by `PairingResult` (T3), `Pairing` (T4), `Seal` (T5), `Run` (T6). `Settings` (T1) everywhere. `Payload`/`File` (T5) in `Run` (T6) and `Drill` (T7). `Receipt`/`Depositor` (T3) in `Run` (T6).
