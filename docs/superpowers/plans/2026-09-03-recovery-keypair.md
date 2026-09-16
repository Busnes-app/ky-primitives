# Suite Recovery Keypair and kycap/3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-capsule random key with one suite-wide recovery keypair, so `capsule.Seal` encrypts to a public key and no product ever holds a secret that opens a backup.

**Architecture:** A new `recoverykey` package wraps Go 1.26's `crypto/hpke` X-Wing KEM: it generates the keypair, exposes the 32-byte seed as the only thing `shamir` ever splits, and fingerprints the public key. `capsule` moves to `kycap/3`: `Seal` takes a `recoverykey.PublicKey`, `Open` takes a `recoverykey.PrivateKey`, and the HPKE encapsulated key plus the key ID ride inside the authenticated manifest. `keyfile` gains `Store` so a product can persist a public key it was handed.

**Tech Stack:** Go 1.26.6 standard library only for every file this plan touches: `crypto/hpke`, `crypto/sha256`, `encoding/base64`, `encoding/hex`. No new dependencies. `testing` only.

**Spec:** `docs/superpowers/specs/2026-09-03-recovery-keypair-design.md`

## Global Constraints

- **Dependency budget: `golang.org/x/crypto` and the `golang.org/x/sys` it drags in, and nothing else.** `nodeps_test.go` enforces it. Nothing in this plan imports outside the standard library.
- **Go floor is 1.26.6** (`go.mod`). `crypto/hpke` is public API in `api/go1.26.txt`. CI runs `1.26.x` and `stable` on Linux and macOS.
- **HPKE suite is fixed:** KEM `hpke.MLKEM768X25519()` (X-Wing, id `0x647a`), KDF `hpke.HKDFSHA256()`, AEAD `hpke.AES256GCM()`. `info` is the bytes of `"kycap/3"`. `aad` is the manifest's exact bytes. Never use the single-shot `hpke.Seal`/`hpke.Open`: they take no AAD.
- **Sizes:** seed 32 bytes; public key 1216 bytes; encapsulated key 1120 bytes.
- **Golden vectors come from a published document, never from the implementation.** X-Wing: draft-ietf-hpke-pq via Go's `crypto/hpke/testdata/hpke-pq.json`. Key schedule and AEAD: the CFRG companion vectors to RFC 9180. Both are reproduced verbatim in this plan.
- **Any test that reconstructs a Shamir secret must use a non-consecutive index set.** `{1,2,3}` degenerates to XOR and passes in any field.
- **Nothing is in the wild.** `kycap/2` is retired unread. No compatibility reader. If a task seems to need one, stop: that is a decision for Yoshi.
- **Commit messages end with:** `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`
- **Work on a branch** named `feat/recovery-keypair`. The consumer compat workflows in gridlock-server will go red on merge; that is expected and recorded in the spec's Part 7.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `recoverykey/recoverykey.go` | `PrivateKey`, `PublicKey`, `Generate`, `FromSeed`, `ParsePublicKey`, `Seed`, `Public`, `Bytes`, `ID`, `HPKE` accessors |
| `recoverykey/shares.go` | `Split`, `Combine` over the seed |
| `recoverykey/recoverykey_test.go` | X-Wing vector pin, length refusals, round trip |
| `recoverykey/shares_test.go` | Non-consecutive combine, wrong set, wrong length |
| `recoverykey/testdata/xwing-vector.json` | `skRm`, `pkRm` from draft-ietf-hpke-pq |
| `capsule/hpke.go` | The fixed suite: `hpkeKDF`, `hpkeAEAD`, `hpkeInfo` |
| `capsule/hpke_vector_test.go` | CFRG vector through the suite `Open` uses |
| `capsule/keys_internal_test.go` | `testRecoveryKey(t)` for `package capsule` tests |
| `capsule/keys_test.go` | `testRecoveryKey(t)` for `package capsule_test` tests |
| `capsule/recovery_test.go` | Wrong key, AAD coverage of the two new fields, kycap/2 refusal |
| `testdata/capsules/kycap3.kycap`, `kycap3.seed` | The persisted fixture and the seed that opens it |
| `testdata/capsules/retired/kycap2.kycap` | The refused fixture |

**Modified:**

| File | Change |
|---|---|
| `capsule/container.go` | `KycapFileFormat = "kycap/3"`; `decryptPayload` takes a `recoverykey.PrivateKey`, compares key ID, runs HPKE |
| `capsule/manifest.go` | `RecoveryKeyID`, `EncapsulatedKey` on `UnverifiedManifest` |
| `capsule/seal.go` | `Seal(…, to recoverykey.PublicKey)`, HPKE sender, no returned key |
| `capsule/capsule.go` | `Open(raw, with, targetDir)`, `ErrWrongRecoveryKey` |
| `capsule/encoding.go` | Doc comment says kycap/3 |
| `capsule/*_test.go` (7 files) | Call sites moved to the new signatures |
| `capsule/fuzz_test.go` | Seed corpus and key |
| `testdata/capsules/README.md` | New fixture table |
| `keyfile/keyfile.go` | `Store`; `create` split into random-then-write |
| `keyfile/keyfile_test.go` | `Store` tests |
| `README.md` | `## capsule` rewritten, `## recoverykey` added, `kycap/2` retired |

---

### Task 1: recoverykey — keypair, seed, public key, fingerprint

**Files:**
- Create: `recoverykey/recoverykey.go`, `recoverykey/recoverykey_test.go`, `recoverykey/testdata/xwing-vector.json`

**Interfaces:**
- Consumes: `crypto/hpke` from the standard library.
- Produces:
  - `type PrivateKey struct{ seed [32]byte; key hpke.PrivateKey }`
  - `type PublicKey struct{ key hpke.PublicKey }`
  - `const SeedBytes = 32`, `const PublicKeyBytes = 1216`, `const EncapsulationBytes = 1120`
  - `var ErrSeedLength, ErrPublicKeyLength error`
  - `func Generate() (PrivateKey, error)`
  - `func FromSeed(seed []byte) (PrivateKey, error)`
  - `func ParsePublicKey(b []byte) (PublicKey, error)`
  - `func (k PrivateKey) Seed() []byte`, `func (k PrivateKey) Public() PublicKey`, `func (k PrivateKey) HPKE() hpke.PrivateKey`
  - `func (p PublicKey) Bytes() []byte`, `func (p PublicKey) ID() string`, `func (p PublicKey) HPKE() hpke.PublicKey`
  - `func KEM() hpke.KEM`

The `HPKE()` accessors exist because `capsule` needs the underlying keys and lives in another package. They return the interface values `crypto/hpke` already hands out; nothing secret leaks that a `PrivateKey` did not already hold.

- [ ] **Step 0: Branch**

```bash
git checkout master && git pull --ff-only && git checkout -b feat/recovery-keypair
```

- [ ] **Step 1: Write the vector file**

Create `recoverykey/testdata/xwing-vector.json`. The values are the `0x647a / 0x0001 / 0x0003` entry of draft-ietf-hpke-pq's test vectors, as shipped in Go's `crypto/hpke/testdata/hpke-pq.json`. `skRm` is the 32-byte seed the draft feeds to `DeserializePrivateKey`; `pkRm` is the 1216-byte public key it must produce.

```json
{
  "source": "draft-ietf-hpke-pq test vectors, KEM 0x647a (MLKEM768-X25519 / X-Wing), via Go crypto/hpke/testdata/hpke-pq.json",
  "skRm": "b3f98b03126a431ccecc62ae0f68e102c2d8e1cc7b21ba85d821d8e31761e0f8",
  "pkRm": "3c282de306815eb40990929aeee0839bb37a71a052a9e5242cf15f4c4aa366e5142da0bb8da49e83840972355000288edfacce195826d1da5fff509dc5694d8ae6590fa763bd7213ece64e74c82134e3b8bb571c841967e44a500c2acfc7c1aba59273a5bb326ef52aa43471a9ecb54ad5c12d19bc05797d59980ae788039c265978586bbf92ce4c4b9013f3853f501a0a7b834f4843324b9bd3a07ff7f954d97aadb7d8621c58c75bc47995d02a2f70cc3d2bc519a8606fc0c9eca0b30a998bd237297dbc0298b106dc00c2a541bdfa9a26c95ba67167acb81ac705f1952fd173e6e23331c56db6913305384d52c51ef7facb92c08024a69e26437e1c289f77d455d08a1500c4a703acb376f424d57234fccaae84b3ae8d000ea8b128c4e259b6a976ffe650a5d9063c83996cbb00b30220ae43170eda370d623f481b24e4692e07a10777ab703d4b4a73c71e7a33a6f52b2aae7a4423aa5b69f58480b7acb04a6dac780a345317b40b171ae0264fb057810bce9c6b5a58027e3ef851e02cce85718c396824e3986a35e12873ba1ee6ec4c2cf0a767234baa61367af5a85f443272fc1e8c338769b8c2b9f1c58859cf920a9c26f71da71a60abf1c3e1824775b12e9608c711938475801036281e8d45a06942ba1164573ee1077b7a40ec213fe79575556bcab9f6823cab8c23297d67897bbec17b4ba6752c8913d0b781b9932a6df03505e3aa25fb6f75c20286b08b375bced9613cad18cbd42ac4063827afe5680e3cacaa96ba8f6c523236ca69da4475999abf18a25a433c94792988945ddfbb8413d367d3ac1315705797aa74632704b936cc96e689969118fac11b4f4c927a66aa670b4d8147a23a42aa6a309dc5f204902726c7ea6f1c6231a262308148c2d2ac81123050188b44a80aa8153bc5915aa8c207b22895a8339549d281c014162200d63cb2015a265ac48f0a3c93b9c71e05986e780c18f38c8fc5734fb7b22f34cc851413a3d17090021eef6b7019b5b93012753b150ffec031a038602ff62ffc6713c290a33ef86dbce641d579aa92c5aa1b4a6520b921efbc3c95156b34658dd14a7cead366a351c7a173907bd403c0cbc9b562281ed3712a4b6233d60f09d80e38e67a01c1660bc02a31303560632db6c63bdbb0bdda46b4faa77ba4cabfdf0789185c295c40220f65689675882fcc452b802a4baa895ebc50a931178d442c857ccfd503b678864a83565fec19c7ab782484877144745fc7227d582237498916a03a4ada6321b62abda04674f39338078ac087b1a52b77781d5574d41a2d320802b9d9bda34c8e356a5725fbae10599b83b97114c6cefca08f8d04809b8a79f9f0a26f2b9007f501a81679f0104c67f244cf514067e04f1aac0c823a6e2cb9517d5722eb3a8326a7b23ed62266f04acca740adb142bac5ba66c5a6b122a3180b97ccd6cf9bfc77a639515bb861a5cbbcc7f53d19b0cd66a0b64df56a15a98bff77182b7751ecc703bc947f516279a3b566485931415c4a9264bd7fcc36f1c4a1e15c3c8c17cab12805d9f585f4cba9bd496805f04c2d930a8e25248c02a362f8a56109cf263a0591ec4bb8bc6604d30dec4c715106266968653686289d7ff82e53d504f85fae5d4f64210866450ad272b3e4849b83de72a2e3b9fcf15ff88bc7348a401a95215ca1b16cbbfe5e082dd66029e768dadf2e52e283ce5d"
}
```

- [ ] **Step 2: Confirm the vector against Go's copy, independently**

Run:

```bash
python3 -c "
import json,hashlib
go=json.load(open('$(go env GOROOT)/src/crypto/hpke/testdata/hpke-pq.json'))
v=[v for v in go if v['kem_id']==0x647a and v['kdf_id']==1 and v['aead_id']==3][0]
ours=json.load(open('recoverykey/testdata/xwing-vector.json'))
assert v['skRm']==ours['skRm'] and v['pkRm']==ours['pkRm'], 'vector mismatch'
print(len(bytes.fromhex(ours['pkRm'])), hashlib.sha256(bytes.fromhex(ours['pkRm'])).hexdigest())
"
```

Expected: `1216 120b60e0ae3c00c1c9def1c61aeb12de710bfa49646ae6f99a7e564b25ace493`

That hash is the expected `ID()` and it was computed here, from the vector's bytes, not by the package.

- [ ] **Step 3: Write the failing tests**

Create `recoverykey/recoverykey_test.go`:

```go
package recoverykey_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func loadVector(t *testing.T) (seed, pub []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/xwing-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ SkRm, PkRm string }
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, err = hex.DecodeString(v.SkRm)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = hex.DecodeString(v.PkRm)
	if err != nil {
		t.Fatal(err)
	}
	return seed, pub
}

// The draft's vector: this seed must produce exactly this public key. If it does not, the
// KEM is not X-Wing as published, whatever the constant is called.
func TestSeedDerivesThePublishedPublicKey(t *testing.T) {
	seed, wantPub := loadVector(t)
	k, err := recoverykey.FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed: %v", err)
	}
	if got := k.Public().Bytes(); !bytes.Equal(got, wantPub) {
		t.Fatalf("public key differs from the published vector (%d bytes)", len(got))
	}
	if got := k.Seed(); !bytes.Equal(got, seed) {
		t.Fatal("Seed() does not round-trip the seed it was built from")
	}
}

// Computed in Step 2 from the vector's bytes with sha256sum, not by this package.
func TestIDIsTheHexSHA256OfThePublicKey(t *testing.T) {
	seed, _ := loadVector(t)
	k, err := recoverykey.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	const want = "120b60e0ae3c00c1c9def1c61aeb12de710bfa49646ae6f99a7e564b25ace493"
	if got := k.Public().ID(); got != want {
		t.Fatalf("ID = %s, want %s", got, want)
	}
}

func TestParsePublicKeyRoundTrips(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p, err := recoverykey.ParsePublicKey(k.Public().Bytes())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if p.ID() != k.Public().ID() {
		t.Fatal("parsed public key has a different ID")
	}
}

func TestGenerateIsNotDeterministic(t *testing.T) {
	a, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Public().ID() == b.Public().ID() {
		t.Fatal("two Generate calls produced the same key")
	}
}

func TestFromSeedRefusesEveryLengthButThirtyTwo(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := recoverykey.FromSeed(make([]byte, n)); !errors.Is(err, recoverykey.ErrSeedLength) {
			t.Errorf("FromSeed(%d bytes) = %v, want ErrSeedLength", n, err)
		}
	}
}

func TestParsePublicKeyRefusesEveryLengthButTwelveSixteen(t *testing.T) {
	for _, n := range []int{0, 32, 1215, 1217} {
		if _, err := recoverykey.ParsePublicKey(make([]byte, n)); !errors.Is(err, recoverykey.ErrPublicKeyLength) {
			t.Errorf("ParsePublicKey(%d bytes) = %v, want ErrPublicKeyLength", n, err)
		}
	}
}

// Bytes and Seed return copies. A caller zeroing its copy must not zero the key.
func TestAccessorsReturnCopies(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := k.Seed()
	for i := range s {
		s[i] = 0
	}
	if bytes.Equal(k.Seed(), s) {
		t.Fatal("Seed() returned the internal buffer")
	}
	b := k.Public().Bytes()
	for i := range b {
		b[i] = 0
	}
	if bytes.Equal(k.Public().Bytes(), b) {
		t.Fatal("Bytes() returned the internal buffer")
	}
}
```

- [ ] **Step 4: Run and watch it fail**

Run: `go test ./recoverykey/ 2>&1 | head -5`
Expected: build failure, `no Go files` or `undefined: recoverykey`.

- [ ] **Step 5: Write `recoverykey/recoverykey.go`**

```go
// Package recoverykey is the suite's recovery keypair: the one public key every product
// seals its backups to, and the private key that exists only while it is being split into
// custodian shares and while a restore combines them.
//
// The KEM is X-Wing (ML-KEM-768 with X25519), through crypto/hpke. A backup is the artefact
// most likely to still matter when a recorded ciphertext is attacked, so the KEM is the
// one place this library pays for post-quantum security.
//
// Every crypto/hpke KEM rebuilds its private key from a 32-byte seed, and the seed is the
// only thing this package ever hands to shamir. Whatever the KEM, a custodian card carries
// 32 bytes.
package recoverykey

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// SeedBytes is the length of the private key seed, the thing that is split.
	SeedBytes = 32
	// PublicKeyBytes is an X-Wing public key: ML-KEM-768 encapsulation key plus X25519 point.
	PublicKeyBytes = 1184 + 32
	// EncapsulationBytes is an X-Wing encapsulated key: ML-KEM-768 ciphertext plus X25519 point.
	EncapsulationBytes = 1088 + 32
)

var (
	// ErrSeedLength reports a seed that is not exactly SeedBytes long.
	ErrSeedLength = errors.New("recoverykey: seed must be exactly 32 bytes")
	// ErrPublicKeyLength reports public key bytes that are not exactly PublicKeyBytes long.
	ErrPublicKeyLength = errors.New("recoverykey: public key must be exactly 1216 bytes")
)

// KEM is the one key encapsulation this package uses. Exported so a test can name it; there
// is no other reason to call it.
func KEM() hpke.KEM { return hpke.MLKEM768X25519() }

// PrivateKey is the recovery private key. It exists in memory during the ceremony that
// splits it and during a restore that combines it, and nowhere else.
type PrivateKey struct {
	seed [SeedBytes]byte
	key  hpke.PrivateKey
}

// PublicKey is what every product holds and seals to.
type PublicKey struct {
	key hpke.PublicKey
}

// Generate makes a fresh keypair.
func Generate() (PrivateKey, error) {
	k, err := KEM().GenerateKey()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	// A hybrid key made by GenerateKey carries its seed; Bytes returns it. Going through
	// FromSeed rather than storing k directly means there is one constructor.
	seed, err := k.Bytes()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	return FromSeed(seed)
}

// FromSeed rebuilds the private key from its 32-byte seed. It is what Combine hands back.
func FromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedBytes {
		return PrivateKey{}, fmt.Errorf("%w: got %d", ErrSeedLength, len(seed))
	}
	k, err := KEM().NewPrivateKey(seed)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	var p PrivateKey
	copy(p.seed[:], seed)
	p.key = k
	return p, nil
}

// ParsePublicKey reads the bytes keyfile.Load or a pairing message hands back.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != PublicKeyBytes {
		return PublicKey{}, fmt.Errorf("%w: got %d", ErrPublicKeyLength, len(b))
	}
	k, err := KEM().NewPublicKey(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	return PublicKey{key: k}, nil
}

// Seed returns a copy of the 32 bytes that are split into custodian shares. Nothing else
// about this key is ever split.
func (k PrivateKey) Seed() []byte { return bytes.Clone(k.seed[:]) }

// Public returns the matching public key.
func (k PrivateKey) Public() PublicKey { return PublicKey{key: k.key.PublicKey()} }

// HPKE exposes the underlying key for capsule.Open. It is the same value crypto/hpke
// returned; nothing here is more secret than the PrivateKey already was.
func (k PrivateKey) HPKE() hpke.PrivateKey { return k.key }

// Bytes returns a copy of the 1216-byte encoding, what keyfile.Store persists.
func (p PublicKey) Bytes() []byte { return bytes.Clone(p.key.Bytes()) }

// ID is the lowercase hex SHA-256 of Bytes. It is what a capsule names, what kyrecovery
// pins, and what a custodian writes on a card.
func (p PublicKey) ID() string {
	sum := sha256.Sum256(p.key.Bytes())
	return hex.EncodeToString(sum[:])
}

// HPKE exposes the underlying key for capsule.Seal.
func (p PublicKey) HPKE() hpke.PublicKey { return p.key }
```

- [ ] **Step 6: Run the tests**

Run: `go test -count=1 ./recoverykey/ -v 2>&1 | tail -20`
Expected: PASS, all seven. If `TestSeedDerivesThePublishedPublicKey` fails, stop: either the vector file was mistyped (re-run Step 2) or `crypto/hpke`'s X-Wing does not match the draft, and that is a finding to report, not something to work around.

- [ ] **Step 7: Check the dependency tests still pass**

Run: `go test -count=1 -run 'TestModuleDependenciesAreAllowlisted|TestOnlyPasswordImportsADependency' . -v 2>&1 | tail -4`
Expected: PASS for both.

- [ ] **Step 8: Commit**

```bash
git add recoverykey/
git commit -m "feat(recoverykey): the suite recovery keypair over X-Wing

One keypair for the suite, generated once, split once, and the public half
handed to every product. Every crypto/hpke KEM rebuilds from a 32-byte
seed, so the seed is the only thing that is ever split and the shares are
the same size whatever the KEM.

Pinned to the draft-ietf-hpke-pq X-Wing vector: this seed, this public key.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: recoverykey — Split and Combine over the seed

**Files:**
- Create: `recoverykey/shares.go`, `recoverykey/shares_test.go`

**Interfaces:**
- Consumes: `PrivateKey`, `FromSeed`, `ErrSeedLength` from Task 1; `shamir.Split(secret []byte, threshold, total int) ([]shamir.Share, error)` and `shamir.Combine(shares []shamir.Share) ([]byte, error)`.
- Produces:
  - `func Split(k PrivateKey, threshold, total int) ([]shamir.Share, error)`
  - `func Combine(shares []shamir.Share) (PrivateKey, error)`

- [ ] **Step 1: Write the failing tests**

Create `recoverykey/shares_test.go`:

```go
package recoverykey_test

import (
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky-primitives/shamir"
)

// Indices {1,3,5}, never {1,2,3}: consecutive indices make every Lagrange coefficient 1,
// the combine degenerates to XOR, and it agrees in any field. That is how the suite's
// 0x11d/0x11b split hid.
func TestNonConsecutiveSharesRebuildTheKey(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(k, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}
	got, err := recoverykey.Combine([]shamir.Share{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if got.Public().ID() != k.Public().ID() {
		t.Fatal("combined key has a different ID from the one that was split")
	}
}

// Shares from two different splits must be refused, not combined into a plausible key.
func TestSharesFromTwoSplitsAreRefused(t *testing.T) {
	a, _ := recoverykey.Generate()
	b, _ := recoverykey.Generate()
	sa, _ := recoverykey.Split(a, 2, 3)
	sb, _ := recoverykey.Split(b, 2, 3)
	if _, err := recoverykey.Combine([]shamir.Share{sa[0], sb[2]}); !errors.Is(err, shamir.ErrShareSet) {
		t.Fatalf("got %v, want ErrShareSet", err)
	}
}

// A share set that reconstructs something other than 32 bytes was never a recovery seed.
func TestCombineRefusesASecretThatIsNotASeed(t *testing.T) {
	shares, err := shamir.Split(make([]byte, 16), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverykey.Combine([]shamir.Share{shares[0], shares[2]}); !errors.Is(err, recoverykey.ErrSeedLength) {
		t.Fatalf("got %v, want ErrSeedLength", err)
	}
}

func TestSplitRefusesAnImpossibleKit(t *testing.T) {
	k, _ := recoverykey.Generate()
	if _, err := recoverykey.Split(k, 1, 3); err == nil {
		t.Fatal("Split accepted threshold 1")
	}
	if _, err := recoverykey.Split(k, 4, 3); err == nil {
		t.Fatal("Split accepted threshold above total")
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./recoverykey/ -run 'Shares|Combine|Split' 2>&1 | head -5`
Expected: FAIL, `undefined: recoverykey.Split`.

- [ ] **Step 3: Write `recoverykey/shares.go`**

```go
package recoverykey

import "github.com/Busnes-app/ky-primitives/shamir"

// Split divides the private key's seed into total custodian shares, any threshold of which
// rebuild it. It is thin over shamir.Split, and exists so that the thing being split is the
// seed by construction: splitting the wrong 32 bytes would fail at restore through the
// capsule's key ID check, and "fails at restore" is the failure this package exists to move
// earlier.
func Split(k PrivateKey, threshold, total int) ([]shamir.Share, error) {
	return shamir.Split(k.Seed(), threshold, total)
}

// Combine rebuilds the private key from custodian shares. shamir.Combine refuses shares
// from different splits, of different lengths, or fewer than their threshold; anything it
// lets through that is not 32 bytes was never a seed and fails FromSeed.
func Combine(shares []shamir.Share) (PrivateKey, error) {
	seed, err := shamir.Combine(shares)
	if err != nil {
		return PrivateKey{}, err
	}
	return FromSeed(seed)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test -count=1 ./recoverykey/ -v 2>&1 | tail -14`
Expected: PASS, eleven tests.

- [ ] **Step 5: Commit**

```bash
git add recoverykey/shares.go recoverykey/shares_test.go
git commit -m "feat(recoverykey): split and combine the seed

Thin over shamir, so the thing that is split is the seed by construction.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: capsule — the fixed HPKE suite, pinned to the CFRG vector

**Files:**
- Create: `capsule/hpke.go`, `capsule/hpke_vector_test.go`

**Interfaces:**
- Consumes: `crypto/hpke`.
- Produces (unexported, `package capsule`): `func hpkeKDF() hpke.KDF`, `func hpkeAEAD() hpke.AEAD`, `func hpkeInfo() []byte`. Tasks 4 and 5 call these; nothing else may name a KDF or AEAD.

This task pins the key schedule and AEAD `Open` will run, against a published vector, using the exact functions `Open` will call. The vector uses DHKEM(X25519) because no published vector pairs X-Wing with AES-256-GCM; the KEM is pinned separately in Task 1.

- [ ] **Step 1: Write the failing test**

Create `capsule/hpke_vector_test.go`. Values are the `mode 0 / 0x0020 / 0x0001 / 0x0002` entry of the CFRG's RFC 9180 companion vectors (`github.com/cfrg/draft-irtf-cfrg-hpke`, `test-vectors.json`), first encryption. `info` decodes to `Ode on a Grecian Urn`; `aad` to `Count-0`; `pt` to `Beauty is truth, truth beauty`.

```go
package capsule

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The CFRG companion vector for HKDF-SHA256 + AES-256-GCM, through the same hpkeKDF and
// hpkeAEAD that Open uses. If either function is ever changed to a different suite, this
// stops matching a document.
func TestHPKESuiteMatchesTheCFRGVector(t *testing.T) {
	const (
		info = "4f6465206f6e2061204772656369616e2055726e"
		skRm = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"
		pkRm = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c"
		enc  = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"
		aad  = "436f756e742d30"
		pt   = "4265617574792069732074727574682c20747275746820626561757479"
		ct   = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"
	)

	priv, err := ecdh.X25519().NewPrivateKey(mustHex(t, skRm))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), mustHex(t, pkRm)) {
		t.Fatal("vector's skRm does not produce its pkRm; the constants above are mistyped")
	}
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	r, err := hpke.NewRecipient(mustHex(t, enc), k, hpkeKDF(), hpkeAEAD(), mustHex(t, info))
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	got, err := r.Open(mustHex(t, aad), mustHex(t, ct))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, mustHex(t, pt)) {
		t.Fatalf("plaintext = %x, want %s", got, pt)
	}
}

func TestHPKEInfoIsTheContainerFormat(t *testing.T) {
	if string(hpkeInfo()) != KycapFileFormat {
		t.Fatalf("info = %q, want %q", hpkeInfo(), KycapFileFormat)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./capsule/ -run HPKE 2>&1 | head -5`
Expected: FAIL, `undefined: hpkeKDF`.

- [ ] **Step 3: Write `capsule/hpke.go`**

```go
package capsule

import "crypto/hpke"

// The HPKE suite is fixed. It is not negotiated in the container and there is no field
// that names it: a capsule is kycap/3, and kycap/3 is this suite.
//
// KEM: X-Wing, in recoverykey. KDF and AEAD: here, because Seal and Open are the only
// callers. info binds the container format into the key schedule so a ciphertext lifted
// into some future container fails without a format check having to remember to exist.
//
// The single-shot hpke.Seal and hpke.Open are never used: they take no AAD, and the
// manifest-as-AAD is the property that retired kycap/1.

func hpkeKDF() hpke.KDF   { return hpke.HKDFSHA256() }
func hpkeAEAD() hpke.AEAD { return hpke.AES256GCM() }
func hpkeInfo() []byte    { return []byte(KycapFileFormat) }
```

- [ ] **Step 4: Run the test**

Run: `go test -count=1 ./capsule/ -run HPKE -v 2>&1 | tail -6`
Expected: `TestHPKESuiteMatchesTheCFRGVector` PASS. `TestHPKEInfoIsTheContainerFormat` PASS with `KycapFileFormat` still `kycap/2` — Task 4 changes the constant and this test follows it.

- [ ] **Step 5: Commit**

```bash
git add capsule/hpke.go capsule/hpke_vector_test.go
git commit -m "feat(capsule): fix the HPKE suite and pin it to the CFRG vector

HKDF-SHA256 and AES-256-GCM, through the exact functions Open will call,
against the RFC 9180 companion vector. The KEM is pinned in recoverykey.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: capsule — Seal to a public key, Open with a private key

**Files:**
- Modify: `capsule/container.go`, `capsule/manifest.go`, `capsule/seal.go`, `capsule/capsule.go`, `capsule/encoding.go`
- Create: `capsule/keys_internal_test.go`, `capsule/keys_test.go`
- Modify (call sites only): `capsule/authenticated_test.go`, `capsule/filelist_test.go`, `capsule/fixtures_test.go`, `capsule/fuzz_test.go`, `capsule/manifest_test.go`, `capsule/review_test.go`, `capsule/seal_test.go`

**Interfaces:**
- Consumes: `recoverykey.PublicKey`, `recoverykey.PrivateKey`, `.HPKE()`, `.ID()`, `recoverykey.EncapsulationBytes` (Task 1); `hpkeKDF`, `hpkeAEAD`, `hpkeInfo` (Task 3).
- Produces:
  - `const KycapFileFormat = "kycap/3"`
  - `func Seal(serviceName, appVersion string, files []File, deps, recipe map[string]any, threshold, totalShares int, to recoverykey.PublicKey) (raw []byte, m Manifest, err error)`
  - `func Open(raw []byte, with recoverykey.PrivateKey, targetDir string) (Manifest, []File, error)`
  - `var ErrWrongRecoveryKey error`
  - `UnverifiedManifest.RecoveryKeyID string`, `UnverifiedManifest.EncapsulatedKey string`
  - Test helper `testRecoveryKey(t *testing.T) recoverykey.PrivateKey` in both test packages.

This is the breaking change. Every step until Step 9 leaves the package not compiling; that is expected. Do not commit between them.

- [ ] **Step 1: Write the test helpers**

Create `capsule/keys_internal_test.go`:

```go
package capsule

import (
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// testRecoveryKey is a fresh keypair per test. Generation is fast enough that sharing one
// across tests would only add a way for them to interfere.
func testRecoveryKey(t *testing.T) recoverykey.PrivateKey {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
```

Create `capsule/keys_test.go` with the same body under `package capsule_test`:

```go
package capsule_test

import (
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func testRecoveryKey(t *testing.T) recoverykey.PrivateKey {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
```

- [ ] **Step 2: Add the sentinel and change `Open` in `capsule/capsule.go`**

Add to the `var (...)` block, after `ErrDuplicatePath`:

```go
	// ErrWrongRecoveryKey reports a capsule sealed to a recovery key other than the one
	// Open was given. It is checked before any decapsulation, so a wrong kit fails cheaply
	// and by name.
	ErrWrongRecoveryKey = errors.New("capsule is sealed to a different recovery key")
```

Add `"github.com/Busnes-app/ky-primitives/recoverykey"` to the imports.

Replace `Open`'s doc comment and signature. The body is unchanged except the first line:

```go
// Open parses a kycap/3 container, decrypts it with the recovery private key, verifies the
// payload hash, and returns the authenticated manifest with the files. When targetDir is
// non-empty the files are also written there under the containment rules in extract.go;
// the directory must be empty or absent. When it is empty nothing is written and the files
// are returned in memory.
//
// The manifest is returned because a successful Open is the only proof it was not
// rewritten. Callers that want it without a key want ReadUnverifiedManifest, and should
// read that type's doc comment first.
//
// A capsule names the recovery key it was sealed to. Open compares that name with the key
// it was given before decapsulating anything, and fails with ErrWrongRecoveryKey on a
// mismatch — the custodians brought the wrong kit, and that is worth saying plainly.
func Open(raw []byte, with recoverykey.PrivateKey, targetDir string) (Manifest, []File, error) {
	m, payload, err := decryptPayload(raw, with)
```

Delete the paragraph of the old doc comment beginning `key is raw bytes, never a hex string` — there is no raw key any more.

- [ ] **Step 3: Add the two manifest fields in `capsule/manifest.go`**

In `UnverifiedManifest`, after `TotalShares int`, add:

```go
	// RecoveryKeyID names the recovery key this capsule is sealed to: recoverykey.PublicKey.ID().
	// Not secret — it is a hash of a public key — and in the clear on purpose, so kyrecovery
	// can display it and refuse a deposit sealed to a key it did not hand out, without
	// holding any key at all.
	RecoveryKeyID string `json:"recovery_key_id"`
	// EncapsulatedKey is the HPKE encapsulated key, standard base64 of 1120 bytes. Public by
	// construction. Inside the AAD like every other field, so swapping it fails the AEAD.
	EncapsulatedKey string `json:"encapsulated_key"`
```

Update the `Manifest` doc comment's last sentence, `Only a successful Open or Seal returns one.`, to stay as is — it is still true.

- [ ] **Step 4: Change the container in `capsule/container.go`**

Change the constant and its comment's first line:

```go
// KycapFileFormat identifies the one container this package reads and writes.
//
// It is kycap/3: kycap/2 with the payload sealed to the suite recovery public key through
// HPKE instead of a per-capsule symmetric key the caller had to protect and split. Three
// containers came before it and all are gone: kysignon-server's kycap/1 and
// kyrecovery-server's tar, which authenticated their ciphertext and left the manifest
// outside the AEAD — so capsule_id, service_name, threshold, total_shares and the
// verification recipe could all be rewritten by someone who never learned the key — and
// kycap/2, which fixed that and still handed back a raw key.
//
// Reading them was retired rather than kept: a reader that half-trusts a manifest cannot
// tell a caller which half, and nothing is in the wild.
const KycapFileFormat = "kycap/3"
```

Replace `decryptPayload` and delete `newGCM`:

```go
// decryptPayload parses the container, checks it names the key it was given, decrypts it
// under the manifest, and returns the authenticated manifest alongside the hash-verified
// gzipped tar payload.
func decryptPayload(raw []byte, with recoverykey.PrivateKey) (manifest, []byte, error) {
	cf, err := parseContainer(raw)
	if err != nil {
		return manifest{}, nil, err
	}
	var m manifest
	if err := json.Unmarshal(cf.Manifest, &m); err != nil {
		return manifest{}, nil, fmt.Errorf("%w: unreadable manifest: %v", ErrCorruptCapsule, err)
	}

	// Before any decapsulation. The manifest is not yet authenticated here, so this is a
	// courtesy to the operator holding the wrong kit, not a security check — the AEAD below
	// is the security check, and a forged ID that matches the wrong key still fails there.
	if m.RecoveryKeyID != with.Public().ID() {
		return manifest{}, nil, ErrWrongRecoveryKey
	}

	enc, err := base64.StdEncoding.DecodeString(m.EncapsulatedKey)
	if err != nil {
		return manifest{}, nil, fmt.Errorf("%w: encapsulated key is not standard base64: %v", ErrCorruptCapsule, err)
	}
	if len(enc) != recoverykey.EncapsulationBytes {
		return manifest{}, nil, fmt.Errorf("%w: encapsulated key is %d bytes, want %d", ErrCorruptCapsule, len(enc), recoverykey.EncapsulationBytes)
	}

	ct, err := DecodeCiphertext(cf.Ciphertext)
	if err != nil {
		return manifest{}, nil, err
	}

	recipient, err := hpke.NewRecipient(enc, with.HPKE(), hpkeKDF(), hpkeAEAD(), hpkeInfo())
	if err != nil {
		return manifest{}, nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	// The manifest is the additional authenticated data, so any edit to it fails here
	// rather than being handed to the caller as fact.
	payload, err := recipient.Open(cf.Manifest, ct)
	if err != nil {
		return manifest{}, nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	if err := verifyPayloadHash(payload, m.PayloadHash); err != nil {
		return manifest{}, nil, err
	}
	return m, payload, nil
}
```

Imports become:

```go
import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)
```

`crypto/aes` and `crypto/cipher` are no longer imported by this file.

Update `verifyPayloadHash`'s comment: replace `a wrong-but-valid key or a corrupt share reconstructs plaintext that decrypts without an AEAD error` with `the AEAD passes for a reason nobody predicted`. The function is unchanged.

- [ ] **Step 5: Change `Seal` in `capsule/seal.go`**

Replace the signature, the doc comment's last paragraph, and the key/nonce/GCM section:

```go
// Seal writes a kycap/3 container sealed to the suite recovery public key, and returns it
// with the manifest it sealed.
//
// The manifest is returned because Seal is the only place CapsuleID, CreatedAt and
// PayloadHash exist: they are minted here and have no other source. Returning only the
// bytes left a caller re-parsing its own output through ReadUnverifiedManifest to recover
// them — reaching for the keyless reader, whose doc comment says not to decide on what it
// returns, to read fields it had just authored. This value is a Manifest because it is the
// one that went into the AEAD, not one read back out of a container.
//
// Seal returns no key. The payload is sealed to a public key through HPKE, the shared
// secret exists only inside crypto/hpke for the duration of this call, and the only thing
// that opens the result is the recovery private key the custodians hold in shares. A
// product that calls Seal holds nothing afterwards that it did not hold before.
func Seal(serviceName, appVersion string, files []File, deps, recipe map[string]any, threshold, totalShares int, to recoverykey.PublicKey) (raw []byte, m Manifest, err error) {
	if len(files) == 0 {
		return nil, Manifest{}, fmt.Errorf("refusing to seal a capsule with no files")
	}
	if threshold < 2 || totalShares < threshold || totalShares > 255 {
		return nil, Manifest{}, fmt.Errorf("capsule: %d-of-%d is not a recoverable kit; need 2 <= threshold <= total <= 255", threshold, totalShares)
	}

	payload, entries, err := buildPayload(files)
	if err != nil {
		return nil, Manifest{}, err
	}

	// The encapsulated key is minted before the manifest because the manifest carries it,
	// and the manifest is the AAD for the seal that follows.
	enc, sender, err := hpke.NewSender(to.HPKE(), hpkeKDF(), hpkeAEAD(), hpkeInfo())
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("failed to encapsulate capsule key: %w", err)
	}

	sum := sha256.Sum256(payload)

	now := time.Now().UTC()
	sealedManifest := manifest{
		CapsuleID:          fmt.Sprintf("cap-%s-%d", serviceName, now.UnixNano()),
		ServiceName:        serviceName,
		AppVersion:         appVersion,
		CreatedAt:          now,
		PayloadHash:        hex.EncodeToString(sum[:]),
		Threshold:          threshold,
		TotalShares:        totalShares,
		RecoveryKeyID:      to.ID(),
		EncapsulatedKey:    base64.StdEncoding.EncodeToString(enc),
		Files:              entries,
		Dependencies:       deps,
		VerificationRecipe: recipe,
	}
```

Keep the existing `manifestBytes` marshal and the `maxManifestBytes` check exactly as they are (their comments still hold). Replace the line `sealed := gcm.Seal(nonce, nonce, payload, manifestBytes)` with:

```go
	sealed, err := sender.Seal(manifestBytes, payload)
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("failed to seal capsule: %w", err)
	}
```

Every remaining `return nil, nil, Manifest{}, err` in the function becomes `return nil, Manifest{}, err`, and the final return becomes:

```go
	return raw, Manifest{UnverifiedManifest: sealedManifest}, nil
```

Delete the `key = make([]byte, 32)` block, the `gcm, err := newGCM(key)` block, and the nonce block. Imports become:

```go
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)
```

`crypto/rand` leaves this file; nothing in it draws randomness any more.

- [ ] **Step 6: Update `capsule/encoding.go`'s doc comment**

Change `// DecodeCiphertext reads the ciphertext field of a kycap/2 container.` to `kycap/3`. Nothing else in the file changes.

- [ ] **Step 7: Build, and read the errors**

Run: `go build ./... && go vet ./capsule/ 2>&1 | head -40`
Expected: `go build` passes (no non-test code outside `capsule` calls `Seal` or `Open`; `cmd/kyauditverify` does not import `capsule`). `go vet` lists every test call site that no longer compiles. Those are the next step.

- [ ] **Step 8: Move every test call site to the new signatures**

Seven files. The rule is mechanical and the same everywhere:

1. At the top of any test that calls `Seal` or `Open`, add `priv := testRecoveryKey(t)`. In table-driven subtests, put it inside the `t.Run` closure where the calls happen.
2. `raw, key, m, err := Seal(a, b, files, d, r, k, n)` becomes `raw, m, err := Seal(a, b, files, d, r, k, n, priv.Public())`. Same for `capsule.Seal`. Where the key was discarded (`raw, _, _, err`), the result has one fewer blank.
3. `Open(raw, key, dir)` becomes `Open(raw, priv, dir)`. Same for `capsule.Open`.
4. `Open(raw, make([]byte, 32), "")` — a call with an arbitrary key on bytes that are not a capsule — becomes `Open(raw, priv, "")`.
5. Any test that flips a key byte to make a wrong key (`key[0] ^= 0xFF`) uses a second keypair instead: `wrong := testRecoveryKey(t)` and `Open(raw, wrong, "")`.

Specific sites that need more than the rule:

- `capsule/fixtures_test.go`: `loadFixture` currently reads a `.key` hex file into `[]byte`. Change it to read a `.seed` hex file and return `recoverykey.PrivateKey` via `recoverykey.FromSeed`. The glob stays `../testdata/capsules/*.kycap`. Task 6 writes the new fixture; until then this file's tests **fail at runtime** on the old `kycap2.kycap` (no `.seed` beside it), which is correct and expected. `TestOpenRejectsWrongKey` and `TestOpenRejectsWrongKeyWithoutErrCorruptCapsule` use a second keypair per rule 5; their doc comments say `AES-GCM authenticates` — leave that, HPKE's AEAD is AES-GCM. `TestOpenReportsAnUnreadableManifestAsErrCorruptCapsule`'s literal `"format":"kycap/2"` becomes `"kycap/3"`, otherwise it now fails at `parseContainer` with `ErrUnknownContainer` and proves nothing about the manifest.

  New `loadFixture`:

  ```go
  func loadFixture(t *testing.T, path string) (raw []byte, with recoverykey.PrivateKey) {
  	t.Helper()
  	raw, err := os.ReadFile(path)
  	if err != nil {
  		t.Fatal(err)
  	}
  	seedHex, err := os.ReadFile(strings.TrimSuffix(path, ".kycap") + ".seed")
  	if err != nil {
  		t.Fatal(err)
  	}
  	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
  	if err != nil {
  		t.Fatalf("fixture seed is not hex: %v", err)
  	}
  	with, err = recoverykey.FromSeed(seed)
  	if err != nil {
  		t.Fatalf("fixture seed does not rebuild a key: %v", err)
  	}
  	return raw, with
  }
  ```

  Add `"github.com/Busnes-app/ky-primitives/recoverykey"` to its imports.

- `capsule/fuzz_test.go`: generate one keypair before `f.Fuzz`:

  ```go
  	priv, err := recoverykey.Generate()
  	if err != nil {
  		f.Fatal(err)
  	}
  	f.Fuzz(func(t *testing.T, raw []byte) {
  		_, _, _ = Open(raw, priv, "")
  	})
  ```

  Change the seed corpus path to `../testdata/capsules/kycap3.kycap` and every `"kycap/2"` literal in the corpus to `"kycap/3"`. Keep the `"kycap/1"` entry. Add `"github.com/Busnes-app/ky-primitives/recoverykey"` to its imports.

- `capsule/authenticated_test.go`, `TestOpenRejectsATamperedManifest`: the edits table gains no rows here (Task 5 covers the new fields) but `priv := testRecoveryKey(t)` goes inside the `t.Run` closure, before `Seal`.

- `capsule/manifest_test.go`, `TestUnverifiedManifestIsRewritableWithoutTheKey`: it `Open`s a forged container with the sealing key and expects failure. Same key, `priv`, rule 3.

- `capsule/review_test.go`: thirteen sites, all covered by rules 1 to 3.

- `capsule/seal_test.go`, `capsule/filelist_test.go`: all covered by rules 1 to 3.

- [ ] **Step 9: Vet and run everything except the fixture tests**

Run: `go vet ./... && go test -count=1 ./capsule/ -skip 'TestOpensEveryPersistedCapsule|TestOpenRejectsWrongKey|TestOpenRejectsTamperedContainer' 2>&1 | tail -15`
Expected: `go vet` clean. Tests PASS. `TestHPKEInfoIsTheContainerFormat` now checks `kycap/3` and passes. The three skipped tests read the fixture that Task 6 writes.

Run: `go test -count=1 ./...  -skip 'TestOpensEveryPersistedCapsule|TestOpenRejectsWrongKey|TestOpenRejectsTamperedContainer' 2>&1 | tail -15`
Expected: every package `ok`.

- [ ] **Step 10: Confirm no data key is reachable**

Run: `grep -n "key \[\]byte\|key, \[\]byte\|\[\]byte, key\|newGCM\|crypto/aes\|crypto/cipher\|crypto/rand" capsule/*.go | grep -v _test.go`
Expected: no output. The only key-typed values in non-test code are `recoverykey.PublicKey` and `recoverykey.PrivateKey`.

- [ ] **Step 11: Commit**

```bash
git add capsule/
git commit -m "feat(capsule)!: seal to the suite recovery public key

Seal takes a recoverykey.PublicKey and returns no key. Open takes the
recovery private key the custodians rebuild from shares. The shared secret
exists only inside crypto/hpke for the duration of each call, so a product
that seals a backup holds nothing afterwards that opens it.

The encapsulated key and the recovery key ID ride in the manifest, inside
the AAD like every other field. Open compares the ID before decapsulating,
so the wrong kit fails cheaply and by name.

BREAKING CHANGE: kycap/2 is retired unread. Seal(..., to) returns
(raw, Manifest, error); Open(raw, with, dir).

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: capsule — the properties the new fields must have

**Files:**
- Create: `capsule/recovery_test.go`

**Interfaces:**
- Consumes: `Seal`, `Open`, `ErrWrongRecoveryKey`, `ErrUnknownContainer`, `ReadUnverifiedManifest`, `testRecoveryKey` (Task 4); `recoverykey.Generate`, `.Public().ID()` (Task 1).
- Produces: nothing new. This task exists so a reviewer can reject the properties independently of the signatures.

- [ ] **Step 1: Write the tests**

Create `capsule/recovery_test.go`:

```go
package capsule_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func sealOne(t *testing.T, to recoverykey.PublicKey) []byte {
	t.Helper()
	raw, _, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, to)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rewriteManifest re-encodes the plaintext manifest with one field replaced. The AAD is
// the manifest's exact bytes, so the result must fail Open whatever the field.
func rewriteManifest(t *testing.T, raw []byte, field string, value any) []byte {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc["manifest"], &m); err != nil {
		t.Fatal(err)
	}
	m[field] = value
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	doc["manifest"] = mb
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sameLengthEdit replaces one field value with another of exactly the same length, so the
// container's bytes change only where the value sits. Re-marshalling would reorder or
// respace the manifest and fail the AEAD for reasons unrelated to the field under test.
func sameLengthEdit(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	if len(from) != len(to) {
		t.Fatalf("edit changes length (%d -> %d), which would prove nothing", len(from), len(to))
	}
	if !bytes.Contains(raw, []byte(from)) {
		t.Fatalf("cannot tamper: %q is not in the container", from)
	}
	return bytes.Replace(raw, []byte(from), []byte(to), 1)
}

func TestSealedManifestNamesTheRecoveryKey(t *testing.T) {
	priv := testRecoveryKey(t)
	raw, m, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if m.RecoveryKeyID != priv.Public().ID() {
		t.Fatalf("sealed manifest names %q, want %q", m.RecoveryKeyID, priv.Public().ID())
	}
	opened, _, err := capsule.Open(raw, priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if opened.RecoveryKeyID != m.RecoveryKeyID || opened.EncapsulatedKey != m.EncapsulatedKey {
		t.Fatal("Open returned different key fields from the ones Seal reported")
	}
}

// The wrong kit fails by name, and before decapsulation: the encapsulated key here is
// garbage, which would produce a different error if decapsulation ran first.
func TestWrongRecoveryKeyFailsByNameBeforeDecapsulation(t *testing.T) {
	sealer := testRecoveryKey(t)
	wrong := testRecoveryKey(t)
	raw := rewriteManifest(t, sealOne(t, sealer.Public()), "encapsulated_key", "AAAA")

	_, _, err := capsule.Open(raw, wrong, "")
	if !errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatalf("got %v, want ErrWrongRecoveryKey", err)
	}
}

// The ID compare is a courtesy, not the security check. Forge the ID to match the wrong
// key and the AEAD is what refuses it — which proves the field is inside the AAD.
func TestForgedRecoveryKeyIDFailsAtTheAEAD(t *testing.T) {
	sealer := testRecoveryKey(t)
	wrong := testRecoveryKey(t)
	// Both IDs are 64 hex characters, so this changes exactly the field and nothing else.
	raw := sameLengthEdit(t, sealOne(t, sealer.Public()), sealer.Public().ID(), wrong.Public().ID())

	_, _, err := capsule.Open(raw, wrong, "")
	if err == nil {
		t.Fatal("a capsule opened under a key it was not sealed to")
	}
	if errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatal("the forged ID passed the compare, as intended, but then reported ErrWrongRecoveryKey")
	}
	if errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("reported as ErrCorruptCapsule, want the AEAD failure: %v", err)
	}
}

// Swapping in another valid encapsulated key must fail the AEAD, not decrypt to garbage.
func TestSwappedEncapsulatedKeyFailsAtTheAEAD(t *testing.T) {
	priv := testRecoveryKey(t)
	a := sealOne(t, priv.Public())
	b := sealOne(t, priv.Public())

	ua, err := capsule.ReadUnverifiedManifest(a)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := capsule.ReadUnverifiedManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	// Both encapsulations are 1120 bytes, so their base64 is the same length: only the
	// field changes.
	swapped := sameLengthEdit(t, a, ua.EncapsulatedKey, ub.EncapsulatedKey)

	if _, _, err := capsule.Open(swapped, priv, ""); err == nil {
		t.Fatal("a capsule opened with another capsule's encapsulated key")
	}
}

// The keyless reader believes a rewritten key ID. That is its nature, and it is why
// kyrecovery may display the ID but must pin it against what it handed out, not trust it.
func TestUnverifiedReaderBelievesARewrittenRecoveryKeyID(t *testing.T) {
	priv := testRecoveryKey(t)
	forged := rewriteManifest(t, sealOne(t, priv.Public()), "recovery_key_id", "0000")

	u, err := capsule.ReadUnverifiedManifest(forged)
	if err != nil {
		t.Fatal(err)
	}
	if u.RecoveryKeyID != "0000" {
		t.Fatalf("unverified read gave %q, want the forged 0000", u.RecoveryKeyID)
	}
	if _, _, err := capsule.Open(forged, priv, ""); err == nil {
		t.Fatal("Open accepted the forged ID")
	}
}

// A kycap/2 container is refused at the format check, before any key is looked at.
func TestKycap2IsRefusedAsUnknown(t *testing.T) {
	priv := testRecoveryKey(t)
	raw := bytes.Replace(sealOne(t, priv.Public()), []byte(`"format":"kycap/3"`), []byte(`"format":"kycap/2"`), 1)
	if !bytes.Contains(raw, []byte(`"kycap/2"`)) {
		t.Fatal("test setup: format field not found where expected")
	}
	if _, _, err := capsule.Open(raw, priv, ""); !errors.Is(err, capsule.ErrUnknownContainer) {
		t.Fatalf("got %v, want ErrUnknownContainer", err)
	}
}
```

- [ ] **Step 2: Run them**

Run: `go test -count=1 ./capsule/ -run 'RecoveryKey|Encapsulated|Kycap2|UnverifiedReaderBelieves' -v 2>&1 | tail -16`
Expected: all six PASS. If `TestForgedRecoveryKeyIDFailsAtTheAEAD` reports `ErrWrongRecoveryKey`, the compare in `decryptPayload` is reading the wrong side; if it reports `ErrCorruptCapsule`, the encapsulated-key length check fired, which means `rewriteManifest` disturbed that field — neither is acceptable, fix the test setup or the code, not the assertion.

- [ ] **Step 3: Commit**

```bash
git add capsule/recovery_test.go
git commit -m "test(capsule): the recovery key fields are authenticated and the wrong kit fails by name

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: fixtures — a kycap/3 capsule with its seed, and the retired kycap/2

**Files:**
- Create: `testdata/capsules/kycap3.kycap`, `testdata/capsules/kycap3.seed`, `capsule/fixture_write_test.go`
- Move: `testdata/capsules/kycap2.kycap` → `testdata/capsules/retired/kycap2.kycap`
- Delete: `testdata/capsules/kycap2.key`
- Modify: `testdata/capsules/README.md`, `capsule/fixtures_test.go`

**Interfaces:**
- Consumes: `Seal`, `Open`, `loadFixture` (Task 4); `recoverykey.Generate`, `.Seed()` (Task 1).
- Produces: the persisted fixture every future run opens, and one that every future run refuses.

- [ ] **Step 1: Write the fixture writer**

Create `capsule/fixture_write_test.go`. It runs only when asked, so a routine `go test` never rewrites the golden file:

```go
package capsule_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// TestWriteFixture writes testdata/capsules/kycap3.kycap and its seed. It is a no-op
// unless KY_WRITE_FIXTURE=1, because a fixture that rewrites itself proves nothing.
//
// Run it once when the container format changes deliberately, and commit the result. The
// seed is committed on purpose: a golden capsule whose key is withheld cannot prove that a
// capsule written before a change still opens after it.
func TestWriteFixture(t *testing.T) {
	if os.Getenv("KY_WRITE_FIXTURE") != "1" {
		t.Skip("set KY_WRITE_FIXTURE=1 to rewrite the golden capsule")
	}
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	files := []capsule.File{
		{Path: "config.json", Content: []byte(`{"service":"fixture","version":3}` + "\n"), Mode: 0600},
		{Path: "keys/signing.key", Content: []byte("not a real key, a fixture\n"), Mode: 0600},
	}
	raw, _, err := capsule.Seal("fixture", "0.0.0", files, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "testdata", "capsules")
	if err := os.WriteFile(filepath.Join(dir, "kycap3.kycap"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kycap3.seed"), []byte(hex.EncodeToString(priv.Seed())+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Retire the old fixture and write the new one**

```bash
mkdir -p testdata/capsules/retired
git mv testdata/capsules/kycap2.kycap testdata/capsules/retired/kycap2.kycap
git rm -q testdata/capsules/kycap2.key
KY_WRITE_FIXTURE=1 go test -count=1 ./capsule/ -run TestWriteFixture -v 2>&1 | tail -3
ls -la testdata/capsules/ testdata/capsules/retired/
```

Expected: `TestWriteFixture` PASS; `kycap3.kycap` and `kycap3.seed` exist; `retired/kycap2.kycap` exists; no `.key` file anywhere.

- [ ] **Step 3: Add the retired-fixture refusal to `capsule/fixtures_test.go`**

Append:

```go
// The kycap/2 capsule this package used to write is refused at the format check. It is
// kept so that refusal is measured against a real container, not a hand-typed one.
func TestRetiredKycap2FixtureIsRefused(t *testing.T) {
	raw, err := os.ReadFile("../testdata/capsules/retired/kycap2.kycap")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := capsule.Open(raw, testRecoveryKey(t), ""); !errors.Is(err, capsule.ErrUnknownContainer) {
		t.Fatalf("got %v, want ErrUnknownContainer", err)
	}
}
```

- [ ] **Step 4: Run the whole capsule suite, including the fixture tests**

Run: `go test -count=1 ./capsule/ 2>&1 | tail -5`
Expected: `ok`. `TestOpensEveryPersistedCapsule` opens `kycap3.kycap` with `kycap3.seed`; `TestOpenRejectsWrongKey` and friends run against it; `TestRetiredKycap2FixtureIsRefused` passes.

Run: `go test -count=1 ./capsule/ -run FuzzOpenNeverPanics -v 2>&1 | tail -3`
Expected: PASS on the seed corpus, which now includes `kycap3.kycap`.

- [ ] **Step 5: Rewrite `testdata/capsules/README.md`**

```markdown
# Capsule fixtures

A capsule written by this package, with the recovery seed that opens it:

| File | Container |
|---|---|
| `kycap3.kycap` | `kycap/3` — JSON manifest bound in as AAD, payload sealed to the suite recovery public key through HPKE (X-Wing / HKDF-SHA256 / AES-256-GCM) |
| `kycap3.seed` | The 32-byte recovery seed, hex. `recoverykey.FromSeed` rebuilds the private key. |

This seed protects fixture data and nothing else. It is committed on purpose: a golden
capsule whose key is withheld cannot prove that a capsule written before a change still
opens after it.

Regenerate with `KY_WRITE_FIXTURE=1 go test ./capsule/ -run TestWriteFixture`, and only
when the container format changes deliberately. A change that stops this opening is a
breaking change to every backup already on disk.

## Retired

`retired/kycap2.kycap` is the container this package wrote before `v0.4.0`. It
authenticated its manifest and still handed the caller a raw key to protect and split per
capsule. It is kept so that `Open`'s refusal is measured against a real container. Its key
is not kept; nothing reads it.

`kysignon.kycap` (`kycap/1`) and `kyrecovery.kycap` (a tar of `manifest.json`, `nonce.bin`
and `payload.enc`) were real output from `kysignon-server` and `kyrecovery-server`. Both
authenticated their ciphertext and left the manifest outside the AEAD, so `capsule_id`,
`service_name`, `threshold`, `total_shares` and the verification recipe could be rewritten
by anyone who could reach the file. Neither server needs its old capsules read.
```

- [ ] **Step 6: Run everything**

Run: `go test -race -count=1 ./... 2>&1 | tail -15`
Expected: every package `ok`.

- [ ] **Step 7: Commit**

```bash
git add testdata/capsules/ capsule/fixture_write_test.go capsule/fixtures_test.go
git commit -m "test(capsule): persist a kycap/3 fixture and refuse the retired kycap/2 one

The golden capsule now carries the recovery seed that opens it, for the
same reason the key was committed before. The kycap/2 capsule stays so the
refusal is measured against a real container.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: keyfile — Store a key that was handed to us

**Files:**
- Modify: `keyfile/keyfile.go`
- Test: `keyfile/keyfile_test.go`

**Interfaces:**
- Consumes: `create`, `writeAll`, `randRead`, `syncDir`, `Encoding.valid`, `Encoding.encode`, `minSize`, `mu` — all existing in `keyfile`.
- Produces: `func Store(path string, key []byte, enc Encoding) error`

A product must persist a public key it received at pairing. `create` is the only writer and it mints random bytes, so it is split: `create` draws the bytes, then calls the write path; `Store` calls the same write path with the caller's bytes. One temp-file, fsync, `os.Link`, directory-sync sequence, two entry points.

- [ ] **Step 1: Write the failing tests**

Append to `keyfile/keyfile_test.go`:

```go
func TestStoreWritesTheBytesItWasGiven(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "recovery.pub")
	want := bytes.Repeat([]byte{0xAB}, 1216)
	if err := Store(path, want, Raw); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := Load(path, 1216)
	if err == nil {
		t.Fatal("Load with Hex read a Raw file; the encodings must not read each other")
	}
	got, err = LoadEncoded(path, 1216, Raw)
	if err != nil {
		t.Fatalf("LoadEncoded: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Load returned different bytes from what Store wrote")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("stored file mode is %04o, want 0600", perm)
	}
}

// Replacing the public key file is the substitution attack: every later backup is sealed
// to whoever wrote it. Store must refuse, and the first key must survive the attempt.
func TestStoreRefusesToReplaceAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.pub")
	first := bytes.Repeat([]byte{0x01}, 32)
	second := bytes.Repeat([]byte{0x02}, 32)
	if err := Store(path, first, Raw); err != nil {
		t.Fatal(err)
	}
	if err := Store(path, second, Raw); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second Store gave %v, want ErrExist", err)
	}
	got, err := LoadEncoded(path, 32, Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatal("the first key was replaced")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries after a refused Store, want 1", len(entries))
	}
}

func TestStoreRefusesASillySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := Store(path, make([]byte, minSize-1), Raw); err == nil {
		t.Fatal("Store accepted a key below the floor")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused Store left a file behind")
	}
}

func TestStoreRefusesAnUnknownEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := Store(path, make([]byte, 32), Encoding(99)); err == nil {
		t.Fatal("Store accepted an unknown encoding")
	}
}

func TestStoreSurvivesAFailedWriteWithNoFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	original := writeAll
	boom := errors.New("no space left on device")
	writeAll = func(f *os.File, s string) error {
		_, _ = f.WriteString(s[:len(s)/2])
		return boom
	}
	t.Cleanup(func() { writeAll = original })

	if err := Store(path, make([]byte, 32), Raw); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the write error", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d entries left behind after a failed Store", len(entries))
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./keyfile/ -run TestStore 2>&1 | head -5`
Expected: FAIL, `undefined: Store`.

- [ ] **Step 3: Split `create` and add `Store`**

In `keyfile/keyfile.go`, replace `create` with two functions. `create` keeps its doc comment; the body of the old function from `dir := filepath.Dir(path)` to the end moves verbatim into `write`:

```go
// create writes a fresh key, failing if the path already exists.
//
// The key is written to a uniquely named temporary file in the same directory, fsynced,
// and only then linked to its final name. Writing straight to the final name meant a
// short write or a full disk left partial hex at the real path — and because this package
// refuses to replace an unreadable key, that partial file is permanent until someone
// deletes it by hand.
func create(path string, size int, enc Encoding) ([]byte, error) {
	key := make([]byte, size)
	if _, err := randRead(key); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if err := write(path, key, enc); err != nil {
		return nil, err
	}
	return key, nil
}

// write is the durable, non-replacing write path shared by create and Store.
func write(path string, key []byte, enc Encoding) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyfile-*.tmp")
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	tmpName := tmp.Name()
	// Removed on every failure path below; a no-op once the rename has consumed it.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// CreateTemp makes the file 0600 already; set it explicitly so the guarantee does not
	// depend on that staying true.
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if err := writeAll(tmp, string(enc.encode(key))); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	// Without the fsync a crash here leaves a zero-length file that the next boot reads
	// as a corrupt key, which is the failure the refusal above then reports forever.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}

	// os.Link rather than os.Rename: rename would silently replace a key another process
	// created while we were writing, and this package must never destroy a key.
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	// And without syncing the directory the name can be lost even though its contents
	// were durable.
	return syncDir(dir)
}
```

Check the existing `create`'s error-wrapping lines against what you moved: they must be byte-identical apart from `return nil, ` becoming `return `. `TestAFailedWriteLeavesNoKeyFileBehind` and `TestRngFailureIsAnErrorAndWritesNothing` hold this.

Add `Store` after `LoadEncoded`:

```go
// Store persists a key the caller already holds — a public key received at pairing — with
// the durability and permissions of LoadOrCreate, and refuses to replace a file that exists.
//
// The refusal is the point. Replacing a product's recovery public key is how every later
// backup gets sealed to whoever wrote the replacement; os.Link failing on an existing name
// is what makes that attack fail rather than succeed silently. Rotation, when it comes,
// gets a deliberate path, not an overwrite. The error satisfies errors.Is(err, fs.ErrExist).
func Store(path string, key []byte, enc Encoding) error {
	if len(key) < minSize {
		return fmt.Errorf("keyfile: key is %d bytes, below the %d-byte floor", len(key), minSize)
	}
	if !enc.valid() {
		return fmt.Errorf("keyfile: unknown encoding %d", int(enc))
	}

	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return write(path, key, enc)
}
```

- [ ] **Step 4: Run the keyfile suite**

Run: `go test -count=1 ./keyfile/ -v 2>&1 | grep -E "^(---|ok|FAIL)" | tail -30`
Expected: every test PASS, including the five new ones and the two pre-existing failure-path tests.

- [ ] **Step 5: Update the package doc's first line**

In `keyfile/keyfile.go`, change `// Package keyfile loads a long-lived secret from disk, creating it on first use.` to `// Package keyfile loads a long-lived key from disk, creating it on first use or storing one it was handed.`

- [ ] **Step 6: Commit**

```bash
git add keyfile/
git commit -m "feat(keyfile): Store a key the caller already holds

A product must persist the recovery public key it receives at pairing.
create was the only writer and it minted random bytes, so the write path is
split out and Store shares it. Store refuses to replace an existing file:
overwriting the public key is the substitution attack.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: README, retirement table, and the v0.4.0 release note

**Files:**
- Modify: `README.md` (`## capsule` section, lines 26–137 at time of writing; add `## recoverykey` before `## shamir`)

**Interfaces:**
- Consumes: every exported name from Tasks 1, 4 and 7.
- Produces: documentation only.

- [ ] **Step 1: Rewrite the top of `## capsule`**

Replace everything from `## capsule` down to, but not including, `### Extraction hardening` with:

```markdown
## capsule

Reads and writes the suite's encrypted backup container.

`kycap/3`: a JSON object holding the manifest, a base64 ciphertext, and nothing else. The
payload is sealed to the suite recovery public key through HPKE — X-Wing (ML-KEM-768 with
X25519), HKDF-SHA256, AES-256-GCM — so `Seal` returns no key and a product that seals a
backup holds nothing afterwards that opens it. The manifest is bound into the AEAD, so
every field describing the capsule is authenticated rather than merely present, and it is
carried and authenticated as the exact bytes that were read, not a re-encoding.

The manifest carries what identifies a capsule — `capsule_id`, `service_name`,
`created_at`, `payload_hash`, the recovery topology, and two fields that name the key:
`recovery_key_id` (the hex SHA-256 of the recovery public key) and `encapsulated_key` (the
HPKE encapsulation, 1120 bytes base64). Neither is secret; both are inside the AAD.
kyrecovery reads the key ID without any key to display it and to refuse a deposit sealed to
a key it did not hand out. The per-member list of paths, sizes and SHA-256 digests travels
inside the encrypted payload, as a reserved member, because the manifest is stored in the
clear and a per-member digest read without the key is an offline confirmation oracle.
`Open` fills `Manifest.Files` after the payload hash verifies; `ReadUnverifiedManifest`
returns none.

`Open` compares the manifest's `recovery_key_id` with the key it was given before
decapsulating anything, and fails with `ErrWrongRecoveryKey`: the custodians brought the
wrong kit. That compare is a courtesy on unauthenticated data; the AEAD is the check, and a
forged ID that matches the wrong key still fails there.

Three containers came before it and all are retired unread:

| Container | Was written by | Why it is gone |
|---|---|---|
| `kycap/1` | `kysignon-server` | Authenticated its ciphertext and nothing else |
| tar | `kyrecovery-server` | Authenticated its ciphertext and its own `aad` string, not the rest of the manifest |
| `kycap/2` | this package, before `v0.4.0` | Authenticated the manifest, then handed the caller a raw key to protect and split per capsule |

In the first two, `capsule_id`, `service_name`, `threshold`, `total_shares` and the
verification recipe were rewritable by anyone who could reach the file — a 2-of-3 kit
could be restated as 1-of-1 and still open. In the third, every backup was a fresh key and
so a fresh custodian ceremony, which no one runs nightly, so the key ended up stored next
to the data it protected. Nothing is in the wild, so none of the three is read.

`Seal` refuses a kit that cannot exist — `threshold` below 2, above `totalShares`, or a
total past 255 — because a manifest that records recovery topology without checking it
sends a custodian looking for shares that were never issued.

```go
raw, m, err := capsule.Seal(name, version, files, nil, nil, 2, 3, pub)  // pub: recoverykey.PublicKey
m, files, err := capsule.Open(raw, priv, "/var/restore")                // priv: recoverykey.PrivateKey
m, files, err := capsule.Open(raw, priv, "")                            // decode only, writes nothing
u, err := capsule.ReadUnverifiedManifest(raw)                           // no key; show, do not decide
```

`Open` returns the manifest because a successful `Open` is the only proof it was not
rewritten. `Seal` returns one too: `capsule_id`, `created_at`, `payload_hash` and
`encapsulated_key` are minted inside `Seal` and have no other source.
`ReadUnverifiedManifest` returns a different type, `UnverifiedManifest`, so the compiler
stops it reaching anything that decides on it.

`errors.Is` a failed `Open` against `ErrWrongRecoveryKey` for the wrong kit, against
`ErrUnknownContainer` for a retired or foreign format, and against `ErrCorruptCapsule` for
a malformed container; an AEAD failure wraps none of them.

The ciphertext field is standard base64 in and out.

```

- [ ] **Step 2: Fix the `### Fixtures` paragraph**

Replace the `### Fixtures` section body with:

```markdown
### Fixtures

`testdata/capsules/` holds one `kycap/3` capsule with the recovery seed that opens it, and
under `retired/` the last `kycap/2` capsule, kept so `Open`'s refusal is measured against a
real container. See the README there for why the seed is committed.
```

- [ ] **Step 3: Add `## recoverykey` before `## shamir`**

```markdown
## recoverykey

The suite's recovery keypair: one public key every product seals its backups to, and the
private key that exists only while it is being split into custodian shares and while a
restore combines them.

The KEM is X-Wing (ML-KEM-768 with X25519) through Go's `crypto/hpke`. A backup is the
artefact most likely to still matter when a recorded ciphertext is attacked, so this is
the one place the library pays for post-quantum security. Every `crypto/hpke` KEM rebuilds
its private key from a 32-byte seed, and the seed is the only thing this package hands to
`shamir`: a custodian card carries 32 bytes whatever the KEM.

```go
priv, err := recoverykey.Generate()                  // once, in kyrecovery's ceremony
shares, err := recoverykey.Split(priv, 3, 5)         // shamir shares of the seed; print, then zero priv
pub := priv.Public()                                 // hand pub.Bytes() to every product; pin pub.ID()

pub, err := recoverykey.ParsePublicKey(b)            // in a product, from keyfile.Load
priv, err := recoverykey.Combine(shares)             // at restore, from k custodian cards
```

`Generate` is called on exactly one host, once, and that host holds the seed in memory
until `Split` returns. That is the one place in the suite the recovery private key exists
outside custodian cards; the ceremony code must zero it and must never log or persist it.

`ID()` is the hex SHA-256 of the public key. It is what a capsule names, what kyrecovery
pins per product, and what a custodian writes on a card. `FromSeed` refuses any length but
32; `ParsePublicKey` refuses any length but 1216. Pinned to the draft-ietf-hpke-pq X-Wing
vector: that seed produces that public key, or the package is not X-Wing.

```

- [ ] **Step 4: Add `Store` to `## keyfile`**

Find the `## keyfile` section's usage block and add one line to it, and one paragraph after:

```go
err := keyfile.Store(path, pub.Bytes(), keyfile.Raw)  // a key the caller was handed; never overwrites
```

```markdown
`Store` persists a key the caller already holds — the recovery public key received at
pairing — and refuses to replace an existing file, with `errors.Is(err, fs.ErrExist)`.
Replacing a product's recovery public key is how every later backup gets sealed to whoever
wrote the replacement.
```

- [ ] **Step 5: Check the README against the code**

Run: `go doc ./capsule Seal && go doc ./capsule Open && go doc ./recoverykey && go doc ./keyfile Store`
Expected: each signature printed matches the README's usage lines exactly in parameter order and count.

Run: `grep -n "kycap/2" README.md`
Expected: only the retirement table row and the `v0.3.0` history sentence, if it was kept. Any other mention is stale; fix it.

- [ ] **Step 6: Full suite, race detector, vet**

Run: `go build ./... && go vet ./... && go test -race -count=1 ./... 2>&1 | tail -15`
Expected: every package `ok`.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs: kycap/3, recoverykey, and keyfile.Store

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

- [ ] **Step 8: Open the pull request and stop**

```bash
git push -u origin feat/recovery-keypair
gh pr create --title "Seal capsules to the suite recovery public key (kycap/3)" --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-09-03-recovery-keypair-design.md.

- New `recoverykey`: the suite keypair over X-Wing via Go 1.26 `crypto/hpke`; 32-byte seed is the only thing shamir splits.
- `capsule` -> kycap/3: `Seal(..., to)` returns no key; `Open(raw, with, dir)`; `recovery_key_id` and `encapsulated_key` inside the AAD; `ErrWrongRecoveryKey` before decapsulation.
- `keyfile.Store` for a key the caller was handed; refuses to overwrite.
- Golden vectors: X-Wing seed->pk from draft-ietf-hpke-pq; HKDF-SHA256 + AES-256-GCM from the CFRG RFC 9180 companion vectors.

BREAKING: kycap/2 retired unread. gridlock-server's compat workflow goes red until Plan 3 re-forks it; expected per spec Part 7.

Tag v0.4.0 after merge.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Then stop.** `v0.4.0` is tagged on `master` after the pull request merges, by whoever merges it:

```bash
git checkout master && git pull && git tag -a v0.4.0 -m "v0.4.0 — capsules seal to the suite recovery public key; kycap/2 retired" && git push origin v0.4.0
```

---

## What this plan does not cover

- **Plan 2, streaming.** Inherits the manifest fields and replaces `baseNonce` with an `hpke.Sender`/`hpke.Recipient` per stream. Written after this lands.
- **Plan 3, gridlock.** Moves `internal/backup` to `Seal(…, to)` and `Open(raw, with, …)`, and receives the public key at pairing.
- **Plan 5, kyrecovery.** The ceremony (`Generate`, `Split`, zero the seed, never persist), the key ID pin, the deposit-time refusal, and the share relay.
- **Rotation.** No reason to rotate exists yet.
