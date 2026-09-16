# ky-primitives Library Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ky-primitives` a library its consumers can adopt without local workarounds, and make any future breaking change fail in the pull request that causes it.

**Architecture:** Three movements. First, a downstream CI job that builds and tests every consumer against the pull request's checkout — so the rest of the work is watched. Second, close the API gaps that force callers to work around the library (gridlock already re-unmarshals sealed capsule bytes by hand because the manifest type is unexported). Third, unstick the three consumers that are pinned behind the last breaking change, and tag `v0.2.0`.

**Tech Stack:** Go 1.26.6, standard library plus `golang.org/x/crypto`. GitHub Actions. No test framework beyond `testing`.

**Spec:** `docs/superpowers/specs/2026-09-02-suite-migration-design.md`

## Global Constraints

- **Dependency budget: `golang.org/x/crypto` and the `golang.org/x/sys` it drags in, and nothing else.** `nodeps_test.go` enforces this — `TestModuleDependenciesAreAllowlisted` fails on any `require` outside the budget, `TestOnlyPasswordImportsADependency` fails if any package but `password` imports one. Do not add a dependency to make a task easier.
- **Every package except `password` is standard-library-only.** New code in `capsule`, `auditchain`, `keyfile`, `derive`, `shamir`, `totp`, `recoverycode` must not import `x/crypto`.
- **Go floor is 1.26.6** (`go.mod`). CI also runs `stable` and macOS; `keyfile`'s fsync and permission handling and `capsule`'s mode clamping are the parts that diverge from Linux.
- **Golden vectors are derived by hand or from a published document, never read off the implementation.** This is how the 0x11d/0x11b field split was caught.
- **Any test touching Shamir share reconstruction must use a non-consecutive index set.** Indices `{1,2,3}` make every Lagrange coefficient 1, the combine degenerates to XOR, and it passes in any field.
- **Nothing is in the wild.** No compatibility shims, no dual-format readers, no data migrations. If a task seems to need one, stop — the assumption has broken and that is a decision for Yoshi, not a workaround.
- **Commit messages end with:** `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `.github/workflows/downstream.yml` | Build and test each consumer against this checkout |
| `capsule/manifest.go` | `UnverifiedManifest`, `Manifest`, `ReadUnverifiedManifest` |
| `capsule/manifest_test.go` | Manifest reading, and that unverified cannot pass as verified |
| `capsule/stream.go` | Streaming container for payloads too large to hold in memory |
| `capsule/stream_test.go` | Streaming round-trip, chunk tampering, size limits |
| `auditchain/verify_record.go` | `VerifyRecord`, `Replay` |
| `auditchain/verify_record_test.go` | Digest-only verification and bulk replay |
| `keyfile/encoding.go` | `Encoding`, encoded load variants, read-only `Load`, `FromEnv` |
| `keyfile/encoding_test.go` | Each encoding, the read-only refusal, env validation |

**Modified:**

| File | Change |
|---|---|
| `capsule/capsule.go:45-47` | `Open` returns the verified `Manifest` alongside the files |
| `capsule/container.go:37-48` | `manifest` gains `Files []FileEntry`; typed `Dependencies` |
| `password/password.go` | `HashWith`, `DummyVerify`, `NeedsRehash` on a foreign format |
| `keyfile/keyfile.go` | `LoadOrCreate` delegates to the encoded variant |
| `derive/derive.go` | `AuthSecretContext`; export the concurrency budget |
| `README.md` | Correct the kybookmarks literal; document the new API |

---

## Task 1: Downstream CI

> **Superseded — do not implement as written.** `.github/workflows/downstream.yml` was
> built, then removed. It required a `SUITE_READ_TOKEN` with organisation read access to
> reach the private consumer, that secret was never created, and the job was the only
> failing check on PR #8. The check now lives in each consumer as
> `.github/workflows/ky-primitives-compat.yml`, cloning this public repository with no
> secret at all. `SUITE_READ_TOKEN` is not needed and should not be created. See
> `README.md` under `## Contributing`. The rest of this task is kept as a record only.


**Files:**
- Create: `.github/workflows/downstream.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: a required check named `downstream` that later tasks rely on to catch breakage. The consumer list in this file is the migration's progress bar — every later product phase adds one entry.

**Why this is first.** `ci.yml` builds and tests ky-primitives alone. Nothing anywhere builds a consumer against it, which is why gridlock sat 16 commits behind on a changed wire format while every check stayed green, and why kybookmarks and kypassword are running the pre-hardening `Append` today.

**The branch-pairing rule matters.** A breaking library change will fail every consumer until that consumer is updated, and the two live in different repositories, so no single commit can fix both. The job therefore looks for a branch in the consumer repo with the **same name as the pull request's head branch**, and falls back to the consumer's default branch. A coordinated change is then: open `feat/capsule-manifest` in ky-primitives *and* in the consumer, and the job pairs them.

- [ ] **Step 1: Confirm the starting state — gridlock is green, the other two are not**

```bash
cd /tmp && rm -rf dsprobe && mkdir dsprobe && cd dsprobe
for r in gridlock-server kybookmarks-server kypassword-server; do
  cp -r "/home/yoshi/busness.app/$r" "$r"
  ( cd "$r" \
    && go mod edit -replace github.com/Busnes-app/ky-primitives=/home/yoshi/busness.app/ky-primitives \
    && echo "=== $r ===" \
    && go build ./... 2>&1 | head -5 )
done
```

Expected: `gridlock-server` prints nothing (builds clean). `kybookmarks-server` and `kypassword-server` each print `not enough arguments in call to auditchain.Resume`. This is the state the job must report.

- [ ] **Step 2: Write the workflow**

```yaml
name: Downstream

on:
  pull_request:
  push:
    branches: [master]

permissions:
  contents: read

jobs:
  downstream:
    # A library whose consumers nobody builds will break them again. This job is the
    # only thing standing between a breaking change and a product that finds out
    # months later. The list grows by one entry as each product phase lands.
    strategy:
      fail-fast: false
      matrix:
        consumer:
          - gridlock-server
    runs-on: ubuntu-latest
    steps:
      - name: Check out ky-primitives
        uses: actions/checkout@v4
        with:
          path: ky-primitives

      - name: Check out ${{ matrix.consumer }}
        # A breaking change cannot be fixed in one commit across two repositories.
        # Prefer a consumer branch named like this PR's head branch so a coordinated
        # change can be tested as a pair; otherwise use the consumer's default branch.
        env:
          GH_TOKEN: ${{ secrets.SUITE_READ_TOKEN }}
          HEAD_REF: ${{ github.head_ref }}
        run: |
          set -euo pipefail
          repo="https://x-access-token:${GH_TOKEN}@github.com/Busnes-app/${{ matrix.consumer }}.git"
          if [ -n "${HEAD_REF}" ] && git ls-remote --exit-code --heads "${repo}" "${HEAD_REF}" >/dev/null 2>&1; then
            echo "Pairing with ${{ matrix.consumer }} branch ${HEAD_REF}"
            git clone --depth 1 --branch "${HEAD_REF}" "${repo}" "${{ matrix.consumer }}"
          else
            echo "Using ${{ matrix.consumer }} default branch"
            git clone --depth 1 "${repo}" "${{ matrix.consumer }}"
          fi

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.x'

      - name: Point the consumer at this checkout
        working-directory: ${{ matrix.consumer }}
        run: go mod edit -replace github.com/Busnes-app/ky-primitives=../ky-primitives

      - name: Build
        working-directory: ${{ matrix.consumer }}
        run: go build ./...

      - name: Test
        working-directory: ${{ matrix.consumer }}
        run: go test -count=1 ./...
```

- [ ] **Step 3: Verify the workflow parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/downstream.yml')); print('valid')"`
Expected: `valid`

- [ ] **Step 4: Record the credential requirement**

This job needs `secrets.SUITE_READ_TOKEN` — a token with `contents: read` on the `Busnes-app` organisation. **It is the one step in the whole plan gated on something outside the code.** If the repos are public, delete the `x-access-token:${GH_TOKEN}@` prefix and the `GH_TOKEN` env entry.

Add to `README.md` under a new `## Contributing` heading:

```markdown
## Contributing

`.github/workflows/downstream.yml` builds and tests every consumer against your pull
request. A breaking change fails there, in your PR, rather than months later in a product
nobody rebuilt.

To land a change that breaks a consumer, open a branch with the same name in the consumer
repository. The job pairs them by branch name and tests the two together.

The job needs a `SUITE_READ_TOKEN` secret with `contents: read` on the organisation.
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/downstream.yml README.md
git commit -m "ci: build every consumer against the pull request

gridlock sat sixteen commits behind on a changed share format while every
check stayed green, because nothing anywhere builds a consumer against this
library. Pairs by branch name so a breaking change can be landed across two
repositories at once.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: capsule — read a manifest without the key

**Files:**
- Create: `capsule/manifest.go`, `capsule/manifest_test.go`
- Modify: `capsule/container.go:37-48`

**Interfaces:**
- Consumes: `manifest` and `kycapFile` from `capsule/container.go`.
- Produces:
  - `type UnverifiedManifest struct { CapsuleID, ServiceName, AppVersion string; CreatedAt time.Time; PayloadHash string; Threshold, TotalShares int; Dependencies, VerificationRecipe any }`
  - `type Manifest struct { UnverifiedManifest }`
  - `func ReadUnverifiedManifest(raw []byte) (UnverifiedManifest, error)`

**The security point, which is the whole reason for two types.** The manifest is bound into the AEAD precisely so that `capsule_id`, `threshold`, `total_shares` and the verification recipe cannot be rewritten by anyone who reaches the file without the key — that is what `kycap/1` got wrong and what retiring it fixed. A function that reads the manifest *without* a key hands back exactly those unauthenticated fields. So it returns a **different type**, and Go's type checker stops an `UnverifiedManifest` from reaching anything expecting a `Manifest`. Display it, do not decide on it.

kyrecovery has six keyless manifest reads driving TUI quorum display, `diff.CompareManifests` and drill path selection. The first is fine. The third is not, and the type is how that gets caught in review.

- [ ] **Step 1: Write the failing test**

Create `capsule/manifest_test.go`:

```go
package capsule_test

import (
	"encoding/json"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
)

func TestReadUnverifiedManifestNeedsNoKey(t *testing.T) {
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, _, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatalf("ReadUnverifiedManifest: %v", err)
	}
	if got.ServiceName != "kyrecovery" {
		t.Errorf("ServiceName = %q, want %q", got.ServiceName, "kyrecovery")
	}
	if got.AppVersion != "2.1" {
		t.Errorf("AppVersion = %q, want %q", got.AppVersion, "2.1")
	}
	if got.Threshold != 3 || got.TotalShares != 5 {
		t.Errorf("kit = %d-of-%d, want 3-of-5", got.Threshold, got.TotalShares)
	}
	if got.CapsuleID == "" {
		t.Error("CapsuleID is empty")
	}
}

```

The companion test — that `Open` refuses a manifest rewritten this way — lives in Task 3,
because refusing it is Task 3's deliverable and this task must not commit a failing test.

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./capsule/ -run TestReadUnverifiedManifest -v`
Expected: FAIL — `undefined: capsule.ReadUnverifiedManifest`

- [ ] **Step 3: Write `capsule/manifest.go`**

```go
package capsule

import (
	"encoding/json"
	"fmt"
	"time"
)

// UnverifiedManifest is a capsule's manifest read without its key.
//
// Every field here is attacker-controlled wherever the capsule file is. The manifest is
// bound into the AEAD exactly so that threshold, total_shares and the verification recipe
// cannot be rewritten by whoever reaches the file — that is what kycap/1 got wrong, where
// a 2-of-3 kit could be restated as 1-of-1 and still open. Reading it without the key
// gives that guarantee up.
//
// So it is a distinct type from Manifest, and the compiler is what keeps the two apart.
// Show these fields to an operator if you must; do not decide anything on them. Anything
// that chooses a restore path, a quorum, or a verification rule wants Manifest, which only
// a successful Open can produce.
type UnverifiedManifest struct {
	CapsuleID   string    `json:"capsule_id"`
	ServiceName string    `json:"service_name"`
	AppVersion  string    `json:"app_version"`
	CreatedAt   time.Time `json:"created_at"`
	PayloadHash string    `json:"payload_hash"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`

	Dependencies       any `json:"dependencies,omitempty"`
	VerificationRecipe any `json:"verification_recipe,omitempty"`
}

// Manifest is a capsule's manifest, authenticated. Only Open returns one.
//
// The embedded field is not an accident: a Manifest can be read wherever the fields are
// wanted, but an UnverifiedManifest cannot be passed where a Manifest is required.
type Manifest struct {
	UnverifiedManifest
}

// ReadUnverifiedManifest returns a capsule's manifest without decrypting it and without a
// key. Read the doc comment on UnverifiedManifest before using it.
func ReadUnverifiedManifest(raw []byte) (UnverifiedManifest, error) {
	var doc kycapFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return UnverifiedManifest{}, fmt.Errorf("%w: %w", ErrCorruptCapsule, err)
	}
	if doc.Format != KycapFileFormat {
		return UnverifiedManifest{}, fmt.Errorf("%w: %q", ErrUnknownContainer, doc.Format)
	}
	var m UnverifiedManifest
	if err := json.Unmarshal(doc.Manifest, &m); err != nil {
		return UnverifiedManifest{}, fmt.Errorf("%w: %w", ErrCorruptCapsule, err)
	}
	return m, nil
}
```

- [ ] **Step 4: Make `manifest` in `container.go` reuse the type**

Replace the `type manifest struct { ... }` block at `capsule/container.go:37-48` with:

```go
// manifest is the authenticated description of a capsule. It is carried and authenticated
// as the exact bytes that were read, never a re-encoding of this struct — see kycapFile.
type manifest = UnverifiedManifest
```

A type alias, not a new type: the writer and the unverified reader must decode the same
field names or the two drift, and drift here fails every capsule rather than any forgery.

- [ ] **Step 5: Run the tests**

Run: `go test -count=1 ./capsule/ -v`
Expected: PASS, with no failing or skipped tests.

- [ ] **Step 6: Commit**

```bash
git add capsule/manifest.go capsule/manifest_test.go capsule/container.go
git commit -m "feat(capsule): read a manifest without the key, as a distinct type

gridlock re-unmarshals sealed bytes into a hand-rolled struct because the
manifest type is unexported, and kysignon and kyrecovery would each have
written the same workaround.

A keyless read hands back unauthenticated fields, which is what kycap/1 got
wrong. So it returns UnverifiedManifest, and only Open produces a Manifest.
The compiler is what keeps a quorum decision off a forgeable threshold.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: capsule — Open returns the verified manifest

**Files:**
- Modify: `capsule/capsule.go:45-47` and the body of `Open`
- Modify: `capsule/seal.go` (if it decodes the manifest on the way out)
- Test: `capsule/manifest_test.go` (already written in Task 2)

**Interfaces:**
- Consumes: `Manifest` from Task 2.
- Produces: `func Open(raw, key []byte, targetDir string) (Manifest, []File, error)` — **a breaking change**, deliberately. Every later task and every consumer uses this three-value form.

**This task is where the downstream job earns its place.** Changing `Open`'s signature breaks gridlock, which is the only consumer in the job's list. The job pairs on `github.head_ref` — the **ky-primitives** branch name — so gridlock's branch must also be `feat/library-readiness`. A differently-named consumer branch is simply not found, which `ls-remote` reports as exit 2, which the job correctly reads as "no pair" before falling back to the consumer's default — and that default does not compile against this change. If the job goes red and stays red, Task 1 is not finished.

- [ ] **Step 1: Write the failing test**

Append to `capsule/manifest_test.go`:

```go
// The manifest read without a key is unauthenticated: anyone who can reach the file can
// rewrite it. This test is the reason the two types are distinct — it demonstrates the
// rewrite, so the type boundary is not merely decorative.
func TestUnverifiedManifestIsRewritableWithoutTheKey(t *testing.T) {
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, key, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal container: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc["manifest"], &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	m["threshold"] = 1
	m["total_shares"] = 1
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	doc["manifest"] = tampered
	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("remarshal container: %v", err)
	}

	// The unverified read believes the forgery. That is its nature.
	got, err := capsule.ReadUnverifiedManifest(forged)
	if err != nil {
		t.Fatalf("ReadUnverifiedManifest: %v", err)
	}
	if got.Threshold != 1 {
		t.Fatalf("Threshold = %d, want the forged 1", got.Threshold)
	}

	// Open does not. This is the line that makes the type split worth having.
	if _, _, err := capsule.Open(forged, key, ""); err == nil {
		t.Fatal("Open accepted a rewritten manifest")
	}
}
```

- [ ] **Step 1b: Run it and watch it fail**

Run: `go test ./capsule/ -run TestUnverifiedManifestIsRewritable -v`
Expected: FAIL — `assignment mismatch: 3 variables but capsule.Open returns 2 values`

- [ ] **Step 2: Change the signature**

In `capsule/capsule.go`, change `Open`'s declaration and doc comment to:

```go
// Open parses a kycap/2 container, decrypts it, verifies the payload hash, and returns the
// authenticated manifest with the files. When targetDir is non-empty the files are also
// written there under the containment rules in extract.go; the directory must be empty or
// absent. When it is empty nothing is written and the files are returned in memory.
//
// The manifest is returned because a successful Open is the only proof it was not
// rewritten. Callers that want it without a key want ReadUnverifiedManifest, and should
// read that type's doc comment first.
func Open(raw, key []byte, targetDir string) (Manifest, []File, error) {
```

Every `return nil, err` in the body becomes `return Manifest{}, nil, err`. The success path
returns `Manifest{UnverifiedManifest: m}, files, nil`, where `m` is the manifest the
function already decodes to check the payload hash.

- [ ] **Step 3: Fix the call sites inside this repo**

Run: `go build ./... && go vet ./...`
Expected: errors in `capsule/*_test.go` and possibly `cmd/`. Update each to the three-value
form. Do not change what any test asserts — only the arity.

- [ ] **Step 4: Run the full package suite**

Run: `go test ./capsule/ -v`
Expected: PASS, including `TestUnverifiedManifestIsRewritableWithoutTheKey`.

- [ ] **Step 5: Run every package**

Run: `go test -race -count=1 ./...`
Expected: PASS.

- [ ] **Step 6: Pair the consumer branch**

```bash
cd /home/yoshi/busness.app/gridlock-server
git checkout -b feat/library-readiness
```

The branch name matches this repo's, because that is what the pairing keys on.

In `internal/backup/capsule.go`, delete the manifest workaround at lines 71-76 — the
re-`json.Unmarshal` of sealed `raw` into a locally-declared struct — and take the manifest
from the library instead. Update the `kycapsule.Open` call at line 97 to the three-value
form.

`ExtractCapsule` returns `(kycapsule.Manifest, []BackupFile, error)`, and `drill.go` reads
`VerificationRecipe` off that returned `Manifest` local. Do **not** store the authenticated
manifest back into `Capsule.Manifest`: that field is typed `UnverifiedManifest`, so writing
to it downgrades the value and puts a verification-rule decision back on data the type system
has stopped vouching for. Returning it keeps the compiler in the loop and removes a silent
mutation of the caller's `*Capsule`.

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit both**

```bash
cd /home/yoshi/busness.app/ky-primitives
git add capsule/
git commit -m "feat(capsule)!: Open returns the authenticated manifest

A successful Open is the only proof the manifest was not rewritten, so it is
what hands one back. gridlock's hand-rolled re-unmarshal goes away with it.

BREAKING CHANGE: Open returns (Manifest, []File, error).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"

cd /home/yoshi/busness.app/gridlock-server
git add internal/backup/capsule.go
git commit -m "refactor(backup): take the manifest from Open

The local re-unmarshal existed because capsule kept its manifest type
unexported. It does not any more.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: capsule — per-file size and digest

**Files:**
- Modify: `capsule/manifest.go` (add `FileEntry`, `Dependency`, `Files`)
- Modify: `capsule/seal.go` (populate the entries)
- Test: `capsule/manifest_test.go`

**Interfaces:**
- Consumes: `Manifest`, `UnverifiedManifest` from Task 2.
- Produces:
  - `type FileEntry struct { Path string; Size int64; Sum string; Mode os.FileMode }` where `Sum` is lowercase hex SHA-256 of the content.
  - `UnverifiedManifest.Files []FileEntry`

kyrecovery verifies each restored file against a per-file SHA-256 (`capsule.go:287-297`).
`File{Path, Content, Mode}` cannot express that, so the check has nowhere to go.

`File` itself is **not** changed: its content length gives the size and the digest is
computed at seal time, so putting either on the input value would create a second source of
truth for both. The manifest records them. The
payload hash covers the archive as a whole; it cannot say *which* file is wrong.

- [ ] **Step 1: Write the failing test**

Append to `capsule/manifest_test.go`:

```go
func TestManifestRecordsEveryFile(t *testing.T) {
	files := []capsule.File{
		{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600},
		{Path: "keys/signing.key", Content: []byte("secret"), Mode: 0o400},
	}
	raw, key, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 2, 3)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	m, _, err := capsule.Open(raw, key, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(m.Files) != 2 {
		t.Fatalf("Files = %d entries, want 2", len(m.Files))
	}

	// sha256("payload"), computed independently of this package.
	const wantSum = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	byPath := map[string]capsule.FileEntry{}
	for _, e := range m.Files {
		byPath[e.Path] = e
	}
	got := byPath["db.sqlite"]
	if got.Sum != wantSum {
		t.Errorf("db.sqlite Sum = %q, want %q", got.Sum, wantSum)
	}
	if got.Size != 7 {
		t.Errorf("db.sqlite Size = %d, want 7", got.Size)
	}
	if byPath["keys/signing.key"].Mode != 0o400 {
		t.Errorf("signing.key Mode = %v, want 0400", byPath["keys/signing.key"].Mode)
	}
}
```

- [ ] **Step 2: Confirm the expected digest independently**

Run: `printf 'payload' | sha256sum`
Expected: `239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5  -`

If it differs, the constant in the test is wrong — fix the test, not the implementation.

- [ ] **Step 3: Run the test and watch it fail**

Run: `go test ./capsule/ -run TestManifestRecordsEveryFile -v`
Expected: FAIL — `m.Files undefined` and `undefined: capsule.FileEntry`.

- [ ] **Step 4: Add the type and the field**

In `capsule/manifest.go`, above `UnverifiedManifest`:

```go
// FileEntry describes one member of the payload. The digest lets a restore say which file
// is wrong; the payload hash only says that one of them is.
type FileEntry struct {
	Path string      `json:"path"`
	Size int64       `json:"size_bytes"`
	Sum  string      `json:"sha256"`
	Mode os.FileMode `json:"mode"`
}

// Dependency is one thing a service needs that is not in the capsule — an environment
// variable, a port, a peer. A restore that produces every file and none of these produces
// a service that does not start, so they are recorded rather than remembered.
type Dependency struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}
```

`Dependencies` on the manifest stays `any` on the way in — `Seal` takes `deps any` and a
product may hand it whatever shape it already has — but a product that uses this shape gets
a type to decode into rather than a `map[string]interface{}` it must pick apart. kyrecovery
has three interface signatures resting on exactly this (`adapter.VerifyRestore`,
`diff.CompareManifests`, `export.KitData`).

Add `os` to the imports, and add to `UnverifiedManifest`, after `TotalShares`:

```go
	Files []FileEntry `json:"files,omitempty"`
```

- [ ] **Step 5: Populate it in Seal**

In `capsule/seal.go`, where the manifest is built, add an entry per file before the
manifest is marshalled:

```go
	entries := make([]FileEntry, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Content)
		entries = append(entries, FileEntry{
			Path: f.Path,
			Size: int64(len(f.Content)),
			Sum:  hex.EncodeToString(sum[:]),
			Mode: f.Mode,
		})
	}
```

and set `Files: entries` on the manifest literal. `crypto/sha256` and `encoding/hex` are
standard library, so the dependency budget is untouched.

- [ ] **Step 6: Run the tests**

Run: `go test ./capsule/ -v`
Expected: PASS.

- [ ] **Step 7: Run everything**

Run: `go test -race -count=1 ./...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add capsule/
git commit -m "feat(capsule): record size, mode and digest per file

The payload hash says one file is wrong. It cannot say which. kyrecovery
checks each restored file against its own SHA-256 and had nowhere to put it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: auditchain — VerifyRecord

**Files:**
- Create: `auditchain/verify_record.go`, `auditchain/verify_record_test.go`

**Interfaces:**
- Consumes: `Record`, `Anchor`, and the internal digest function from `auditchain/auditchain.go`.
- Produces: `func VerifyRecord(key []byte, r Record) error`

Both kybookmarks (`audit.go:259`) and kypassword (`audit.go:286`) ask one question in
`converge()`: *does this record carry its own digest under this key?* They ask it with
`Resume`, discarding the chain and the error. `Resume` now also asserts tail-ness, so the
probe silently started asking a different question. This gives them the one they meant.

- [ ] **Step 1: Write the failing test**

Create `auditchain/verify_record_test.go`:

```go
package auditchain_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/auditchain"
)

func appendOne(t *testing.T, key []byte, fields ...string) auditchain.Record {
	t.Helper()
	c, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec, err := c.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error {
		return nil
	}, fields...)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return rec
}

func TestVerifyRecordAcceptsAnAuthenticRecord(t *testing.T) {
	key := make([]byte, 32)
	rec := appendOne(t, key, "login", "alice")
	if err := auditchain.VerifyRecord(key, rec); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
}

func TestVerifyRecordRefusesAForgedField(t *testing.T) {
	key := make([]byte, 32)
	rec := appendOne(t, key, "login", "alice")
	rec.Fields = []string{"login", "mallory"}
	if err := auditchain.VerifyRecord(key, rec); err == nil {
		t.Fatal("VerifyRecord accepted a rewritten field")
	}
}

func TestVerifyRecordRefusesAnotherKey(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	other[0] = 1
	rec := appendOne(t, key, "login", "alice")
	if err := auditchain.VerifyRecord(other, rec); err == nil {
		t.Fatal("VerifyRecord accepted a record under a different key")
	}
}

// The whole point: unlike Resume, this asks nothing about where the record sits.
func TestVerifyRecordSaysNothingAboutTailness(t *testing.T) {
	key := make([]byte, 32)
	c, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	persist := func(auditchain.Record, auditchain.Anchor) error { return nil }
	first, err := c.Append(context.Background(), persist, "login", "alice")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := c.Append(context.Background(), persist, "logout", "alice"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// first is now in the middle. VerifyRecord still accepts it.
	if err := auditchain.VerifyRecord(key, first); err != nil {
		t.Fatalf("VerifyRecord on a mid-chain record: %v", err)
	}
	// Resume, given the same record and the chain's real anchor, refuses it.
	if _, err := auditchain.Resume(key, first, c.Anchor()); err == nil {
		t.Fatal("Resume accepted a mid-chain record as the tail")
	}
}

func TestVerifyRecordRefusesAShortKey(t *testing.T) {
	rec := appendOne(t, make([]byte, 32), "login", "alice")
	if err := auditchain.VerifyRecord(make([]byte, 31), rec); err == nil {
		t.Fatal("VerifyRecord accepted a 31-byte key")
	}
	if err := auditchain.VerifyRecord(nil, rec); !errors.Is(err, auditchain.ErrKeyTooShort) {
		t.Errorf("nil key gave %v, want ErrKeyTooShort", err)
	}
}
```

- [ ] **Step 2: Find the existing digest function and key floor**

Run: `grep -n 'func.*digest\|func.*hashRecord\|ErrKeyTooShort\|minKey' auditchain/auditchain.go`
Expected: the unexported digest helper and the key-length sentinel. Use whatever names are
there; the test above assumes `ErrKeyTooShort` — if the sentinel has another name, change
the **test** to match the package, not the other way round.

- [ ] **Step 3: Run the test and watch it fail**

Run: `go test ./auditchain/ -run TestVerifyRecord -v`
Expected: FAIL — `undefined: auditchain.VerifyRecord`

- [ ] **Step 4: Write `auditchain/verify_record.go`**

```go
package auditchain

import "crypto/hmac"

// VerifyRecord reports whether a record carries its own digest under this key.
//
// It says nothing about where the record sits. Resume answers a different question — is
// this the tail — and answering it requires the anchor, because every record in a healthy
// chain carries a valid digest. Callers converting a log from an older format want this
// one: they are asking whether a record is already in the shared shape, not whether it is
// the end.
func VerifyRecord(key []byte, r Record) error {
	if len(key) < minKeyBytes {
		return ErrKeyTooShort
	}
	want := digest(key, r.Seq, r.Prev, r.Fields)
	if !hmac.Equal([]byte(r.Hash), []byte(want)) {
		return ErrBrokenChain
	}
	return nil
}
```

Substitute the real names found in Step 2 for `minKeyBytes`, `digest` and `ErrBrokenChain`.
`digest`'s parameter order must match its definition — read it, do not assume.

- [ ] **Step 5: Run the tests**

Run: `go test ./auditchain/ -run TestVerifyRecord -v`
Expected: PASS, all five.

- [ ] **Step 6: Commit**

```bash
git add auditchain/verify_record.go auditchain/verify_record_test.go
git commit -m "feat(auditchain): add a digest-only predicate

Both format-conversion probes in the suite ask whether a record carries its
own digest, and both ask it with Resume, discarding the chain and the error.
Resume now also asserts tail-ness, so the probes quietly started asking
something else. This is the question they meant.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: auditchain — Replay for bulk conversion

**Files:**
- Modify: `auditchain/verify_record.go`
- Modify: `auditchain/verify_record_test.go`

**Interfaces:**
- Consumes: `Record`, `Anchor`, `New`, `Append`.
- Produces: `func Replay(key []byte, tuples [][]string) ([]Record, Anchor, error)`

Both `converge()` loops rebuild a whole chain in memory and then write the file once,
atomically, followed by one anchor save. A per-record `persist` there would return nil
having written nothing — a lie to the API whose entire purpose is that the chain advances
only when the store says it did. `Replay` is the honest shape: build in memory, hand back
the records and the final anchor, and let the caller make one transaction of it.

- [ ] **Step 1: Write the failing test**

Append to `auditchain/verify_record_test.go`:

```go
func TestReplayBuildsAChainVerifyAccepts(t *testing.T) {
	key := make([]byte, 32)
	tuples := [][]string{
		{"login", "alice"},
		{"logout", "alice"},
		{"login", "bob"},
	}
	records, anchor, err := auditchain.Replay(key, tuples)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("Replay returned %d records, want 3", len(records))
	}
	if anchor.Count != 3 {
		t.Errorf("anchor.Count = %d, want 3", anchor.Count)
	}
	if anchor.Hash != records[2].Hash {
		t.Errorf("anchor.Hash = %q, want the last record's %q", anchor.Hash, records[2].Hash)
	}
	if err := auditchain.Verify(key, records, anchor); err != nil {
		t.Fatalf("Verify on a replayed chain: %v", err)
	}
}

func TestReplayNumbersFromOne(t *testing.T) {
	key := make([]byte, 32)
	records, _, err := auditchain.Replay(key, [][]string{{"a"}, {"b"}})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if records[0].Seq != 1 || records[1].Seq != 2 {
		t.Errorf("Seq = %d, %d; want 1, 2", records[0].Seq, records[1].Seq)
	}
}

func TestReplayOfNothingIsTheGenesisAnchor(t *testing.T) {
	key := make([]byte, 32)
	records, anchor, err := auditchain.Replay(key, nil)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
	if anchor.Count != 0 {
		t.Errorf("anchor.Count = %d, want 0", anchor.Count)
	}
}

func TestReplayRefusesAShortKey(t *testing.T) {
	if _, _, err := auditchain.Replay(make([]byte, 31), [][]string{{"a"}}); err == nil {
		t.Fatal("Replay accepted a 31-byte key")
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./auditchain/ -run TestReplay -v`
Expected: FAIL — `undefined: auditchain.Replay`

- [ ] **Step 3: Implement**

Append to `auditchain/verify_record.go`:

```go
// Replay builds a whole chain in memory from field tuples and returns its records with the
// anchor they end at. It writes nothing.
//
// Append takes a persist function because the chain's head is a claim about what is on
// disk, and advancing it before the store agrees leaves the next record chained onto one
// that never existed. A bulk conversion inverts that: it rebuilds every record, writes the
// log once atomically, and saves one anchor. Passing a persist that does nothing per record
// would satisfy the signature and mean nothing. This is the shape that fits — the caller
// still owes one transaction over the returned records and anchor together.
func Replay(key []byte, tuples [][]string) ([]Record, Anchor, error) {
	c, err := New(key)
	if err != nil {
		return nil, Anchor{}, err
	}
	records := make([]Record, 0, len(tuples))
	noop := func(Record, Anchor) error { return nil }
	for _, fields := range tuples {
		rec, err := c.Append(context.Background(), noop, fields...)
		if err != nil {
			return nil, Anchor{}, err
		}
		records = append(records, rec)
	}
	return records, c.Anchor(), nil
}
```

Add `"context"` to the file's imports.

- [ ] **Step 4: Run the tests**

Run: `go test ./auditchain/ -run 'TestReplay|TestVerifyRecord' -v`
Expected: PASS.

- [ ] **Step 5: Run everything with the race detector**

Run: `go test -race -count=1 ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add auditchain/
git commit -m "feat(auditchain): add Replay for bulk conversion

Both converge() loops in the suite rebuild a chain in memory and write the
log once. A per-record persist there returns nil having written nothing,
which is a lie to the one parameter whose job is to mean the opposite.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: password — a cost knob tests can afford

**Files:**
- Modify: `password/password.go`
- Test: `password/hashwith_test.go` (create)

**Interfaces:**
- Consumes: `Params`, `DefaultParams`, the unexported `hashWith` and `parse`.
- Produces:
  - `func HashWith(plaintext string, p Params) (string, error)`
  - `func (p Params) Validate() error`

kypost runs ~14 derivation sites and drops N from 2^17 to 2^14 in tests via
`SetHashCostForTest`. `Hash` takes only a plaintext and `hashWith` is unexported, so
adopting `password` means the suite pays 64 MiB × t=3 per derivation with no way down.
That single gap blocks the whole of kypost.

**The tension, stated plainly.** Exporting a cost knob lets a product mint a weak hash in
production, which is exactly what "this package is the one answer" exists to prevent. The
mitigation is not to hide it — `Verify` already accepts anything in the 8–256 MiB band, so
the weak hash was always verifiable. It is to bound `HashWith` to the same band `parse`
accepts, so it cannot mint something `Verify` would reject, and to pin the intended usage
with a discovery test in the repo's existing style.

- [ ] **Step 1: Write the failing test**

Create `password/hashwith_test.go`:

```go
package password_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/password"
)

func TestHashWithRoundTripsAtALowerCost(t *testing.T) {
	p := password.Params{Memory: 8 * 1024, Time: 1, Threads: 1}
	encoded, err := password.HashWith("correct horse battery staple", p)
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	if !strings.Contains(encoded, "m=8192,t=1,p=1") {
		t.Errorf("encoded = %q, want the requested parameters", encoded)
	}
	ok, err := password.Verify("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify rejected a hash HashWith just minted")
	}
}

func TestHashWithRefusesWhatVerifyWouldRefuse(t *testing.T) {
	// Below the 8 MiB floor parse accepts. Minting it would produce a hash that
	// verifies nowhere, which is worse than refusing.
	cases := map[string]password.Params{
		"memory below floor": {Memory: 4 * 1024, Time: 3, Threads: 4},
		"memory above cap":   {Memory: 512 * 1024, Time: 3, Threads: 4},
		"time zero":          {Memory: 64 * 1024, Time: 0, Threads: 4},
		"time above cap":     {Memory: 64 * 1024, Time: 11, Threads: 4},
		"threads zero":       {Memory: 64 * 1024, Time: 3, Threads: 0},
		"threads above cap":  {Memory: 64 * 1024, Time: 3, Threads: 17},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := password.HashWith("hunter2", p); err == nil {
				t.Errorf("HashWith accepted %+v", p)
			}
		})
	}
}

func TestHashWithDefaultParamsMatchesHash(t *testing.T) {
	a, err := password.HashWith("hunter2", password.DefaultParams())
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	b, err := password.Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	// Different salts, so not equal — but the parameter segment must match.
	if strings.Split(a, "$")[3] != strings.Split(b, "$")[3] {
		t.Errorf("HashWith(DefaultParams()) params %q != Hash params %q",
			strings.Split(a, "$")[3], strings.Split(b, "$")[3])
	}
}

// HashWith exists for tests and for a product that must match an existing deployment.
// Production code in this repository mints at the suite parameters, through Hash.
func TestHashWithIsNotCalledOutsideTests(t *testing.T) {
	root := ".."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "HashWith(") && !strings.Contains(path, "password.go") {
			t.Errorf("%s calls HashWith; production code mints through Hash", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./password/ -run TestHashWith -v`
Expected: FAIL — `undefined: password.HashWith`

- [ ] **Step 3: Find the existing bounds**

Run: `grep -n 'minMemory\|maxMemory\|minTime\|maxTime\|minThreads\|maxThreads\|8 \* 1024\|256' password/password.go`
Expected: the constants `parse` checks against. `Validate` must use the same ones — two
copies of a bound is how they drift.

- [ ] **Step 4: Implement**

Add to `password/password.go`:

```go
// Validate reports whether these parameters are inside the band a stored hash may carry.
//
// The band is parse's, not a second opinion: minting something Verify would refuse is a
// hash that works nowhere, which is a worse failure than being told no.
func (p Params) Validate() error {
	switch {
	case p.Memory < minMemory || p.Memory > maxMemory:
		return fmt.Errorf("%w: memory %d KiB outside %d-%d", ErrMalformed, p.Memory, minMemory, maxMemory)
	case p.Time < minTime || p.Time > maxTime:
		return fmt.Errorf("%w: time %d outside %d-%d", ErrMalformed, p.Time, minTime, maxTime)
	case p.Threads < minThreads || p.Threads > maxThreads:
		return fmt.Errorf("%w: threads %d outside %d-%d", ErrMalformed, p.Threads, minThreads, maxThreads)
	}
	return nil
}

// HashWith derives a PHC-encoded Argon2id hash at the given parameters.
//
// Hash is the suite's answer and what production code should call. This exists for two
// callers: a test suite that cannot afford 64 MiB per derivation, and a product that must
// mint at parameters an existing deployment already uses. Parameters are bounded to the
// band Verify accepts, so this cannot mint a hash that verifies nowhere — but it can mint
// a weaker one than the suite standard, and that is the caller's responsibility.
func HashWith(plaintext string, p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return hashWith(plaintext, p)
}
```

Substitute the real constant names found in Step 3. If `hashWith` has a different name or
signature, match it — read the function, do not assume.

- [ ] **Step 5: Run the tests**

Run: `go test ./password/ -v`
Expected: PASS, including `TestHashWithIsNotCalledOutsideTests`.

- [ ] **Step 6: Commit**

```bash
git add password/
git commit -m "feat(password): add a bounded cost knob for tests

kypost runs fourteen derivation sites at 2^14 in its suite and cannot adopt
this package while Hash is the only minter. Parameters are bounded to the
band Verify already accepts, so this cannot mint a hash that verifies
nowhere, and a discovery test keeps production code on Hash.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: password — DummyVerify and NeedsRehash on a foreign format

**Files:**
- Modify: `password/password.go`
- Test: `password/dummy_test.go` (create)

**Interfaces:**
- Consumes: `HashWith`, `Params`, `DefaultParams` from Task 7.
- Produces:
  - `func DummyVerify()`
  - `NeedsRehash` returns `(false, nil)` for a hash this package did not write.

kysignon calls `DummyVerify` on four reject paths so a missing account costs the same as a
wrong password. Without it, adopting `password` reintroduces the enumeration oracle it was
written to close. `ErrBusy` returning fast is a second, smaller version of the same leak —
document it rather than pretend otherwise.

kypost's `NeedsRehash` returns false for a format it did not write, deliberately: rehashing
something this package did not mint is a guess. `password.NeedsRehash` returns
`ErrMalformed`, so every caller has to special-case it.

- [ ] **Step 1: Write the failing test**

Create `password/dummy_test.go`:

```go
package password_test

import (
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/password"
)

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	password.DummyVerify()
}

func TestNeedsRehashIsFalseForAForeignFormat(t *testing.T) {
	cases := []string{
		"scrypt$131072$8$1$c2FsdA$aGFzaA",
		"$2b$12$abcdefghijklmnopqrstuv",
		"239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
		"",
	}
	for _, encoded := range cases {
		stale, err := password.NeedsRehash(encoded)
		if err != nil {
			t.Errorf("NeedsRehash(%q) = error %v, want (false, nil)", encoded, err)
		}
		if stale {
			t.Errorf("NeedsRehash(%q) = true, want false", encoded)
		}
	}
}

func TestNeedsRehashStillFlagsAWeakOwnHash(t *testing.T) {
	weak, err := password.HashWith("hunter2", password.Params{Memory: 8 * 1024, Time: 1, Threads: 1})
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	stale, err := password.NeedsRehash(weak)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if !stale {
		t.Error("NeedsRehash did not flag a hash below the current parameters")
	}
}

func TestNeedsRehashIsFalseForACurrentHash(t *testing.T) {
	current, err := password.Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	stale, err := password.NeedsRehash(current)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if stale {
		t.Error("NeedsRehash flagged a hash minted at the current parameters")
	}
}

// Verify must still refuse a malformed stored hash outright. A fallback there is the
// bug this package exists to remove, and relaxing NeedsRehash must not relax Verify.
func TestVerifyStillErrorsOnAForeignFormat(t *testing.T) {
	if _, err := password.Verify("hunter2", "scrypt$131072$8$1$c2FsdA$aGFzaA"); !errors.Is(err, password.ErrMalformed) {
		t.Errorf("Verify on a foreign format gave %v, want ErrMalformed", err)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./password/ -run 'TestDummyVerify|TestNeedsRehash|TestVerifyStillErrors' -v`
Expected: FAIL — `undefined: password.DummyVerify`, and `NeedsRehash` returning an error
for the foreign formats.

- [ ] **Step 3: Implement**

Add to `password/password.go`:

```go
// DummyVerify spends the cost of a verification and reports nothing.
//
// A login that answers "no such account" faster than "wrong password" enumerates accounts.
// Call this on every reject path that did not reach a real Verify, so the two cost the
// same.
//
// It is not perfect and should not be sold as such: Verify can return ErrBusy without
// deriving anything, and that path is fast. Under load the oracle reopens. Shedding is
// still the right answer to overload — just do not describe this as constant time.
func DummyVerify() {
	_, _ = Verify(dummyPlaintext, dummy())
}
```

and, at package scope:

```go
const dummyPlaintext = "dummy verification plaintext"

// dummyHash is minted once, on first use, at whatever the current parameters are — so
// DummyVerify costs what a real verification costs even after those parameters move.
//
// Minted through the path that does NOT acquire the derivation budget. Hash does acquire
// it, and can return ErrBusy after the queue wait — which is exactly when DummyVerify
// matters, under the burst or the credential-stuffing run. And an error here must never be
// cached: sync.OnceValue memoises a panic and re-raises the same value forever, so one
// transient ErrBusy would brick DummyVerify for the process lifetime. Missing-account
// logins would then 500 while wrong-password logins 401 — a louder oracle than the timing
// difference this closes. One derivation once per process is not what admission control
// exists to bound.
var (
	dummyMu   sync.Mutex
	dummyHash string
)

func dummy() string {
	dummyMu.Lock()
	defer dummyMu.Unlock()
	if dummyHash == "" {
		h, err := hashWith(dummyPlaintext, DefaultParams())
		if err != nil {
			// Leave it unset so the next call retries. A cached failure is the bug above.
			return ""
		}
		dummyHash = h
	}
	return dummyHash
}
```

and change `DummyVerify`'s body to `_, _ = Verify(dummyPlaintext, dummy())`. Add `sync` to
the imports. Confirm by reading it that `hashWith` really is the non-acquiring path before
using it here.

Then change `NeedsRehash`'s parse-failure branch to return `(false, nil)` rather than the
error, with this comment above it:

```go
	// A hash this package did not write is not stale — it is not ours. Rehashing on a
	// guess is how a product ends up re-minting a format it cannot read. Verify still
	// refuses it outright; that is where a malformed hash must be an error.
```

- [ ] **Step 4: Run the tests**

Run: `go test ./password/ -v`
Expected: PASS.

- [ ] **Step 5: Check the init cost is paid once**

Run: `go test ./password/ -run TestDummyVerifyDoesNotPanic -v -count=1`
Expected: PASS. Then confirm the minting happens once rather than per call:

Run: `go test ./password/ -run TestDummyVerifyDoesNotPanic -count=20 -v`
Expected: PASS, and the whole run takes roughly one derivation's time plus twenty
verifications — not twenty mintings. If it scales with `-count`, the memo is not holding.

Then pin the failure mode I got wrong, as a **committed test**, not a throwaway. It holds
the whole derivation budget, calls `DummyVerify` twice, and asserts neither panics and that
the second sees the same memoised value as the first. It must fail if `dummyMint` ever
starts acquiring the budget again.

A security property proved once by a probe that is then deleted is unproven from the next
commit onward — and routing the mint back through the budget is exactly the mistake that
produced the bug. Make the test release the budget even on failure; one that leaves it held
poisons every test after it.

- [ ] **Step 6: Commit**

```bash
git add password/
git commit -m "feat(password): add DummyVerify, and stop calling a foreign hash stale

kysignon spends a dummy verification on four reject paths so a missing
account costs what a wrong password costs. Adopting this package without one
reopens the enumeration oracle.

NeedsRehash now answers false for a format this package did not write, which
is what it means: not ours, not stale. Verify still refuses it outright.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: keyfile — encodings, a read-only load, and the environment

**Files:**
- Create: `keyfile/encoding.go`, `keyfile/encoding_test.go`
- Modify: `keyfile/keyfile.go`

**Interfaces:**
- Consumes: the existing `LoadOrCreate` internals and `RequireOwnerOnly`.
- Produces:
  - `type Encoding int`, with `Hex`, `Raw`, `Base64`
  - `func LoadOrCreateEncoded(path string, size int, enc Encoding) ([]byte, error)`
  - `func Load(path string, size int) ([]byte, error)`
  - `func LoadEncoded(path string, size int, enc Encoding) ([]byte, error)`
  - `func FromEnv(name string, size int) ([]byte, bool, error)`
  - `LoadOrCreate(path, size)` becomes `LoadOrCreateEncoded(path, size, Hex)`

Four repos cannot call `LoadOrCreate` as it stands. kydns' `node_key` is 32 raw ed25519
seed bytes; kysignon's key files are raw; kynotes and kypost write base64. kypost splits
`LoadOrCreateKey` from `LoadKey` on purpose — the daemon process must never mint a key the
API process did not, or half the data ends up under a key that no longer exists. And four
loaders check an environment variable first, which today means the env-supplied key skips
every check this package makes.

- [ ] **Step 1: Write the failing test**

Create `keyfile/encoding_test.go`:

```go
package keyfile_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

func TestEachEncodingRoundTrips(t *testing.T) {
	for name, enc := range map[string]keyfile.Encoding{
		"hex":    keyfile.Hex,
		"raw":    keyfile.Raw,
		"base64": keyfile.Base64,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "k")
			made, err := keyfile.LoadOrCreateEncoded(path, 32, enc)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if len(made) != 32 {
				t.Fatalf("len = %d, want 32", len(made))
			}
			again, err := keyfile.LoadOrCreateEncoded(path, 32, enc)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if !bytes.Equal(made, again) {
				t.Error("reload returned a different key")
			}
		})
	}
}

func TestRawEncodingWritesTheBytesThemselves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_key")
	key, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Raw)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(onDisk, key) {
		t.Error("raw encoding did not write the key bytes verbatim")
	}
}

func TestEncodingsDoNotReadEachOther(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if _, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Hex); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 64 hex characters are not 32 raw bytes, and must be refused rather than
	// truncated into a key nobody chose.
	if _, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Raw); err == nil {
		t.Error("Raw read a hex file")
	}
}

func TestLoadNeverCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if _, err := keyfile.Load(path, 32); err == nil {
		t.Fatal("Load created or accepted a missing file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("Load wrote a file it was only asked to read")
	}
}

func TestLoadReadsWhatLoadOrCreateWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	made, err := keyfile.LoadOrCreate(path, 32)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	read, err := keyfile.Load(path, 32)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(made, read) {
		t.Error("Load returned a different key")
	}
}

func TestFromEnvValidatesLikeAFile(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)

	t.Run("hex", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", hex.EncodeToString(key))
		got, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32)
		if err != nil || !ok {
			t.Fatalf("FromEnv: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(got, key) {
			t.Error("wrong key")
		}
	})

	t.Run("base64", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", base64.StdEncoding.EncodeToString(key))
		got, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32)
		if err != nil || !ok {
			t.Fatalf("FromEnv: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(got, key) {
			t.Error("wrong key")
		}
	})

	t.Run("absent", func(t *testing.T) {
		os.Unsetenv("KY_TEST_KEY")
		if _, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32); ok || err != nil {
			t.Errorf("absent gave ok=%v err=%v, want false, nil", ok, err)
		}
	})

	t.Run("wrong length is an error, not a miss", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", hex.EncodeToString(key[:16]))
		if _, ok, err := keyfile.FromEnv("KY_TEST_KEY", 32); err == nil {
			t.Errorf("a 16-byte value gave ok=%v err=nil; a set-but-wrong key must fail loudly", ok)
		}
	})

	t.Run("garbage is an error", func(t *testing.T) {
		t.Setenv("KY_TEST_KEY", "not a key")
		if _, _, err := keyfile.FromEnv("KY_TEST_KEY", 32); err == nil {
			t.Error("garbage was accepted")
		}
	})
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./keyfile/ -run 'TestEachEncoding|TestRaw|TestEncodingsDoNot|TestLoad|TestFromEnv' -v`
Expected: FAIL — `undefined: keyfile.Encoding`, `keyfile.Load`, `keyfile.FromEnv`.

- [ ] **Step 3: Read the existing implementation before changing it**

Run: `cat keyfile/keyfile.go`

Note where the hex decode and encode happen, where the `O_EXCL` create and the loser's
re-read live, and where both fsyncs are. The encoding change goes *only* at the decode and
encode points; the race handling, the permission check and the fsyncs must be shared by
every variant, not reimplemented.

- [ ] **Step 4: Write `keyfile/encoding.go`**

```go
package keyfile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Encoding is how a key is spelled on disk.
//
// Hex is this package's default and the suite's preference: an operator can read it, copy
// it and diff it without a tool. Raw and Base64 exist because four products already wrote
// their key files that way, and a package that cannot read them is a package they cannot
// adopt.
type Encoding int

const (
	// Hex is lowercase hex, optionally with surrounding whitespace.
	Hex Encoding = iota
	// Raw is the key bytes themselves, with nothing around them.
	Raw
	// Base64 is standard base64, optionally with surrounding whitespace.
	Base64
)

func (e Encoding) decode(b []byte) ([]byte, error) {
	switch e {
	case Raw:
		return b, nil
	case Base64:
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	case Hex:
		return hex.DecodeString(strings.TrimSpace(string(b)))
	}
	return nil, fmt.Errorf("keyfile: unknown encoding %d", int(e))
}

func (e Encoding) encode(key []byte) []byte {
	switch e {
	case Raw:
		return key
	case Base64:
		return []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	default:
		return []byte(hex.EncodeToString(key) + "\n")
	}
}

// FromEnv reads a key from an environment variable, accepting hex or base64.
//
// It returns false when the variable is unset. A variable that is set but does not decode
// to exactly size bytes is an error, never a miss: falling through to the file there would
// start the process under a key the operator did not choose and thought they had.
//
// This exists because four products in the suite check an environment variable before the
// file, and doing that outside this package means the env-supplied key skips every check
// the file-supplied one gets.
func FromEnv(name string, size int) ([]byte, bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, false, nil
	}
	trimmed := strings.TrimSpace(raw)
	for _, enc := range []Encoding{Hex, Base64} {
		key, err := enc.decode([]byte(trimmed))
		if err == nil && len(key) == size {
			return key, true, nil
		}
	}
	return nil, true, fmt.Errorf("keyfile: %s is set but is not %d bytes of hex or base64", name, size)
}
```

- [ ] **Step 5: Thread the encoding through `keyfile.go`**

Rename the existing `LoadOrCreate` body to `LoadOrCreateEncoded(path string, size int, enc Encoding)`,
replacing its `hex.DecodeString` with `enc.decode` and its `hex.EncodeToString(key)+"\n"`
with `enc.encode(key)`. Then:

```go
// LoadOrCreate returns the size-byte secret stored at path as lowercase hex, creating it
// if the file does not exist. See LoadOrCreateEncoded for other spellings.
func LoadOrCreate(path string, size int) ([]byte, error) {
	return LoadOrCreateEncoded(path, size, Hex)
}

// Load returns the size-byte secret stored at path, and never creates one.
//
// A process that reads a key another process minted must not be able to mint its own. When
// both can, a restart in the wrong order leaves half the data under a key that no longer
// exists, and nothing reports it — every write succeeds, and every old read fails as
// though the data were corrupt.
func Load(path string, size int) ([]byte, error) {
	return LoadEncoded(path, size, Hex)
}

// LoadEncoded is Load for a key written in another spelling.
func LoadEncoded(path string, size int, enc Encoding) ([]byte, error) {
	return readKey(path, size, enc)
}
```

Both `LoadEncoded` and `LoadOrCreateEncoded` must go through one `readKey`. Two copies of a
refusal is how one of them stops matching the other. Factor the existing read path in
`keyfile.go` into:

```go
// readKey reads and validates an existing key file. It never creates one.
func readKey(path string, size int, enc Encoding) ([]byte, error) {
	if err := RequireOwnerOnly(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := enc.decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnreadable, path, err)
	}
	if len(key) != size {
		// Left untouched on purpose. A file that does not decode to the expected size is
		// not a file to overwrite: it is either someone else's key or a truncated write,
		// and replacing it orphans everything encrypted under the original.
		return nil, fmt.Errorf("%w: %s: %d bytes, want %d", ErrUnreadable, path, len(key), size)
	}
	return key, nil
}
```

Substitute the real sentinel name for `ErrUnreadable` — read `keyfile.go` first — and make
`LoadOrCreateEncoded`'s existing-file branch call `readKey` rather than repeating it.

**Keep the exact-size rule.** Three loaders in the suite accept `>= size` today, and
kybookmarks' own error message tells the operator to run `openssl rand -hex 64`. Exact is
the better invariant — a key that is longer than asked for is a key half of which is being
silently discarded — so the fix is to that error message, in Task 12, not to this check.

- [ ] **Step 6: Run the keyfile tests**

Run: `go test ./keyfile/ -v`
Expected: PASS, including every pre-existing test.

- [ ] **Step 7: Run everything on both platforms' logic**

Run: `go test -race -count=1 ./...`
Expected: PASS. CI will also run macOS, where the fsync and permission behaviour differs;
if the macOS leg fails, the shared helper has drifted from the original read path.

- [ ] **Step 8: Commit**

```bash
git add keyfile/
git commit -m "feat(keyfile): read raw and base64 keys, load without creating, validate the env

Four products cannot call LoadOrCreate: kydns writes 32 raw ed25519 seed
bytes, kysignon writes raw, kynotes and kypost write base64.

Load never creates, because kypost's daemon must not mint a key its API
process did not — when both can, a restart in the wrong order puts half the
data under a key that no longer exists and nothing says so.

FromEnv exists because four repos check an environment variable first, which
today means that key skips every check this package makes.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: derive — context, and an honest word about the budget

**Files:**
- Modify: `derive/derive.go`
- Test: `derive/context_test.go` (create)

**Interfaces:**
- Consumes: the existing `AuthSecret` and its unexported admission control.
- Produces:
  - `func AuthSecretContext(ctx context.Context, password, saltBase64 string, iterations int, label string) (string, error)`
  - `AuthSecret` delegates with `context.Background()`
  - `const MaxConcurrent = 4`, and in `password`, `MaxMemoryKiB` and `MaxLanes`

kypost checks `ctx.Err()` before queueing so a client that has already gone does not take a
slot ahead of one that is still waiting. `derive`'s acquire is a bare two-second timer with
no cancellation.

**On the two budgets, which the spec left open.** kypost puts all memory-hard work under
one process-wide semaphore, and its comment is right that a ceiling half the callers walk
around is not a ceiling. But `derive` and `password` bound *different resources* — PBKDF2 is
single-threaded CPU, so a slot is a core; Argon2id is memory, so the budget is bytes and
lanes. Two ceilings over two resources is not a hole. What was missing is that neither
budget was visible, so a product could not add them up. Export them and document the sum.
A shared injectable limiter is the answer if a third caller ever appears; it is not
warranted for one.

- [ ] **Step 1: Write the failing test**

Create `derive/context_test.go`:

```go
package derive_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/derive"
)

func TestAuthSecretContextMatchesAuthSecret(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	const pw = "correct horse battery staple"

	want, err := derive.AuthSecret(pw, salt, 100_000, "kynotes/auth/v1")
	if err != nil {
		t.Fatalf("AuthSecret: %v", err)
	}
	got, err := derive.AuthSecretContext(context.Background(), pw, salt, 100_000, "kynotes/auth/v1")
	if err != nil {
		t.Fatalf("AuthSecretContext: %v", err)
	}
	if got != want {
		t.Errorf("AuthSecretContext = %q, AuthSecret = %q; the two must not diverge", got, want)
	}
}

func TestAuthSecretContextRefusesACancelledContext(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := derive.AuthSecretContext(ctx, "hunter2", salt, 100_000, "kynotes/auth/v1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context gave %v, want context.Canceled", err)
	}
}

func TestConcurrencyBudgetIsVisible(t *testing.T) {
	if derive.MaxConcurrent < 1 {
		t.Errorf("MaxConcurrent = %d, want a positive slot count", derive.MaxConcurrent)
	}
}
```

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./derive/ -run 'TestAuthSecretContext|TestConcurrencyBudget' -v`
Expected: FAIL — `undefined: derive.AuthSecretContext`, `undefined: derive.MaxConcurrent`.

- [ ] **Step 3: Read the current admission control**

Run: `grep -n 'acquire\|slots\|time.After\|chan struct' derive/derive.go`

Note the slot count and the wait duration. `MaxConcurrent` must be the same constant the
acquire uses, not a second copy.

- [ ] **Step 4: Implement**

In `derive/derive.go`, export the slot count as `MaxConcurrent` (replacing the unexported
constant, not shadowing it) with:

```go
// MaxConcurrent is how many stretches may run at once. PBKDF2 is single-threaded, so a
// slot really is a core.
//
// This budget is separate from password's, and deliberately: this package is
// standard-library-only, and importing password would pull x/crypto into it. The two also
// bound different resources — slots of CPU here, bytes and lanes of memory there. A product
// adopting both is spending MaxConcurrent cores plus password.MaxMemoryKiB; add them up
// against the box before deciding either is safe.
const MaxConcurrent = 4
```

Change `acquire` to take a context, selecting on `ctx.Done()` alongside the existing timer,
and checking `ctx.Err()` before it queues at all — a caller who has already gone must not
take a slot ahead of one still waiting. Then:

```go
// AuthSecretContext is AuthSecret, bounded by a context.
//
// The context governs the wait for a derivation slot, not the derivation: PBKDF2 at these
// iteration counts is not interruptible, so a cancellation during the stretch itself is
// noticed when it finishes.
func AuthSecretContext(ctx context.Context, password, saltBase64 string, iterations int, label string) (string, error) {
	// existing AuthSecret body, with acquire(ctx)
}

// AuthSecret is AuthSecretContext without a deadline of its own.
func AuthSecret(password, saltBase64 string, iterations int, label string) (string, error) {
	return AuthSecretContext(context.Background(), password, saltBase64, iterations, label)
}
```

Add `"context"` to the imports.

- [ ] **Step 5: Export the password budget**

In `password/password.go`, alongside the existing bounds:

```go
// MaxMemoryKiB and MaxLanes are the two dimensions of this package's derivation budget,
// taken together under one acquirer so two waiters can never each hold part of what the
// other needs. They are exported so a product running derive as well can add the two
// budgets up rather than assume one of them is the whole story.
const (
	MaxMemoryKiB = budgetKiB // 262144 KiB = 256 MiB
	MaxLanes       = 16
)
```

Use the constants the acquirer already uses. If they are literals in the acquirer, replace
the literals with these names.

- [ ] **Step 6: Run the tests**

Run: `go test -race -count=1 ./derive/ ./password/ -v`
Expected: PASS.

- [ ] **Step 7: Confirm the dependency budget is intact**

Run: `go test -run 'TestModuleDependenciesAreAllowlisted|TestOnlyPasswordImportsADependency' -v ./...`
Expected: PASS. `derive` must still import nothing outside the standard library.

- [ ] **Step 8: Commit**

```bash
git add derive/ password/
git commit -m "feat(derive): take a context, and make both budgets visible

kypost checks ctx.Err() before queueing so a client that has already gone
does not take a slot ahead of one still waiting. This had a bare timer.

The two packages keep separate budgets — they bound different resources, and
derive stays standard-library-only. What was missing is that neither budget
was visible, so a product running both could not add them up.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: README corrections and the v0.2.0 tag

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: every API added in Tasks 2-10.
- Produces: tag `v0.2.0`. Every product phase after this pins a tag, never a pseudo-version.

- [ ] **Step 0: Remove `capsule.Dependency`, and document what `Manifest` does not promise**

Two carried rulings, both due before the tag freezes the API.

**Delete `Dependency` from `capsule/manifest.go`.** It has no reference anywhere in this
repo: `Seal` keeps `deps any` and never encodes through it, and no test exercises it. It was
specified because three kyrecovery signatures need something to decode into — but that
migration is Phase 5, its plan is unwritten, and the shape it needs will be known then rather
than guessed now. An exported type with no exerciser is surface that must be maintained and
cannot be changed freely once a tag exists.

**Add one sentence to `Manifest`'s doc comment** saying what a successful `Open` does and does
not establish:

```go
// A Manifest is authenticated, not validated. Open proves the manifest is the one that was
// sealed under this key; it does not re-apply Seal's topology rule, so a kit recorded as
// 0-of-0 by some other writer opens without complaint. Check the numbers you intend to act
// on.
```

Run: `go build ./... && go test -race -count=1 ./...`
Expected: PASS. If deleting `Dependency` breaks a build, it was not dead after all — stop and
say so.

- [ ] **Step 1: Correct the kybookmarks claim**

`README.md` currently says `kybookmarks-server/internal/audit/audit.go:44` substitutes
`"kybookmarks-audit-default-secret"`. Verified against the source: the literal is
`"kybookmarks-default-hmac-secret"`, it is at `audit.go:41`, and the **write path no longer
reaches it** — `loadOrCreateKey` has no constant fallback.

Replace that paragraph with:

```markdown
`kybookmarks-server/internal/audit/audit.go:41` keeps a literal,
`"kybookmarks-default-hmac-secret"`, and its write path no longer reaches it —
`loadOrCreateKey` has no constant fallback. What survives is narrower and still real: the
literal is what `legacyHash` verifies v0 entries against, so a wholly-forged log on a first
boot with no state file converts cleanly through `converge` and verifies forever. The key
floor here is 32 bytes and there is no fallback at all.
```

- [ ] **Step 2: Document the new API**

Under `## capsule`, after the existing code block:

```markdown
`Open` returns the manifest because a successful `Open` is the only proof it was not
rewritten. `ReadUnverifiedManifest` reads one without a key and returns a different type,
`UnverifiedManifest`, so the compiler stops it reaching anything that decides on it — a
threshold read without the key is a threshold anyone who can reach the file chose.

```go
m, files, err := capsule.Open(raw, key, "/var/restore")   // authenticated
m, files, err := capsule.Open(raw, key, "")               // decode only, writes nothing
u, err := capsule.ReadUnverifiedManifest(raw)             // no key; show, do not decide
```
```

Under `## auditchain` — the section currently enumerates `New`/`Resume`/`Append`/`Verify`/
`VerifyStream` and does not mention the two functions added for the consumers, which is the
whole point of the branch:

```markdown
`VerifyRecord` asks whether a record carries its own digest, and nothing about where it
sits. It also refuses a record numbered zero or carrying a malformed hash, because `Append`
mints neither. `Resume` answers a different question — is this the tail — and needs the anchor to do
it. A conversion probe wants the first.

`Replay` builds a chain in memory from field tuples and hands back the records with their
final anchor, for a bulk rewrite that writes the log once. `Append`'s persist parameter
means the chain advances only when the store agrees; passing one that does nothing per
record would satisfy the signature and mean the opposite.
```

Under `## password`:

```markdown
`HashWith` mints at chosen parameters, bounded to the same band `Verify` accepts, for a
test suite that cannot afford 64 MiB per derivation. `Hash` is the suite's answer and what
production code calls. `DummyVerify` spends a verification's cost on a reject path that
never reached one, so a missing account does not answer faster than a wrong password —
though `ErrBusy` returns without deriving, so under load that leak reopens.
```

Under `## keyfile`:

```markdown
`LoadOrCreateEncoded` reads `Raw` and `Base64` as well as hex, because four products
already wrote their key files those ways. `Load` never creates: kypost's daemon must not
mint a key its API process did not, or a restart in the wrong order leaves half the data
under a key that no longer exists. `FromEnv` validates an environment-supplied key the same
way a file-supplied one is validated.
```

Under `## derive`:

```markdown
`AuthSecretContext` bounds the wait for a slot. The budget stays separate from
`password`'s — the two bound different resources, and this package importing `password`
would pull `x/crypto` into it — but `derive.MaxConcurrent`, `password.MaxMemoryKiB` and
`password.MaxLanes` are exported so a product running both can add them up.
```

- [ ] **Step 3: Verify every claim in the README still holds**

Run: `go test -race -count=1 ./...`
Expected: PASS. The README's rule is that nothing is asserted without a test; if a sentence
added above has no test behind it, either write the test or delete the sentence.

- [ ] **Step 4: Confirm the downstream job is green**

Clone gridlock's **paired branch**, not its default — the default branch has not taken
Task 3's `Open` change, so checking it would either fail spuriously or pass vacuously.

Run: `cd /tmp && rm -rf tagprobe && mkdir tagprobe && cd tagprobe && git clone --depth 1 -b feat/library-readiness /home/yoshi/busness.app/gridlock-server && cd gridlock-server && go mod edit -replace github.com/Busnes-app/ky-primitives=/home/yoshi/busness.app/ky-primitives && go build ./... && go test -count=1 ./...`
Expected: PASS. Do not tag until it does.

- [ ] **Step 5: Commit and tag**

```bash
git add README.md
git commit -m "docs: correct the kybookmarks claim, document the new API

The literal is kybookmarks-default-hmac-secret at audit.go:41, not
kybookmarks-audit-default-secret at :44, and the write path no longer reaches
it. The surviving hole is narrower than this file claimed and still real.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"

git tag -a v0.2.0 -m "Capsule manifests, auditchain replay, and a library its consumers can adopt

Every consumer pins this tag. The last release was pinned by three products
and left behind by all of them, because nothing built them against it."
```

---

## Task 12: kybookmarks — fix the four auditchain call sites

**Files:**
- Modify: `/home/yoshi/busness.app/kybookmarks-server/internal/audit/audit.go` at `:233`, `:259`, `:281`, `:345`
- Modify: `/home/yoshi/busness.app/kybookmarks-server/go.mod`
- Modify: `.github/workflows/downstream.yml` (add the consumer)

**Interfaces:**
- Consumes: `VerifyRecord` (Task 5), `Replay` (Task 6), `v0.2.0` (Task 11).
- Produces: a consumer that builds and tests against the tag, and a longer matrix.

**The ordering hazard, which is the whole difficulty.** `Resume` requires
`anchor.Count == last.Seq && anchor.Hash == last.Hash`. The block at `:241-244` exists to
handle a log one entry *ahead* of its anchor — the interrupted-write case, where the record
was written and the process died before the anchor was saved. Under the current library
`Resume` fails before that block is ever reached, so it is unreachable. The fix is to
**detect the overrun first**, then resume.

- [ ] **Step 1: Reproduce the failure**

```bash
cd /home/yoshi/busness.app/kybookmarks-server
git checkout -b feat/library-readiness
go mod edit -replace github.com/Busnes-app/ky-primitives=/home/yoshi/busness.app/ky-primitives
go build ./... 2>&1 | head
```

Expected: four `not enough arguments` errors at `:233`, `:259`, `:281`, `:345`.

- [ ] **Step 2: Read the recovery path before changing it**

Run: `sed -n '200,300p' internal/audit/audit.go`

Identify: where `l.anchor` is populated (`:207`), where `l.stateMissing` is set (`:218-220`),
and the one-ahead adoption at `:241-244`. Do not start editing until you can state what
each of the three does when the state file is absent.

- [ ] **Step 3: Fix `:259` — the format probe**

Replace the `Resume`-as-predicate with the predicate:

```go
	// Is this log already in the shared digest format? That is all this asks. Resume
	// would also assert that the record is the tail, which is a different question and
	// not the one converge needs answered.
	if auditchain.VerifyRecord(l.key, recordOf(entries[len(entries)-1], uint64(len(entries)))) == nil {
		return entries, nil
	}
```

- [ ] **Step 4: Fix `:281` — the bulk rewrite**

Replace the per-record `chain.Append` loop with `Replay`, since the file is written once
after the loop and the anchor saved once after that:

```go
	tuples := make([][]string, 0, len(entries))
	for _, e := range entries {
		tuples = append(tuples, fieldsOf(e))
	}
	records, anchor, err := auditchain.Replay(l.key, tuples)
	if err != nil {
		return nil, err
	}
	converted := make([]Entry, 0, len(entries))
	for i, e := range entries {
		e.PrevHash, e.Hash = records[i].Prev, records[i].Hash
		converted = append(converted, e)
	}
```

Then the existing marshal-and-`writeFileAtomic` at `:289-299` is unchanged, and the anchor
save at `:301-304` uses `anchor` rather than `chain.Anchor()`.

- [ ] **Step 5: Fix `:233` — resume, overrun first**

Restructure so the overrun is detected before `Resume` is called:

```go
	last := recordOf(entries[len(entries)-1], uint64(len(entries)))
	anchor := l.anchor

	// A log one entry ahead of its anchor is the interrupted write: the record reached
	// disk and the process died before the anchor did. Verify that one record against
	// the key and adopt it, rather than refusing a log that is merely mid-write.
	if uint64(len(entries)) == l.anchor.Count+1 && l.anchor.Count > 0 {
		if err := auditchain.VerifyRecord(l.key, last); err != nil {
			return fmt.Errorf("audit: log overruns its anchor and the extra record does not verify: %w", err)
		}
		anchor = auditchain.Anchor{Count: uint64(len(entries)), Hash: last.Hash}
	}

	if l.chain, err = auditchain.Resume(l.key, last, anchor); err != nil {
		return err
	}
```

Delete the now-dead adoption block at `:241-244`.

- [ ] **Step 6: Fix `:345` — Append with a real persist**

Lines `:351-373` are already the record write and the anchor write, already under `l.mu`.
Move them into the callback:

```go
	rec, err := l.chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
		entry.PrevHash, entry.Hash = r.Prev, r.Hash
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.Write(append(data, '\n')); err != nil {
			return err
		}
		// stateMissing means this deployment has deliberately no anchor file. The record
		// is still written; the chain still advances. Returning an error here would stop
		// the logger entirely.
		if a.Count > l.anchor.Count && !l.stateMissing {
			l.anchor = a
			return l.saveState()
		}
		return nil
	}, fieldsOf(entry)...)
```

`Log` needs a `ctx`. If its signature has none, add one and thread it from the callers —
`Append`'s context bounds the wait for the chain lock, and a logger that can block forever
on a hung store is what the parameter exists to prevent.

- [ ] **Step 7: Note what is not fixed**

The record and the anchor go to two files in two directories with no fsync on either. The
comment at `:366-368` already says so: "Entry first, state second. A crash between them
leaves the mark one behind." Moving them inside `persist` does **not** make them one
transaction. Leave the comment, and add:

```go
	// Still two writes to two files. persist makes the chain advance only when both
	// return nil, which is the part that was wrong before; it does not make them atomic.
	// The one-ahead recovery in recover() is what covers the remaining window.
```

- [ ] **Step 8: Fix the key-length hint**

`keyfile` requires a key file to decode to *exactly* the size asked for, and this repo's
own error message at `internal/audit/audit.go:186` tells the operator to run
`openssl rand -hex 64` — which produces 64 bytes, not 32, and which `keyfile` will refuse.

Change the hint to match what is accepted:

```go
		return nil, fmt.Errorf("audit: %s must hold %d bytes of hex (openssl rand -hex %d)", path, keyBytes, keyBytes)
```

- [ ] **Step 9: Build and test**

Run: `go build ./... && go test -count=1 ./...`
Expected: PASS.

- [ ] **Step 10: Pin the tag and drop the false indirect**

```bash
go mod edit -dropreplace github.com/Busnes-app/ky-primitives
go mod edit -require github.com/Busnes-app/ky-primitives@v0.2.0
go mod tidy
grep 'ky-primitives' go.mod
```

Expected: `github.com/Busnes-app/ky-primitives v0.2.0` with **no** `// indirect` — the
package is imported directly, and `go mod tidy` removes the marking.

- [ ] **Step 11: Add it to the downstream matrix**

In ky-primitives, `.github/workflows/downstream.yml`, add under `consumer:`:

```yaml
          - kybookmarks-server
```

- [ ] **Step 12: Commit both**

```bash
cd /home/yoshi/busness.app/kybookmarks-server
git add internal/audit/audit.go go.mod go.sum
git commit -m "fix(audit): move onto the hardened auditchain

This was pinned to a pseudo-version predating the fix that made Resume
require an anchor and Append persist transactionally, so it has been running
the unhardened chain.

The one-ahead recovery now runs before Resume rather than after it, where
the stricter Resume had made it unreachable. The format probe asks
VerifyRecord, which is the question it meant. The bulk rewrite uses Replay,
because a per-record persist that writes nothing is a lie.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"

cd /home/yoshi/busness.app/ky-primitives
git add .github/workflows/downstream.yml
git commit -m "ci: watch kybookmarks-server

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: kypassword — fix the call sites and abandon v0

**Files:**
- Modify: `/home/yoshi/busness.app/kypassword-server/internal/audit/audit.go` at `:230`, `:286`, `:306`, `:383`, and `:81-94`, `:103-111`, `:328-346`
- Modify: `go.mod`
- Modify: `.github/workflows/downstream.yml`

**Interfaces:**
- Consumes: `VerifyRecord`, `Replay`, `v0.2.0`.
- Produces: a consumer with a single-version chain and no `LegacyAnchor`.

**Why the v0 machinery goes rather than gets migrated.** `chainState.LegacyAnchor` (JSON key
`"anchor"`) marks where unkeyed records end. It has three read sites and **no write site** —
`saveAnchor` builds a `chainState` without it, and the field is `omitempty`, so every anchor
save erases it. On any deployment that has logged once, the boundary is already gone.
Rediscovering it by scanning for the first index where only the keyed digest matches is
exactly what an attacker who could write the log would want, since they choose what the
"v0 prefix" looks like. Nothing is in the wild, so this is a dev-data problem: delete the
files and delete the code.

- [ ] **Step 1: Reproduce and read**

```bash
cd /home/yoshi/busness.app/kypassword-server
git checkout -b feat/library-readiness
go mod edit -replace github.com/Busnes-app/ky-primitives=/home/yoshi/busness.app/ky-primitives
go build ./... 2>&1 | head
sed -n '100,135p;160,200p;280,350p' internal/audit/audit.go
```

Expected: four `not enough arguments` errors, and the `chainState`, `loadState`,
`legacyHash` and `legacyChainVerifies` bodies on screen.

- [ ] **Step 2: Confirm LegacyAnchor has no writer**

Run: `grep -n 'LegacyAnchor' internal/audit/audit.go`
Expected: exactly three lines — the two doc-comment lines at `:107-108`, the field at
`:110`, and the single read at `:290`. **No assignment.** If a write site appears, stop:
the field is live and abandoning v0 needs a different plan.

- [ ] **Step 3: Delete the v0 machinery**

- Remove `LegacyAnchor` from `chainState` (`:110`) and its doc comment (`:107-108`).
- Remove the `keyed bool` parameter from `legacyHash` (`:81-94`) and its unkeyed branch
  (`:86-89`); it is HMAC only now.
- In `legacyChainVerifies` (`:328-346`), delete the `case s.legacyHash(e, false)` arm and
  the `unkeyedLimit` parameter with it.
- Delete the `chainVersion` const at `:21` if nothing else references it.
- At `:290-293`, delete `unkeyedLimit := st.LegacyAnchor` and the `st.Count == 0` override.

- [ ] **Step 4: Fix the four call sites**

`:286` becomes `auditchain.VerifyRecord(s.key, recordOf(last)) == nil`.

`:306` becomes `auditchain.Replay`, exactly as in Task 12 Step 4, with `s.rewrite(converted)`
at `:314` unchanged and `s.anchor = anchor` at `:317`.

`:230` gets the overrun-first restructure from Task 12 Step 5, using `s.anchor` and
`recordOf(last)`. Delete the now-dead adoption at `:238-243`.

`:383` moves `:389-414` into the persist callback. Note that `persist` receives a `Record`
and not an `Entry`, so the callback closes over `entry` and derives the JSON inside it:

```go
	rec, err := s.chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
		entry.Index, entry.PrevHash, entry.Hash = int64(r.Seq)-1, r.Prev, r.Hash
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.Write(data); err != nil {
			return err
		}
		if a.Count > s.anchor.Count {
			s.anchor = a
			return s.saveAnchor()
		}
		return nil
	}, fieldsOf(entry)...)
```

`Entry.Index` is zero-based while `Record.Seq` is one-based — that `-1` is load-bearing.

- [ ] **Step 5: Clear the dev chain**

```bash
rm -f "${KYPASSWORD_DATA_DIR:-./data}/audit/audit.jsonl"
rm -f "${KYPASSWORD_CONFIG_DIR:-./config}/audit.state"
```

If either path does not exist, that is fine — there is nothing to clear. **If either file
is larger than a few kilobytes, stop and ask.** A populated audit log is evidence the "nothing
is in the wild" assumption has broken for this product, and that is Yoshi's decision.

- [ ] **Step 6: Build and test**

Run: `go build ./... && go test -count=1 ./...`
Expected: PASS. Tests asserting v0 acceptance should now fail — delete them; they pin
behaviour that has been removed on purpose. Tests asserting v0 *rejection* should pass and
must be kept.

- [ ] **Step 7: Pin the tag and drop the false indirect**

```bash
go mod edit -dropreplace github.com/Busnes-app/ky-primitives
go mod edit -require github.com/Busnes-app/ky-primitives@v0.2.0
go mod tidy
grep 'ky-primitives' go.mod
```

Expected: `v0.2.0`, no `// indirect`.

- [ ] **Step 8: Add to the downstream matrix and commit both**

```yaml
          - kypassword-server
```

```bash
cd /home/yoshi/busness.app/kypassword-server
git add internal/audit/ go.mod go.sum
git commit -m "fix(audit)!: one chain version, on the hardened auditchain

The v0 records go. LegacyAnchor marked where they ended and had three
readers and no writer — saveAnchor omits it and the field is omitempty, so
every anchor save erased it. Rediscovering the boundary by scanning is
exactly what someone who could write the log would want.

Also moves off a pseudo-version predating the fix that made Resume require
an anchor and Append persist transactionally.

BREAKING CHANGE: pre-key audit records are no longer verifiable.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"

cd /home/yoshi/busness.app/ky-primitives
git add .github/workflows/downstream.yml
git commit -m "ci: watch kypassword-server

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: gridlock — pin the tag and print a real share

**Files:**
- Modify: `/home/yoshi/busness.app/gridlock-server/go.mod`
- Modify: `/home/yoshi/busness.app/gridlock-server/internal/backup/recovery_kit.go:18`
- Modify: `/home/yoshi/busness.app/gridlock-server/internal/api/backup_handlers.go:31,67`
- Modify: `/home/yoshi/busness.app/gridlock-server/cmd/server/main.go:182,219`

**Interfaces:**
- Consumes: `v0.2.0`, and the `Open` signature from Task 3.
- Produces: the first fully-current consumer.

- [ ] **Step 1: Show the share card is wrong**

Run: `sed -n '10,25p' internal/backup/recovery_kit.go`

Expected: the card prints `share.Index` and `hex.EncodeToString(share.Value)`. The field
rename to the library's `Share` was applied; the card was not. `shamir.Share.String()` is
unused and `shamir.ParseShare` has **no caller anywhere in the repo** — so a custodian card
this emits cannot be read back by anything.

- [ ] **Step 2: Write a failing round-trip test**

Create `internal/backup/recovery_kit_test.go`:

```go
package backup_test

import (
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/shamir"
	"github.com/Busnes-app/gridlock-server/internal/backup"
)

// A card a custodian is handed must parse back. Indices 1, 3 and 5 rather than 1, 2 and 3:
// consecutive indices make every Lagrange coefficient 1, the combine degenerates to XOR,
// and it passes in any field. That is how the suite's two incompatible fields stayed hidden.
func TestRecoveryKitCardsParseBack(t *testing.T) {
	secret := []byte("a thirty-two byte master key ...")
	shares, err := shamir.Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	html := backup.GenerateRecoveryKitHTML(shares)

	var recovered []shamir.Share
	for _, i := range []int{0, 2, 4} { // shares at index 1, 3, 5
		card := shares[i].String()
		if !strings.Contains(html, card) {
			t.Fatalf("kit does not contain share %d in its parseable form %q", i+1, card)
		}
		s, err := shamir.ParseShare(card)
		if err != nil {
			t.Fatalf("ParseShare(%q): %v", card, err)
		}
		recovered = append(recovered, s)
	}

	got, err := shamir.Combine(recovered)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("Combine returned %q, want %q", got, secret)
	}
}
```

Adjust `GenerateRecoveryKitHTML`'s signature in the test to match the real one — read it
first.

- [ ] **Step 3: Run and watch it fail**

Run: `go test ./internal/backup/ -run TestRecoveryKitCards -v`
Expected: FAIL — the kit contains `1-9f2a…`, not `ky2-3-…`.

- [ ] **Step 4: Print the self-describing share**

In `recovery_kit.go:18`, replace the manual index-and-hex rendering with `share.String()`.
The share is self-describing precisely so a card can carry its own threshold, set id and
checksum; rendering the fields by hand throws all three away.

- [ ] **Step 5: Fix the undecoded backup payload**

`backup_handlers.go:31,67` and `main.go:182,219` build `BackupFile{Data: []byte(f.DataBase64)}`
— passing the base64 **text**, never decoding it, so a sealed capsule holds a base64
transcript of the SQLite file rather than the file. `ky_server_base/internal/api/backup_handlers.go:26`
decodes correctly; copy that. At each of the four sites:

```go
	data, err := base64.StdEncoding.DecodeString(f.DataBase64)
	if err != nil {
		return fmt.Errorf("backup file %q: %w", f.Path, err)
	}
```

and pass `data`. Add `encoding/base64` to the imports.

- [ ] **Step 6: Pin the tag**

```bash
go mod edit -dropreplace github.com/Busnes-app/ky-primitives
go mod edit -require github.com/Busnes-app/ky-primitives@v0.2.0
go mod tidy
```

- [ ] **Step 7: Build and test**

Run: `go build ./... && go test -race -count=1 ./...`
Expected: PASS, including `TestRecoveryKitCardsParseBack`.

- [ ] **Step 8: Commit**

```bash
git add internal/backup/ internal/api/backup_handlers.go cmd/server/main.go go.mod go.sum
git commit -m "fix(backup): print a share a custodian can hand back

The field rename to the library's Share was applied to the card; the format
was not. It printed index and hex, so ParseShare had no caller anywhere in
this repo and nothing could read a card back.

Also decodes the base64 backup payload before sealing it. Four sites passed
the base64 text, so a capsule held a transcript of the database rather than
the database.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: capsule — design the streaming container

**Files:**
- Create: `docs/superpowers/specs/2026-09-02-capsule-streaming-design.md`

**Interfaces:**
- Consumes: `Manifest`, `FileEntry` (Tasks 2 and 4).
- Produces: a design document, and a decision about whether streaming belongs in this
  library at all. **No implementation.**

**Why this is a design task and not an implementation task.** Every task above ships code
because its shape was already settled — the gap was known, the signature followed from it,
and the test could be written first. Streaming is not in that state. The spec names it the
largest unknown in the library phase and says to split it out rather than let it block the
other seven gaps. Writing implementation steps here would mean inventing a chunk framing,
a nonce derivation and a manifest placement in a plan document, where none of them can be
tested — which is the failure this plan's own rules forbid.

So this task produces the design, and the implementation gets its own plan. Tasks 1-14
ship without it; kyrecovery is the only consumer that needs it, and kyrecovery's migration
is Phase 5, which has not been planned yet either.

- [ ] **Step 1: Read the container being replaced**

Run: `sed -n '1,140p' /home/yoshi/busness.app/kyrecovery-server/internal/capsule/stream.go`
Run: `sed -n '260,300p' /home/yoshi/busness.app/kyrecovery-server/internal/capsule/stream.go`

Record, verbatim: the chunk size, how the per-chunk nonce is derived from the base nonce
and the chunk index, the exact per-chunk AAD string, and where `manifest.json` sits relative
to `payload.stream.enc` in the tar.

- [ ] **Step 2: Measure what it actually holds in memory**

Run:

```bash
cd /home/yoshi/busness.app/kyrecovery-server
grep -rn 'PackDirectoryStream\|UnpackToDirectoryStream' --include='*_test.go' .
go test ./internal/capsule/ -run Stream -benchmem -v 2>&1 | tail -20
```

The claim this container exists for is constant memory. Confirm it holds before designing a
replacement for it — if the existing one already scales with payload size, the requirement
is different from what the comment says and the design changes accordingly.

- [ ] **Step 3: Answer the three questions the design turns on**

Write the answers down before proposing an API. Each has a wrong answer that looks fine:

1. **Can the manifest be authenticated before the first byte is written?** A streaming
   reader that writes as it decrypts has already put attacker-influenced bytes on disk by
   the time it learns the manifest was rewritten. Either the manifest is authenticated
   independently and first, or extraction stages to a temporary location and moves on
   success — and the second costs the disk space the streaming was meant to save.
2. **What stops a chunk being reordered or dropped?** Each chunk authenticates on its own,
   so without the index bound into the nonce *and* the AAD, a database's pages can be
   permuted freely and every chunk still verifies. A truncated stream must also be
   distinguishable from a complete one, which means a length or a terminator inside the
   authenticated data.
3. **Does this belong in `ky-primitives` at all?** The bar for this library is that
   divergence between copies silently corrupts or loses recovery data. One product has one
   streaming container and no second copy exists to diverge from. That is a genuine
   argument for leaving it in kyrecovery and hardening it there, and it should be made and
   rejected on the record rather than skipped.

- [ ] **Step 4: Write the design document**

Create `docs/superpowers/specs/2026-09-02-capsule-streaming-design.md` covering: the answers
from Step 3, the proposed `SealStream`/`OpenStream` signatures with a `FileSource` that
opens lazily, the wire layout, and how it reuses `extract.go`'s containment rather than
growing a second extraction path. A second copy of a refusal is how one of them stops
matching the other.

State explicitly whether the recommendation is to build it here or leave it in kyrecovery.

- [ ] **Step 5: Commit and stop**

```bash
git add docs/superpowers/specs/2026-09-02-capsule-streaming-design.md
git commit -m "docs: design the streaming capsule container

The spec named this the largest unknown in the library phase. It is a design
question — manifest-before-payload authentication, chunk reorder defence,
and whether one container with one copy meets this library's bar at all —
not something to settle inside an implementation plan.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

**Then stop and bring the design back for review.** Implementation gets its own plan, after
the recommendation in Step 3.3 is accepted or rejected.

---

## What this plan does not cover

The spec's Phases 3-8 — the six product migrations — are **not** in this plan, deliberately.
Their tasks depend on API this plan delivers: kypost's `password` adoption needs `HashWith`
from Task 7 and `Load` from Task 9; kyrecovery's capsule work needs `ReadUnverifiedManifest`,
`FileEntry` and `SealStream`. Writing their steps now would mean inventing signatures for
functions that do not exist yet, which is the failure mode this plan's own rules forbid.

Each gets its own plan, written after `v0.2.0` is tagged:

| Plan | Covers | Adopts | Blocked on |
|---|---|---|---|
| 2 | Streaming capsule implementation | — | Task 15's design being accepted |
| 3 | ky_server_base, then re-fork gridlock | shamir, capsule, password, totp, recoverycode, keyfile | v0.2.0 |
| 4 | kysignon-server | password, totp, recoverycode, keyfile, shamir, capsule | Plan 3 (scaffold first) |
| 5 | kyrecovery-server | shamir, capsule, auditchain, password, keyfile | Plan 2 |
| 6 | kynotes-server | derive, password, keyfile | v0.2.0 |
| 7 | kypost-server | derive, totp, recoverycode, password, keyfile | v0.2.0 |
| 8 | kybookmarks (password, keyfile) and kydns | password, keyfile | v0.2.0 |

Plans 6, 7 and 8 depend on nothing but the tag, so they can run alongside 3 and 4. Only
Plan 5 waits on the streaming decision, and only Plan 4 waits on the scaffold.

Each adds its repo to `.github/workflows/downstream.yml`, which is how the matrix ends up
holding all nine.
