# Migrating the Busness.app suite onto ky-primitives

Design, 2026-09-02.

## Goal

Every Ky product uses `ky-primitives` for the primitives it duplicates today, and no
breaking change to the library can reach a release without failing in the pull request
that made it.

The second half is the durable part. The first half is a snapshot that starts rotting
the day it lands.

## Non-goals

- **Building audit chains where none exist.** Five repos have flat audit tables with no
  sequence, no previous hash and no anchor. Giving them a tamper-evident chain is a
  feature, tracked separately.
- **Consolidating HTTP, session, header or rate-limit code.** Real debt, but per-product
  configuration rather than a durable format. Fixed in place.
- **Data migration of any kind.** See "Nothing is in the wild" below.

## Decisions taken

| Decision | Consequence |
|---|---|
| Nothing is in the wild anywhere | No compat shims, no dual-format readers, no rehash-on-login, no format converters. Dev artefacts are deleted, not migrated. |
| KyPassword abandons its v0 audit records | `auditchain` needs no version concept. KyPassword re-anchors from the first keyed record. |
| scrypt products move to Argon2id | kynotes, kypost and kybookmarks adopt `password`. One hash across the suite. |
| Scaffold first, then re-fork gridlock | `ky_server_base` migrates fully; gridlock is reconciled back to it rather than migrated independently. |
| Close every library API gap before migrating | Phase 1 is library work. Products adopt a library that fits them. |
| `auditchain` is migration-only | Goes to kybookmarks, kypassword and kyrecovery. The other five keep flat tables. |
| Each product seals and restores its own capsule (2026-09-03) | kyrecovery stores ciphertext, reads `UnverifiedManifest` for display, and attests only "unchanged since deposit". It never holds a `Manifest`, a key, or another product's plaintext. Phase 5 becomes a deletion of `internal/capsule` and `internal/adapter`, plus a keyless streaming `Inspect`. |
| Kyrecovery coordinates the share ceremony blind (2026-09-03) | Products split the key. Custodians hold shares. At recovery the fresh product instance pairs with kyrecovery and publishes an ephemeral public key; custodians submit shares encrypted to it and kyrecovery relays opaque blobs. Kyrecovery may hold exactly one share as a custodian, never more; threshold is at least 2. Rejected: kyrecovery running the ceremony and seeing the key, even transiently. |

### One suite-wide recovery keypair (decided 2026-09-03)

`Seal` mints a fresh key per capsule. Shares per capsule would mean a ceremony per backup,
so instead the suite has one long-lived recovery keypair. Kyrecovery generates it in a
one-time ceremony, splits the 32-byte seed into custodian shares, shows the cards, and
destroys the ephemeral ceremony host without persisting the seed — the single, recorded
exception to "kyrecovery never holds the key". Each app receives the public key at pairing
over the authenticated channel and stores only that; kyrecovery pins the key ID it handed
out and refuses deposits sealed to any other. Sealing needs no secret and the ceremony runs
once. k custodians can open
every product's backups; the custodians are the same people, so that is accepted and noted.
Rejected: per-capsule shares; per-product keypairs (N ceremonies for no separation anyone
would use); any product holding the private key.

Consequences for the library: `capsule` seals to a public key with `crypto/hpke` (Go 1.26
stdlib) using the X-Wing hybrid KEM, and the encapsulated key and key ID ride in the
authenticated manifest of both containers. A `recoverykey` package owns the keypair and
the split. Designed in `2026-09-03-recovery-keypair-design.md`, ahead of Plan 2.

### Nothing is in the wild

This single fact removes most of the work the survey found. It is load-bearing: if it
turns out to be false for any product, that product's phase stops and gets a migration
path designed for it. It does **not** dissolve the API gaps in Phase 1 — those are
shape problems, not data problems.

What it dissolves, specifically: kypost's synthetic-salt separator (`|` vs `\x00`,
documented at `login_params.go:141-143` as credential-invalidating); every stored scrypt
hash in kynotes, kypost and kybookmarks; every recovery-code digest under the old
uppercase alphabet; kysignon's 0x11d shares; kydns' raw-byte `node_key`; kynotes' and
kypost's base64 key files; kyrecovery's indexed tar capsules.

## Measured current state

Three products already import the library. All three are pinned behind a `refactor!`
and every hardening fix since.

| Product | Adopted | Pinned at | Against HEAD |
|---|---|---|---|
| gridlock-server | capsule, shamir | `v0.1.0` | Compiles. **Wire format changed underneath it.** |
| kybookmarks-server | auditchain | `v0.1.1-0.20260902141005-22c2f8cd0e0e` | 4 call sites fail to compile |
| kypassword-server | auditchain | same pseudo-version | 4 call sites fail to compile |

gridlock is the instructive one. At `v0.1.0` a share printed as `3-9f2a71c4`; at HEAD it
prints as `ky2-<threshold>-<128-bit set id>-<index>-<value>-<check>`. Verified: HEAD's
`ParseShare` rejects the old form with `shamir: share is not ky2 format: 2 fields, want 6`
rather than returning a wrong secret, so the break is loud. But nothing anywhere noticed
that it happened.

Both stale pins also predate the auditchain hardening, so kybookmarks and kypassword are
running the pre-fix `Append` — unanchored `Resume`, non-transactional persist — today.

## Root cause

Nothing builds a consumer against the library. `ci.yml` runs `go build`, `go vet`,
`go test -race` and `govulncheck` on ky-primitives alone. A breaking change is green in
the library's own pull request and surfaces months later, in a product nobody rebuilt, as
a compile error at best and a format break at worst.

Every phase below is downstream of fixing that.

---

## Phase 0 — Downstream CI

**Deliverable:** a `downstream` job in `.github/workflows/ci.yml` that, for each consumer
repo, checks it out, adds `replace github.com/Busnes-app/ky-primitives => <this checkout>`,
and runs `go build ./...` and `go test ./...`.

Runs on pull requests. Failing it means the library change broke a consumer, reported to
the person making the change while they are still making it.

The consumer list starts as the three already-migrated products and grows by one line as
each phase lands. That list is the plan's progress bar.

Two constraints:

- The job needs read access to private `Busnes-app` repos. A token with `contents: read`
  on the org, or the repos are public. Resolve before writing the job — this is the one
  step that can be blocked by something outside the code.
- `replace` must point at the checkout, not a version. A consumer pinned to a tag would
  test the tag, not the change.

Phase 0 lands **before** Phase 1, so the library work is watched from the first commit.

---

## Phase 1 — Close the library gaps, tag v0.2.0

Products cannot adopt what the library cannot express. gridlock already proves this: it
re-`json.Unmarshal`s sealed capsule bytes into a locally-declared struct at
`capsule.go:71-76` because `capsule`'s manifest type is unexported. Migrating eight more
repos into the same library reproduces that workaround eight more times.

### capsule

| Gap | Needed by | Shape |
|---|---|---|
| No manifest accessor | gridlock, kysignon, kyrecovery | Export the manifest type and a `Manifest(raw []byte) (Manifest, error)` that reads it **without a key**. kyrecovery has six keyless manifest reads driving TUI quorum display, `diff.CompareManifests` and drill path selection. |
| ~~No in-memory `Open`~~ | — | **Not a gap.** Verified by running it: `Open(raw, key, "")` returns the files and writes nothing. The survey was wrong. |
| No streaming container | kyrecovery | `stream.go` is a **third container** (`version:2`, `payload.stream.enc`, 1 MiB chunks, per-chunk nonce and AAD) that the README's retirement table does not mention. Multi-GB database capsules have no path forward through `Seal([]File)`. |
| No per-file digest or declared size | kyrecovery | `File{Path,Content,Mode}` cannot reproduce the per-file SHA-256 verification at `capsule.go:287-297`. Needs `Sum` and `Size` on `File`, or an equivalent. |
| No `Dependency` / `FileEntry` types | kyrecovery | Three interface signatures depend on them: `adapter.VerifyRestore`, `diff.CompareManifests`, `export.KitData`. |

`Seal` taking `Files map[string][]byte` in kyrecovery versus an ordered `[]File` here is a
real behaviour change: map iteration order currently determines tar order, so capsule bytes
become reproducible only after the migration fixes an order. That is an improvement; note it.

### auditchain

| Gap | Needed by | Shape |
|---|---|---|
| No digest-only predicate | kybookmarks `:259`, kypassword `:286` | Both `converge()` probes ask "does this record carry its own digest under this key". The only way is `Resume`, which now *also* asserts tail-ness — so the probe silently changed meaning. Needs `VerifyRecord(key, Record) error`. |
| `Resume` rejects the one-ahead anchor | kybookmarks `:241-244`, kypassword `:238-243` | Both have a deliberate, tested recovery for a log one entry ahead of its anchor — the interrupted-write case. HEAD's `Resume` fails before that block is reached, making it dead code. **Decision: the library keeps the strict invariant; the products restructure.** Weakening `Resume` to tolerate an anchor behind the log re-opens exactly the hole `9125dd4` closed — the anchor is the only thing that knows where the end is, and a `Resume` that accepts a record from the middle mints a sequence number that already exists. Each product detects the overrun first, verifies the one extra record against the anchored tail, synthesises the caught-up anchor, then calls `Resume` with it. This needs no new library API beyond `VerifyRecord`. |
| No bulk replay | both `converge()` loops | Both rebuild a whole chain in memory and persist once, with `rewrite()` writing the file atomically after the loop. A per-record `persist` there is a lie to the API — it would return nil having written nothing. |

`Anchor` gains no third field: KyPassword abandons v0.

### password

| Gap | Needed by | Shape |
|---|---|---|
| No cost override for tests | kypost | `SetHashCostForTest` drops N from 2^17 to 2^14 across ~14 derivation sites. `hashWith(plaintext, Params)` is unexported and `Hash` takes only a plaintext, so the suite would pay 64 MiB × t=3 per derivation with no supported way down. **This alone blocks kypost.** |
| No dummy-verify | kysignon | `DummyVerify` at `auth/password.go:88` is the anti-enumeration timing equaliser on four reject paths. `ErrBusy` returning fast reintroduces the oracle. |
| No `NeedsRehash` for foreign formats | kypost | kypost's returns `false` for a format it did not write, deliberately. `password.NeedsRehash` returns `ErrMalformed`. Cheap to align. |

### keyfile

Four repos cannot call `LoadOrCreate` as it stands.

- **Hex-only.** kydns' `node_key` is 32 raw ed25519 seed bytes; kysignon's `secret.key` and
  `encryption.key` are raw; kynotes and kypost write base64. Needs a raw variant or an
  encoding parameter.
- **Exactly `size`.** Three loaders accept `>= 32`. kybookmarks' own error message tells
  the operator to run `openssl rand -hex 64`, which `keyfile` would then reject.
- **No env override.** kybookmarks (`AUDIT_KEY`), kypassword, kysignon and kyrecovery all
  check the environment first. Leaving that outside the call means the env-supplied key
  skips `keyfile`'s validation unless every caller duplicates it.
- **No read-only variant.** kypost splits `LoadOrCreateKey` from `LoadKey` on purpose:
  the daemon process must never mint a key the API process did not. `cryptutil.go:165-169`
  names the failure. `keyfile` exposes only `LoadOrCreate`.

`RequireOwnerOnly` firing on the read path is intended and correct, but it is a breaking
change at rollout. It goes in release notes.

### recoverycode

`MatchCode(code, digests, hash func(string) string)` appears not to fit kypost, which
short-circuits on first match deliberately (`users.go:1838-1842`: "deriving against them
anyway would make a correct code the most expensive request"). At ten codes × Argon2id-64
MiB, a non-short-circuiting scan is a per-request denial of service.

(The survey also reported a format mismatch here. It was wrong: verified by running it,
`recoverycode.Generate(3)` returns `["fu25-msqo-s531" …]` — already `xxxx-xxxx-xxxx`,
already kypost's shape.)

**Decision: the conflict is a symptom, and the fix is in kypost's storage, not the API.**
`MatchCode` scans every entry so the *position* of the match does not leak through response
time. That costs nothing when the digest is cheap — which is the case in `ky_server_base`,
gridlock and kysignon, all of which store a bare SHA-256. kypost is the outlier: it stores
recovery codes as *salted scrypt*, so each comparison needs its own derivation, and a full
scan becomes ten derivations.

A recovery code is 60 bits of uniform randomness, not a user-chosen password. It does not
need a slow KDF — that is what defends a low-entropy secret against offline search, and
there is nothing here to search. Storing `sha256(Normalize(code))` makes the whole scan a
few microseconds, constant-time in the match position, and immune to the amplification
kypost is guarding against. `recoverycode`'s `hash func(string) string` signature — no
`ctx`, no error — already assumes exactly this.

So Phase 7 changes kypost's recovery-code storage to a cheap digest, and `MatchCode` needs
no change. `password` stays for actual passwords.

### derive

- No `context.Context`. Every kypost derivation is ctx-aware; `kdf.go:104` checks
  `ctx.Err()` before queueing so a departed client does not jump the queue. `derive`'s
  acquire is a bare two-second timer.
- `derive` and `password` hold **two independent budgets**. kypost deliberately puts all
  memory-hard work under one process-wide semaphore (`kdf.go:29-32`: "A ceiling that half
  the callers walk around is not a ceiling"). Adopting both splits that ceiling in two.
  The README defends the split — `derive` is standard-library-only and importing
  `password` would pull `x/crypto` into it. That reasoning holds for the dependency
  budget and fails for the resource budget. Resolve: either an injectable limiter both
  packages accept, or document that a product adopting both must configure them together.

`derive.SyntheticSalt`'s hardcoded `\x00` separator and `AuthSecret`'s label parameter
need no change — with nothing in the wild, kypost simply moves to the library's spelling.

### Exit criteria

`go test ./...` green, the Phase 0 downstream job green against all three existing
consumers, and **v0.2.0 tagged**. Every subsequent phase pins a tag, never a pseudo-version.

---

## Phase 2 — Unstick the three existing consumers

Smallest phase, highest value: it makes the library's consumer contract true.

- **kybookmarks-server** — fix the four call sites. `:233` passes `l.anchor`, already in
  hand from `:207`, but the one-ahead recovery at `:241-244` must be restructured to run
  *before* `Resume`. `:259` becomes `VerifyRecord`. `:281` becomes the bulk replay. `:345`
  moves lines `:351-373` into the `persist` callback — they are already the record write
  and the anchor write, already under `l.mu`. Drop the `// indirect` marking.
- **kypassword-server** — same four fixes at `:230`, `:286`, `:306`, `:383`. `:383`'s
  `entry.Index = int64(rec.Seq)-1` moves inside the callback, which receives a `Record`
  and not an `Entry`, so it must close over `entry`. Then abandon v0 (below).
- **gridlock-server** — bump `v0.1.0` to `v0.2.0`. Fix `recovery_kit.go:18`, which still
  prints `share.Index` + bare hex instead of `Share.String()`: the field rename was applied
  but the card was not. `shamir.ParseShare` has no caller anywhere in the repo.

Note two things found in gridlock that are not migration work but sit in the same files:
`backup_handlers.go:31,67` and `main.go:182,219` build `BackupFile{Data: []byte(f.DataBase64)}`
without decoding, so sealed capsules contain a base64 transcript of the SQLite file. The
base decodes correctly at `backup_handlers.go:26`. Fix while re-forking.

### Abandoning KyPassword's v0 records

`chainState.LegacyAnchor` (JSON key `"anchor"`, not `"legacyAnchor"`) marks where unkeyed
records end. It has **three read sites and no write site** — `saveAnchor` omits it and the
field is `omitempty`, so every anchor save erases it. On any deployment that has logged
once, the boundary is already gone and must be rediscovered by scanning for the first index
where only the keyed digest matches.

With nothing in the wild this is a dev-data problem: delete `audit.jsonl` and `audit.state`,
start clean. Then delete the machinery — `legacyChainVerifies`' `unkeyedLimit`, the
`!keyed` branch of `legacyHash`, the `chainVersion` const, and `LegacyAnchor` itself.

The same applies to kybookmarks' `legacyDefaultSecret`. Correcting the record: the literal
is `"kybookmarks-default-hmac-secret"` at `audit.go:41`, not `"kybookmarks-audit-default-secret"`
at `:44` as `README.md:180` states, and the **write path no longer reaches it** —
`loadOrCreateKey` has no constant fallback. The surviving hole is narrower: a wholly-forged
v0 log on a first boot with no state file converts cleanly through `converge` and verifies
forever. Post-migration, `HMAC_SECRET`, `legacyDefaultSecret`, `legacyKey`, `legacyHash`,
`legacyVersions`, `version0`/`version1` and `chainHash` are all deletable. Fix the README.

---

## Phase 3 — ky_server_base, then re-fork gridlock

The scaffold goes first so every future product inherits the primitives.

**Adopts:** `shamir`, `capsule`, `password`, `totp`, `recoverycode`, `keyfile`.
**Does not adopt:** `auditchain` (no chain exists), `derive` (no PBKDF2/HKDF anywhere).

The keyfile adoption is the one that fixes a live bug rather than deduplicating code:
`config.go:107-121` mints a random key in memory when `KY_ENCRYPTION_KEY` is unset outside
production, so the AES-GCM key that decrypts `users.totp_secret_enc` rotates on every
restart.

Two adoptions carry a schema change, not a swap:

- `totp.Validate` returns a counter that must be recorded to defend against replay. There
  is no `totp_last_counter` column in `migrations.go`. Adding one is the point of adopting
  the package; without it the bare-bool behaviour is unchanged.
- `recoverycode` documents blanking a redeemed slot in place. `RedeemRecoveryCode:63`
  removes and renumbers, which is how two concurrent redemptions lose each other's write.

`testdata/shamir-vectors.json` and `shamir_vectors_test.go` are deleted, not ported: the
vectors are 0x11d, and `ParseShare` accepts only the `ky2-` string form. gridlock already
did this.

**`scripts/ky-init.sh` needs one change.** The module `sed` at `:42` is safe — the two
paths do not prefix-collide. `MODULE_OLD` at `:38` is hardcoded, which is why gridlock's
copy had to be hand-edited; derive it with `go list -m`. (An earlier draft said `go mod
tidy` at `:62` would need `GOPRIVATE`; it does not — `ky-primitives` is a public module and
resolves through the proxy. Corrected 2026-09-03.)

**Re-fork gridlock** against the migrated scaffold. `internal/crypto/crypto.go`,
`internal/auth/totp.go` and `internal/auth/recovery.go` were byte-identical to the base's
(verified with `diff -q`) before the migration; the scaffold's migration rewrites all three,
so they arrive with the fresh tree and need no reconciliation.

Planned 2026-09-03 as two documents in `ky_server_base/docs/superpowers/plans/`:
`2026-09-03-scaffold-adopts-ky-primitives.md` and `2026-09-03-gridlock-refork.md`. The
decisions those plans take beyond this section (drill seals to a throwaway keypair; the kit
export becomes a `.kycap` download; the public key and k/n arrive in the pairing claim
response, so pairing is red until Phase 5; gridlock's hand-rolled SCIM is dropped for the
scaffold's, flagged) are tabled at the top of each plan.

---

## Phase 4 — kysignon-server

**Adopts:** `password`, `totp`, `recoverycode`, `keyfile`, `shamir`, `capsule`.
**Does not adopt:** `auditchain` (no chain), `derive` (`crypto.DeriveKey` is
`HMAC(master, label)`, a different construction).

Largest single phase. Notes:

- Its `ExtractCapsule` **is** the code that was ported into ky-primitives, so `capsule.Open`
  is a genuine deduplication rather than a behaviour change.
- `kycap/1` is retired. `SerializeCapsule`/`ParseCapsule`/`KitStore`'s in-memory `*Capsule`
  flow all restructure around `Seal → []byte` plus the new manifest accessor.
- Its shares are **0x11d** — the dead field. All cards are void, which with nothing in the
  wild costs nothing. Thirteen field-dependent sites must move together; a mixed build
  returns a wrong key with a nil error.
- `internal/crypto/crypto.go:230-287` `LoadOrCreateRSAKey` is a PEM keypair, out of
  `keyfile`'s scope. It stays.
- `audit.go`'s `Prepare`/`Pending.Committed()` two-phase pattern hands a row *to* the
  caller's transaction; `auditchain.Append` inverts that, calling `persist` under its own
  lock. Since auditchain is out of scope here, this only matters if the follow-up audit
  project reaches this repo. Record it there.

---

## Phase 5 — kyrecovery-server

**Adopts:** `shamir`, `capsule`, `auditchain`, `password`, `keyfile`.
**Does not adopt:** `totp`, `recoverycode`, `derive` (no surface for any of the three).

- **Its Shamir is already 0x11b** — the same field as ky-primitives. Share values are
  numerically compatible; only the encoding and the API shape change. Fourteen
  field-dependent sites still move together.
- `crypto.Combine(shares, threshold)` skips duplicate indices and takes the first `threshold`
  unique ones; `shamir.Combine` returns `ErrDuplicateIndex` and uses every share. Two sites
  (`server.go:700-706`, `app.go:411`) silently drop unparseable shares today, which becomes
  a wrong-count error. That is the improvement; the error messages need rewriting
  (`ceremony.go:207` still says "expected index-hex").
- `Pack` silently coerces bad topology (`threshold<2 → 2`); `Seal` errors. `server.go:464`
  and `:994` pass client-supplied values straight through, so requests that succeed today
  will start failing. Validate at the handler.
- Password hashes are **hex hash + hex salt in two columns**, with no parameters recorded.
  The parameters happen to match `DefaultParams` exactly, so a PHC string is reconstructible
  in principle — but with nothing in the wild, reset instead.
- **Two bugs to carry into the migration rather than reproduce.** `VerifyChain` reads a
  fixed `ListAuditEvents(ctx, 100000)` and asserts `SequenceNum == i+1` against a
  descending-then-reversed page, so a chain over 100000 reports "sequence gap at index 0"
  on a perfectly intact log — `VerifyStream` removes the reason to page. The same limit
  caps `rekeyLegacyChain`, which is worse: a deployment past 100000 pre-key events re-keys
  only the newest page and then writes `ledger.keyed`, permanently orphaning the rest.
- `ChainStatus{Valid, Count int64, LastHash}` is `Anchor` plus a flag, but computed on
  demand and **never stored**. `Resume` and `Verify` both need an anchor that does not
  exist yet: a column, written in the same transaction as the record, inside `persist`.
- `internal/adapter/kypassword.go` crosses no repo formats. It is a declarative file-capture
  recipe; it does not read KyPassword's `audit.state` or its hashes. Orthogonal.

---

## Phase 6 — kynotes-server

**Adopts:** `derive`, `password`, `keyfile`.
**Does not adopt:** `totp` (none exists), `auditchain`, `capsule`, `shamir`,
`recoverycode` (see below).

The cleanest phase. `derive.AuthSecret` is **already bit-identical**: ky-primitives'
golden vectors were produced from kynotes' own implementation, use the same fixture salt
and password as `web/src/crypto.test.ts:6`, and match `testdata/protocol/auth_vectors.json`.
`derive.SyntheticSalt` is pinned in ky-primitives against kynotes' spelling. Four programs
— Go server, WebCrypto path, pure-JS fallback, library — already agree.

Adopting `derive` and `password` deletes kynotes' only uses of pbkdf2, hkdf and scrypt, so
`x/crypto` leaves its direct requires and returns as an inherited one through ky-primitives.

`recoverycode` does **not** fit: kynotes stores exactly one client-supplied recovery code in
`users.recovery_hash` with a `recovery_used_at` timestamp. `recoverycode` assumes
server-side generation of an array with blank-in-place redemption. Leave it.

Watch: `derive.SyntheticSalt` enforces a 32-byte minimum key, while `config.go:107-115`
silently `continue`s past a corrupt `serversalt.key` leaving `ServerSaltKey == ""`. The
migration turns a silent weak salt into a hard error at every login-params request. That
is correct and it is a behaviour change.

---

## Phase 7 — kypost-server

**Adopts:** `derive` (AuthSecret and SyntheticSalt), `totp`, `recoverycode`, `password`,
`keyfile`. `recoverycode` is a drop-in on format — only the storage change below applies.
**Does not adopt:** `auditchain`, `capsule`, `shamir`.

`internal/totp` is a near-exact clone of the library's — same arithmetic, same
`(int64, bool)` return, same `url.Values` query — and is the cleanest single deletion in
the suite. Only the label escaping differs: kypost escapes the colon
(`KyPost%3Aalice`), the library does not. Enrolled secrets are unaffected; the URI string
changes.

Two things must **not** migrate:

- `HashDeviceSecret` (`users.go:1913`) is `sha256:<hex>` and deliberately not a password
  KDF. Its legacy branch calls the scrypt verifier; that branch goes with the reset.
- `frontend/src/lib/keyVault.ts` is a second, separate PBKDF2 derivation with a
  per-envelope random salt and no HKDF label. No Go counterpart. `E2E_PGP.md:35-39` names
  Argon2id as its eventual target — out of scope here.

kypost cannot drop `x/crypto` regardless: `go-crypto`, `gopenpgp/v3`, `go-jose/v4` and
`webpush-go` all pull it.

This phase depends on Phase 1 delivering the `password` cost override, the `keyfile`
read-only variant and the `recoverycode` short-circuit. Without all three it does not land.

---

## Phase 8 — kybookmarks-server (password) and kydns-server

Both small, both last because nothing depends on them.

**kybookmarks** adopts `password` (six hash sites, four verify sites) and `keyfile` (two
loaders). Its stored hash is bare hex with the salt in a separate column and the parameters
nowhere, so `strings.HasPrefix(h, "$argon2id$")` distinguishes old from new trivially —
useful if the "nothing in the wild" assumption turns out to be wrong here. Its `auth_salt`
is **client-supplied and served back** via `/api/auth/login-params` so the browser can
derive `authSecret`; that salt stays a client-facing value and stops participating in the
server-side hash. Two different jobs that happened to share a column.

`loadOrCreateSaltKey` at `server.go:54` returns `[]byte` with no error and panics on RNG
failure; `NewServer` at `:80` cannot fail today. Adopting `keyfile` forces one of the two
to change.

**kydns** is the cleanest `password` adoption in the suite: its stored PHC strings are
already mutually parseable with the target (`p=2` is inside the accepted `p 1..16` bound),
so existing hashes verify unchanged and `NeedsRehash` correctly flags them for upgrade to
`p=4`. Migrating also fixes three real bugs — `Sscanf` accepting `v=19GARBAGE` and
`p=2TRAILINGGARBAGE`, stored `m`/`t` reaching `argon2.IDKey` with no bounds check at all
(a rewritten row asks for 4 TiB and OOM-kills the process on the next login), and no
concurrency bound whatsoever on a verify called inline in the HTTP handler.

Note the argument order swaps: `VerifyPassword(encoded, plaintext) bool` becomes
`password.Verify(plaintext, encoded) (bool, error)`. And `auth_handlers.go:116` currently
answers 401 and spends a backoff strike on any falsy result — `ErrBusy` must answer 503
and spend nothing.

`node_key` is 32 **raw** bytes and needs Phase 1's raw variant. `bootstrap-token` and
`setup-token` are write-only, deliberately re-minted, and not `keyfile` candidates.

---

Two repos are touched in two phases, deliberately. **gridlock-server** is unstuck in
Phase 2 (bump the pin so it builds) and re-forked in Phase 3 (reconciled against the
migrated scaffold) — the base64 bug below is fixed in Phase 3, not Phase 2.
**kybookmarks-server** has its auditchain break fixed in Phase 2 and adopts `password`
and `keyfile` in Phase 8. Everything else is touched once.

## Testing

Each phase is green before the next begins. Green means:

1. The product's own suite passes.
2. The Phase 0 downstream job passes with the product added to its list.
3. For any phase touching a durable format, a round-trip test in the *product* — not only
   in the library — covering a non-degenerate case. For `shamir` that means share index
   sets other than `{1,2,3}`: consecutive indices make every Lagrange coefficient 1, the
   combine degenerates to XOR, and it agrees in any field. That is precisely how the
   0x11d/0x11b split hid.

Phase 1 additionally requires golden vectors for every format it touches, derived by hand
or from a published document rather than read off the implementation.

## Risks

| Risk | Handling |
|---|---|
| "Nothing is in the wild" is wrong for some product | That phase stops and gets a migration path. The assumption is stated per-phase so it fails loudly rather than silently. |
| Phase 0 blocked on private-repo credentials | Resolve before Phase 1. It is the only step gated on something outside the code. |
| Phase 1 grows without bound | Its scope is exactly the gaps in this document. A gap found later is a new decision, not an extension. |
| A phase lands on a pseudo-version again | Phases 2 onward pin a tag. The downstream job makes a stale pin visible immediately. |
| kyrecovery's streaming container turns out to need a different design | It is the largest unknown in Phase 1. If it does, split it into its own phase rather than blocking the other seven gaps. |
