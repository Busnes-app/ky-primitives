# ky-primitives

Shared security primitives for the Busness.app suite.

The `offsite/` directory is a separately versioned nested module. Its transport
dependencies are not requirements of this root module.

The root module's dependency budget is **`golang.org/x/crypto` and the `golang.org/x/sys` it drags in,
and nothing else.** In that module, everything but `password` is standard-library-only. The rule was "no
dependencies, ever" so that products with minimal trees could import this for free —
`kypassword-server`'s `go.mod` named no third-party module at all, and now names exactly
one: this library — and Argon2 is the one thing that broke it: the suite standardised on it for password hashing, and it is neither in the
standard library nor on a proposal track.

Two tests hold that line. `TestModuleDependenciesAreAllowlisted` fails on any `require`
outside the budget; `TestOnlyPasswordImportsADependency` discovers every other package and
fails if any of them imports one. A consumer that only wants `capsule` compiles none of
`x/crypto`, but it does inherit the requirement in its own `go.mod` — that is the cost.

`go list -m all` names five `golang.org/x` modules because they sit in `x/crypto`'s own
requirement graph. Only two reach `go.sum`, and the build compiles three packages:
`x/sys/cpu`, `x/crypto/blake2b` and `x/crypto/argon2`.

A primitive belongs here when the suite's copies of it disagree in a way that silently
corrupts or loses recovery data. Duplicated HTTP, session and header code across the suite
is real security debt, but it is per-product configuration rather than a durable format, so
it is fixed in place rather than moved here.

## capsule

Reads and writes the suite's encrypted backup container.

`kycap/3`: a JSON object holding the manifest, a base64 ciphertext, and nothing else. The
payload is sealed to the suite recovery public key through HPKE — X-Wing (ML-KEM-768 with
X25519), HKDF-SHA256, AES-256-GCM — so `Seal` returns no key and a product that seals a
backup holds nothing afterwards that opens it. The public key is not secret, so a
successful `Open` proves the container is unmodified and was sealed to this key — not who
sealed it, and not that it is the newest backup; origin and freshness come from
kyrecovery's authenticated deposit record, and a restore must check `service_name`,
`capsule_id` and `created_at` against what it expects. The manifest is bound into the
AEAD, so every field describing the capsule is authenticated rather than merely present,
and it is carried and authenticated as the exact bytes that were read, not a re-encoding.

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

`Open` returns the manifest because a successful `Open` is the proof that the container was
not modified after sealing and was sealed to this recovery key — nothing more; see
`capsule.Open`'s doc comment for what that does and does not prove. `Seal` returns one too:
`capsule_id`, `created_at`, `payload_hash` and
`encapsulated_key` are minted inside `Seal` and have no other source.
`ReadUnverifiedManifest` returns a different type, `UnverifiedManifest`, so the compiler
stops it reaching anything that decides on it.

`errors.Is` a failed `Open` against `ErrWrongRecoveryKey` for the wrong kit, against
`ErrUnknownContainer` for a retired or foreign format, and against `ErrCorruptCapsule` for
a malformed container; an AEAD failure wraps none of them.

The ciphertext field is standard base64 in and out.

### Extraction hardening

The payload decrypts to a gzipped tar, extracted through this hardened path. It is ported
from `kysignon-server`, which carried the strongest version in the suite — stronger than
the checks `kyrecovery-server`'s own `Unpack` ever applied to its own format, now retired.

Extraction runs through an `os.Root` handle, so every component resolves against a
directory descriptor and no member can name a location outside the target. Containment
used to be a string comparison plus `Lstat` on each parent, which a process able to swap a
checked parent for a symlink could step through — `O_NOFOLLOW` only guards the last
component. Go picks `openat2` where the kernel has it, so this carries no minimum kernel of
its own. A failed extraction rolls back whatever it wrote, because the target must be empty
to start and a half-restored keyset otherwise poisons every retry.

Refused: path traversal, absolute paths, backslash separators, NUL bytes, symlinks,
hardlinks, directories, device nodes, FIFOs, two members that normalise to one
destination, archives over 256 MiB expanded, members over 64 MiB, more than 4096 files,
and any restore into a non-empty directory. File modes are clamped to owner-only — a
restored capsule carries signing keys, and an archive header is attacker-controlled.

The two size numbers are memory budgets rather than archive sizes, because `Open` holds
the raw container, the decrypted payload and every expanded member at once. They are
`capsule.MaxFiles`, `capsule.MaxFileBytes` and `capsule.MaxExpandedBytes` (and
`capsule.MaxContainerBytes`, the cap on a container before it is parsed), the
values `capsule/extract.go` enforces, exported so a consumer can name the limit it hit;
raising them is what a streaming `Open` is for.

Every refusal in that list is covered by a test in `capsule/hardening_test.go` or
`capsule/review_test.go`, with one exception: the 256 MiB expansion budget and the 64 MiB
member ceiling are exercised on the `Seal` side only, and `capsule/limits_test.go` asserts
the constants rather than the refusal. An extraction-side test for both is outstanding.

### Fixtures

`testdata/capsules/` holds one `kycap/3` capsule with the recovery seed that opens it, and
under `retired/` the last `kycap/2` capsule, kept so `Open`'s refusal is measured against a
real container. See the README there for why the seed is committed.

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
shares, err := recoverykey.Split(priv, 3, 5)         // shamir shares of the seed; print the cards, then destroy the host
pub := priv.Public()                                 // hand pub.Bytes() to every product; pin pub.ID()

pub, err := recoverykey.ParsePublicKey(b)            // in a product, from keyfile.Load
priv, err := recoverykey.Combine(shares)             // at restore, from k custodian cards
```

`Generate` is called on exactly one host, once, and that host holds the seed in memory
until `Split` returns. That is the one place in the suite the recovery private key exists
outside custodian cards. Go cannot reliably erase it — value copies, the HPKE key's own
state and the garbage collector keep it recoverable from a core dump or a swap page for
the process lifetime — so the ceremony code must never log, persist or return it, and the
ceremony runs on a dedicated ephemeral host with swap off and core dumps disabled,
destroyed after `Split` returns.

`ID()` is the hex SHA-256 of the public key. It is what a capsule names, what kyrecovery
pins per product, and what a custodian writes on a card. `FromSeed` refuses any length but
32; `ParsePublicKey` refuses any length but 1216. Pinned to the draft-ietf-hpke-pq X-Wing
vector: that seed produces that public key, or the package is not X-Wing.

## shamir

Splits a secret into custodian shares and reconstructs it.

The suite carried two implementations over **two different GF(2^8) fields** — 0x11d in
`ky_server_base`, `gridlock-server` and `kysignon-server`, 0x11b in `kyrecovery-server`.
63232 of the 65536 products in their multiplication tables disagree, so shares written by
one reconstruct a different secret through the other, with a nil error.

It stayed hidden because shares 1, 2 and 3 make every Lagrange coefficient 1. The combine
degenerates to XOR and agrees in any field — and those are the shares a round-trip test
reaches for first. `TestRoundTripEveryIndexSubset` covers all ten 3-of-5 subsets for that
reason.

This package uses 0x11b, the AES field, pinned by golden vectors derived by hand rather
than read off the implementation. Nothing was in the wild, so the choice was free.

Arithmetic is branch-free and table-free. Both predecessors indexed exp/log tables with
share bytes, which are the secret; this one multiplies with shifts and masks and inverts by
exponentiation, so no memory access depends on a secret value. A split is not a hot path.

The 0x11d copies also had three ways to fail on a malformed share, all reachable from
`kyrestore`'s repeated `-shard` flag — a custodian retrying mid-disaster:

| Input to `Combine` | 0x11d copies | here |
|---|---|---|
| Same share twice | panic, `divide by zero in GF(256)` | `ErrDuplicateIndex` |
| Truncated share | panic, index out of range | `ErrShareLength` |
| Share at index 0 | all-zero secret, nil error | `ErrShareIndex` |

`FuzzCombineNeverPanics` holds that line. Distinct non-zero indices make every Lagrange
denominator non-zero, so no input can divide by zero however malformed.

`Split` resamples a zero leading coefficient. Without it the polynomial's degree drops and
fewer shares than promised recover that byte, once every 256 draws.

```go
shares, err := shamir.Split(key, 3, 5)   // any 3 of 5
secret, err := shamir.Combine(shares)     // every share given is used
card := shares[0].String()                // ky2-3-9f2a71c4...-1-a1b2...-7d1e
```

A share is self-describing: `ky2-<threshold>-<set id>-<index>-<value>-<check>`. The share
used to be `index-hex` and nothing else, which meant it could not defend against any of the
four ways a custodian gets this wrong. Each field is there for one of them.

| Field | Refuses |
|---|---|
| `ky2` | A share from the suite's 0x11d implementations, which was byte-indistinguishable and reconstructed a different secret with no error |
| threshold | Combining fewer shares than the split needs — previously a silent wrong answer |
| set id | Mixing shares from two different splits — also previously silent |
| check | A character mistyped off the card, before it becomes a wrong secret |

`Combine` still uses every share it is given; passing more than the threshold is correct.
Bind a hash of the plaintext alongside anyway — `capsule`'s payload hash is that check.

The set id is 128 bits. The first version of this format carried 32, which reached even
odds of a collision after about 65,000 splits — a number a deployment issuing recovery kits
reaches — and a collision means the check the field exists for silently does not happen.
The narrow format is not parsed: nothing outside this package ever wrote a share, so there
are no cards to strand, and a narrow id accepted "for compatibility" is the same collision
still reachable.

Every share must declare a threshold of 2..255. It used to be enforced only above zero,
which is what an absent field decodes to, so a `Share` filled in by a deserialiser landed
in the unchecked mode by default.

## auditchain

Builds and verifies a tamper-evident hash chain over audit records.

Three implementations existed, with three tuple layouts and three key policies:

| | `kypassword-server` | `kybookmarks-server` | `kyrecovery-server` |
|---|---|---|---|
| Key | generated, ≥32 bytes enforced | **a literal survives on the verify/convert path; the write path has no fallback** | HKDF from the keyring |
| Truncation | anchor beside the key | undetectable | sequence numbers in the DB |
| Fields | joined on bare `\|` | joined on bare `\|` | details pre-hashed |

`kybookmarks-server/internal/audit/audit.go:50` keeps a literal,
`"kybookmarks-default-hmac-secret"`, and its write path no longer reaches it —
`loadOrCreateKey` has no constant fallback. What survives is narrower: the literal is what
`legacyHash` verifies v0 entries against, so it can still *recognise* a log an attacker
authored under it. It can no longer launder one. `converge` re-mints under the real key
only when the high-water mark attests to that exact log — same record count and same tail
hash — so a forged log is either refused by the mark or left in the old format for
`Resume`'s digest check to reject. Only a genuine first boot, with no mark at all and every
entry `v: 0`, converts. The key floor is 32 bytes, and on the write path — the one that
mints and checks new records — there is no fallback at all.

Every field is length-prefixed. Joining on a delimiter lets a field containing it shift
into its neighbour and produce another record's digest, forging a record without the key;
`TestFieldsAreUnambiguousAcrossDelimiters` pins that.

Persistence is a parameter of `Append`, not the caller's next statement. The chain's
in-memory head is a claim about what is on disk: advancing it first meant a failed insert
left the next record chained onto one that never existed, and a record stored without its
anchor left the opposite inconsistency, with no way to roll back either. `persist` runs
under the lock that reserves the sequence number, and the chain advances only if it
returns nil.

`Verify` requires the `Anchor` — a count and head hash kept outside the log. Hashes alone
cannot catch a log with records removed from the end, because what remains still chains
correctly, so the anchor is a parameter rather than an option.

`Resume` requires it too. A valid digest does not make a record the tail — every record in
a healthy chain carries one — so resuming from the middle was accepted and the next append
minted a sequence number that already existed. The anchor is the only thing that knows
where the end is. Sequence 0 and `MaxUint64` are refused: `Append` starts at one, and
minting `count+1` from the top wraps to zero.

`Append` takes a `context.Context`, which bounds the wait for the chain lock, not
`persist`. `persist` still runs under the lock — the record and its anchor have to be written together — so give it its own
timeout, and do not call back into the `Chain` from it: the lock is not reentrant, and the
anchor it would ask for is already one of its arguments.

```go
chain, err := auditchain.New(key)          // or Resume(key, lastRecord, anchor)
rec, err := chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
    return store.WriteRecordAndAnchor(r, a) // one transaction
}, "login", user)
err = auditchain.Verify(key, records, anchor)
err = auditchain.VerifyStream(key, rows, anchor) // same, for a log too large to hold
```

`VerifyRecord` asks whether a record carries its own digest, and nothing about where it
sits. It also refuses a record numbered zero or carrying a malformed hash, because `Append`
mints neither — a legacy log numbered from zero is exactly what a migration probe hands it.
`Resume` answers a different question — is this the tail — and needs the anchor to do
it. A conversion probe wants the first.

`Replay` builds a chain in memory from field tuples and hands back the records with their
final anchor, for a bulk rewrite that writes the log once. `Append`'s persist parameter
means the chain advances only when the store agrees; passing one that does nothing per
record would satisfy the signature and mean the opposite.

Errors worth an `errors.Is` in a caller: `ErrWeakKey`, `ErrBrokenChain`.

Chains in this suite reach six figures, and the bug that follows from paging them is
specific: `kyrecovery-server`'s `VerifyChain` read a fixed 100000 events and then reported a
sequence gap on a perfectly healthy chain. `VerifyStream` removes the reason to page. A
record yielded with a non-nil error fails the verification rather than ending the walk, so a
store that dies mid-read cannot look like a short chain.

`Anchor` is `{Count, Hash}`, which is exactly `kypassword-server`'s `audit.state` and
`kyrecovery-server`'s `ledger.head`. KyPassword has migrated onto this package. It needed no
version field: its legacy format was a *single* keyed HMAC digest, so `converge` verifies
every entry under that digest and re-mints the whole log under `auditchain`'s in one atomic
rewrite, leaving nothing to distinguish afterwards. The unkeyed variant that preceded it was
deleted rather than carried, because a chain under no secret is one anyone who can write the
log can recompute end to end.

`kybookmarks-server` is the one with two legacy versions, `v: 0` and `v: 1`, and it converts
the same way: a log is re-minted only when it verifies whole under one of them *and* the
mark outside the log attests to it.

`Fields` are opaque and storage is not this package's business. The three implementations
logged different things and wrote to JSON lines, a file and a database; forcing one schema
on them is what made them diverge, and where the bytes went was never the part that broke.

## logging

Emits JSON lines on stderr. A collector agent ships them; this package opens no socket,
holds no buffer and rotates no file, because an agent survives the process dying and a
library buffer does not.

The suite ran five logging architectures across nine servers. Seven of them shipped a
`LOGGING.md` promising structured, privacy-safe output and one delivered it. Redaction
existed in two products with opposite strategies: kynotes dropped anything outside a
21-key allowlist, kypost redacted values whose key *name* looked sensitive — a denylist,
which fails silently on a key nobody thought of, and which seventeen of its own call sites
bypassed anyway.

Three things here are why it is in this library rather than fixed per product.

A field value cannot forge a line. Control characters become U+FFFD on the value, before
any renderer sees it, and values cap at 256 bytes. Six products passed values into
`log.Printf` unescaped and one passed a free-form `map[string]any` into `json.Marshal`; a
newline in any of them writes a log line of the attacker's choosing, and a forged line is
indistinguishable from a real one.

A key must be declared. There is no `Field(name, value)`, and values are `string`,
`int64`, `bool` or `time.Time` rather than `any`, so a struct holding a token cannot be
logged whole.

An event has one name. Four products spelled the same audit event four ways — `user_id`
against `actor` against `actorId`, and one with positional arguments and no names at all.

```go
lg, err := logging.New(logging.Config{App: "kypassword", Out: os.Stderr})
lg.Security(ctx, logging.AuthFailed, logging.UserID(id), logging.RemoteIP(ip))
if err := lg.Audit(ctx, logging.ShareRedeemed, rec, logging.UserID(id)); err != nil {
	// The shipped copy did not land; the local chained file still has it.
}
```

`lg.Handler()` is a `slog.Handler` for products mid-migration. Install it with
`slog.SetDefault` and existing call sites keep working; attributes outside the vocabulary
are dropped and counted into `dropped_fields`, so what is lost shows on the line. A
declared key does not save an arbitrary value: `slog.Any("user_id", someStruct)` drops
even though `user_id` is declared, because a struct or a map is `KindAny` or `KindGroup`,
and a declared name vouches for the key, not for whatever Go value showed up under it —
that is the first thing a migrating call site hits.

Audit lines are flat and carry `seq`, `prev`, `hash` and `fields` at the top level, so
`cmd/kyauditverify` needs no code change to verify them — provided the export handed to it
is filtered to the lines that carry `hash` first. An ordinary `Log` or `Security` line has
none of those four keys; it decodes into a zero `auditchain.Record` with no JSON error, and
`VerifyStream` reports that as a broken chain, not as a line outside its scope. `Audit`
recomputes the flat keys from the fields it is given and checks them against the record's
own `Fields`; a disagreement is caught at emission, not assumed away by construction, and
costs the flat keys — replaced with an `audit_fields_mismatch` marker — while the record
itself, the part that is authenticated, ships regardless. The product keeps its own local
chained file: a tamper-evident chain that exists only on a machine the attacker may also
own is not evidence.

There is no syslog renderer. `log/syslog` is frozen, absent on Windows and Plan 9, and
broken on macOS 12 and later. Writing RFC 5424 to stderr instead would double-frame the
line, because the collector already supplies a frame — so severity and facility are
ordinary JSON fields and the frame is the agent's job.

## health

Serves `/healthz` in the suite's one shape, `ky.health/1`, which kyPulse reads. It is here
rather than fixed per product because the shape is a wire contract: before it, the suite's
health routes disagreed on path, field names, status codes and even content type, so a
monitor needed an adapter per product.

```go
var appendDisabled = health.DeclareReason("append_disabled")

mux.Handle("GET /healthz", health.Handler("kyvault", lg,
	health.Check{Name: "database", Run: db.PingContext},
	health.Check{Name: "audit", Run: func(ctx context.Context) error {
		if auditor.Disabled() {
			return health.Degrade(appendDisabled)
		}
		return nil
	}},
))
```

```json
{"schema":"ky.health/1","service":"kyvault","status":"degraded","time":"2026-09-26T10:41:00Z",
 "checks":[{"name":"database","status":"ok"},{"name":"audit","status":"degraded","reason":"append_disabled"}]}
```

The route is public, so the response is built to be safe to show anyone.

- **No error text.** A check's error text never reaches the response: a DSN, a path or a
  hostname in `err.Error()` is the leak this prevents. An ordinary error is `down` with no
  reason. A check shows `degraded` or a reason only by returning `health.Degrade(r)` or
  `health.Fail(r)`, where `r` came from `DeclareReason`, which panics at startup on a code
  outside `[a-z0-9_]{1,64}`. The operator gets the rest on stderr: each non-ok check writes
  a `health_check_failed` line with the check name, reason and `logging.Err` error kind.
- **No version, build or uptime.** On a public route they fingerprint releases and reveal
  restart timing. A monitor gets the version from the container image.
- **Cached and shared.** One evaluation answers every request for `CacheFor` (5 s), and
  concurrent requests share it, so hammering the route cannot hammer the database. The
  evaluation uses its own context, so one client hanging up cannot cancel the result every
  other client sees.
- **Deadlines.** A check has `Timeout` (default 2 s) and must honour its context. A check
  past its deadline is `down` with reason `timeout`, and a check still running from the
  previous evaluation is not started again: it reports `timeout` until it returns. A
  panicking check is `down`.

The service status is the worst check status; no checks is `ok`. `ok` and `degraded`
return 200, `down` returns 503, so a readiness probe or a monitor that reads only the code
keeps working. Liveness should stay on a route that checks nothing: restarting the app does
not fix a dependency, so a liveness probe wired to `/healthz` would restart in a loop while
the dependency is down. `HEAD` returns the code with no body; other methods return 405.
`Response` and `CheckResult` are exported for monitors that decode the body.

## password

Hashes and verifies passwords with Argon2id.

The suite ran three algorithms and five parameter sets:

| Repos | Algorithm | Parameters |
|---|---|---|
| `ky_server_base`, `gridlock-server` | Argon2id | m=64 MiB, **t=1**, p=4 |
| `kysignon-server`, `kyrecovery-server` | Argon2id | m=64 MiB, t=3, p=4 |
| `kydns-server` | Argon2id | m=64 MiB, t=3, **p=2** |
| `kynotes-server`, `kypost-server` | scrypt | N=2^17 |
| `kybookmarks-server` | scrypt | **N=2^15** |

The Argon2 encodings are mutually parseable, so a hash minted at t=1 verified in a t=3
product at a third of the intended attacker cost and nothing flagged it. This package is
the one answer: RFC 9106's second recommended profile, **m=64 MiB, t=3, p=4**, self-describing
in PHC form. The first recommended profile asks for 2 GiB, which no login endpoint can
afford per request.

**A malformed stored hash is an error, never a fallback.** `ky_server_base` and
`gridlock-server` re-split the string when the parameter segment fails to parse and, if it
merely starts with `$argon2id$`, verify against their compiled defaults instead. `parse`
here requires all six PHC segments, the exact algorithm, version 19, and three readable
parameters.

**Parameters are bounded on the way in.** A stored hash is attacker-controlled wherever the
store is, and `m=4294967295` asks for 4 TiB and OOM-kills the process on the next login
rather than failing it. Accepted: 8–256 MiB, t 1–10, p 1–16, salt ≥8 bytes, hash ≥16.
`kypost-server` bounds its scrypt equivalent for exactly this reason; nothing on the Argon2
side did.

**Derivations are bounded and shed rather than queue.** Four concurrent slots at 64 MiB caps
derivation memory at 256 MiB. Past a 2-second wait `Hash` and `Verify` return `ErrBusy`, which
callers should answer 503 to and must **not** spend a lockout strike on — the server is saying
"not now", not the user getting the password wrong. `kynotes-server` bounds the same way but
blocks forever, so a burst parks unbounded goroutines and overload reports itself as a wrong
password.

Concurrent derivations are bounded in **two dimensions**: 256 MiB of memory and 16 Argon2
lanes, each reservation the size that hash actually asks for, both taken together under one
queue. A request needing more than either whole budget fails immediately rather than waiting
for what it can never get.

A slot count alone bounded how many derivations ran, not how large they were, and `Verify`
accepts a stored hash asking for anything up to 256 MiB — so four slots admitted 1 GiB while
the comment above them claimed 256 MiB. Memory alone was no better: a stored hash at the
8 MiB floor reserves a thirty-second of the byte budget, so 32 run at once, each free to ask
for 16 lanes — **512 lanes**, comfortably under the memory ceiling and quite enough to take
the login endpoint with it. `Verify` reads those parameters out of the stored hash, so
whoever can write the store chooses them. CPU was written off as degrading rather than
killing, which is true of one derivation and false of the fleet a byte budget admits.

Taking both under the same single acquirer is what keeps the second dimension free: two
waiters can never each hold part of what the other needs.

The PHC parser compares against the canonical spelling rather than scanning. `fmt.Sscanf`
reads the fields it is asked for and ignores the rest, so `p=4TRAILINGGARBAGE`, `p=04` and
`v=19GARBAGE` all verified clean.

`HashWith` mints at chosen `Params` — `{Memory, Time, Threads}`, bounded to the same band
`Verify` accepts — for a test suite that cannot afford 64 MiB per derivation. `Hash` is the
suite's answer, calling `HashWith` at `DefaultParams()`, and what production code calls.
`DummyVerify` spends a verification's cost on a reject path that never reached one, so a
missing account does not answer faster than a wrong password — though `ErrBusy` returns
without deriving, so under load that leak reopens.

```go
encoded, err := password.Hash(plaintext)        // "$argon2id$v=19$m=65536,t=3,p=4$..."
ok, err := password.Verify(plaintext, encoded)  // ErrMalformed, never a silent default
stale, err := password.NeedsRehash(encoded)     // upgrade on next successful login
fast, err := password.HashWith(plaintext, password.Params{Memory: 8 * 1024, Time: 1, Threads: 1}) // tests only
```

Errors worth an `errors.Is` in a caller: `ErrBusy`, `ErrMalformed`.

`Verify` accepts a weaker-but-valid hash so a deployment rehashes on login instead of
locking everyone out. Pair it with `NeedsRehash`; no Argon2 repo in the suite had either.

## totp

RFC 6238 one-time passwords. Pinned to the published RFC 4226 Appendix D vectors, so the
construction is checked against a document rather than against itself.

All four implementations in the suite agreed on the arithmetic — HMAC-SHA1, 20-byte secret,
6 digits, 30-second period — so **enrolled secrets stay valid across a migration onto this
one**. They disagreed on everything around it, and two of those differences outlive the
request.

`ky_server_base` and `gridlock-server` build the enrolment URI by interpolation:

```go
fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&...", issuer, accountName, secret, issuer)
```

An account name carrying a `?` starts the query string early. Parsed:

```
account = "x?secret=ATTACKERAAAAAAAA&digits=8"
  enrolled secret -> ATTACKERAAAAAAAA        digits -> 8
```

The user's phone holds a secret the server never issued, until they re-enrol. Nothing
errors. `ProvisioningURI` escapes the label and builds the query with `url.Values`.

The same two return a bare `bool` from validation, so a caller cannot know which step
matched and cannot spend it — a phished code stays live for the full 90-second window.
`Validate` returns the counter:

```go
counter, ok := totp.Validate(secret, code, time.Now())  // record counter, refuse a repeat
uri := totp.ProvisioningURI(issuer, account, secret)
```

## recoverycode

One-time codes that bypass every other factor, so their strength is the account's strength.

`ky_server_base`, `gridlock-server` and `kysignon-server` issue 8 symbols over a 32-symbol
alphabet — **40 bits** — and store them as a bare SHA-256. That is searchable offline by
anyone who reads the store. This package issues 12 symbols: 60 bits.

Hashing and storage stay with the caller; the products disagree about the hash for reasons
this package cannot settle, and it is not what diverged dangerously. What is here is
generation, the normalisation both sides of a comparison must agree on, and `MatchCode`,
which normalises and hashes before scanning every entry instead of breaking on the first
hit — `ky_server_base`'s redeem loop
reports the matching code's position in the list through its timing. An empty stored entry
is a redeemed slot and never matches, so a caller blanks in place rather than removing and
renumbering, which is how two concurrent redemptions lose each other's write.

`Match` was a digest comparison named for codes. Both parameters were strings, so passing
what the user typed compiled, ran, and never matched: enrolment hashed `Normalize(code)`
and a redemption path that forgot the same call rejected a valid code during the emergency
the code exists for. It is now `MatchDigest`, and `MatchCode(code, digests, hash)`
normalises internally so the two sides cannot disagree.

## keyfile

Loads a long-lived secret from disk, creating it on first use. Seven products did this
seven ways; the five whose behaviour differs materially are:

| Product | On a corrupt key file | First-boot race | fsync |
|---|---|---|---|
| `kynotes-server` | **continues with an empty secret** | unguarded | no |
| `kypassword-server` | **regenerates, orphaning every old record** | unguarded | no |
| `kysignon-server` | refuses to start | unguarded | no |
| `kyrecovery-server` | refuses | `O_EXCL` | no |
| `kypost-server` | refuses | mutex + recheck | yes |

This package refuses rather than guesses: an existing file that does not decode to exactly
the expected size is an error and is left untouched. The key is written to a temporary file
and then `os.Link`ed to its final name, so the cross-process race is settled by `link`
failing with `EEXIST` — not by `O_EXCL`, which would leave a partial file at the real path
that this package then refuses to replace forever. The loser re-reads the winner's key
rather than returning one that was never persisted. The file and its directory are both fsynced, because a crash after first boot
otherwise leaves a zero-length file that the refusal above then reports forever.

`RequireOwnerOnly` is exported separately. Nothing in the suite checked that a key file is
still `0600`, so one relaxed by a stray chmod or a restore kept being used as though it
were secret.

```go
key, err := keyfile.LoadOrCreate(filepath.Join(dir, "audit.key"), 32)
```

`LoadOrCreate` and `Load` are hex; `LoadOrCreateEncoded` and `LoadEncoded` take an
`Encoding` — `Hex`, `Raw` or `Base64` — because four products already wrote their key
files those ways: `kydns-server` writes a raw 32-byte ed25519 seed, `kysignon-server`
writes raw, `kynotes-server` and `kypost-server` write base64. A package that can only read
hex is a package those four cannot adopt.

`Load` never creates. `kypost-server` runs a daemon and an API process against the same
key file, and the daemon must never mint a key the API process did not — when both are
allowed to create, a restart in the wrong order leaves half the data under a key that no
longer exists, and nothing reports it: every write succeeds, and every old read fails as
though the data were corrupt.

`FromEnv` reads a key from an environment variable, hex or base64, and applies the same
*content* checks a file-supplied key gets — the encoding must decode and the result must be
exactly `size` bytes — with set-but-unparseable an error rather than a fall-through to the
file. It cannot apply the rest: a file key also goes through `openKey`'s symlink and
`os.SameFile` checks and `checkKeyInfo`'s ownership and 0600 permission checks, and an
environment variable has no inode to check. Four products check an environment variable before the file; doing that outside this
package means the env-supplied key skips every check the file-supplied one gets.

```go
key, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Base64)
key, err := keyfile.Load(path, 32)                       // never creates
key, ok, err := keyfile.FromEnv("KY_AUDIT_KEY", 32)       // ok is false when unset
err := keyfile.Store(path, pub.Bytes(), keyfile.Raw)     // a key the caller was handed; never overwrites
```

`Store` persists a key the caller already holds — the recovery public key received at
pairing — and refuses to replace an existing file, with `errors.Is(err, fs.ErrExist)`.
Replacing a product's recovery public key is how every later backup gets sealed to whoever
wrote the replacement.

A hex key file is lowercase hex with exactly one trailing newline — 65 bytes for a 32-byte
key. That format is pinned by `TestHexFileFormat`.

`errors.Is` a failed load against `ErrUnreadable` to tell a corrupt key file from a missing
one — the second creates under `LoadOrCreate`, the first never does.

## derive

The login secret a client sends in place of a password: PBKDF2-SHA256 stretched, then
HKDF-SHA256 expanded under a per-product label.

`kynotes-server` and `kypost-server` both do this, each mirroring a **browser-side
TypeScript implementation**. That makes it a contract across four programs rather than a
helper — change any byte and every user is locked out. The golden vectors in the test were
produced by running `kynotes-server`'s implementation, not this one, and they pass, so that
product can adopt this package without a single login breaking.

Both existing copies import `golang.org/x/crypto/pbkdf2` and `.../hkdf`. Both moved into
the standard library in Go 1.24, so **adopting this package deletes a dependency from each
rather than adding one** — which is the only reason it can live here at all.

```go
secret, err := derive.AuthSecret(password, saltB64, iterations, "kynotes/auth/v1")
salt, err := derive.SyntheticSalt(pairingKey, "login-salt/v1", username)
```

Iterations are bounded to 100,000–12,000,000: the value arrives from a client or a stored
record, and unbounded it buys minutes of CPU per login.

The two products do not agree on the ceiling, and this package takes the looser of them.
`kypost-server` enforces 12,000,000 with nothing tighter in front of it. `kynotes-server`'s
derivation carries the same 12,000,000, and four of its five routes that accept a client
iteration count cap it below that — one clamps an out-of-range value to 600,000 rather
than refusing it, the other three refuse anything outside 100,000-1,000,000. Its fifth
route, account recovery, checks the client's count only through the derivation's own
100,000-12,000,000 bound, so kynotes does admit the full ceiling, just not on every route.
**Adopting this package as the only bound would raise those four routes' ceiling
twelvefold.** Which number is right is an open product decision; keep their tighter
checks until it is made.

A ceiling is not admission control, though — it bounds one call and says nothing about how
many run at once, so a modest burst at the ceiling takes every core and starves the handlers
that would have shed it. **Four concurrent slots and a 2-second wait**, past which
`AuthSecret` returns `ErrBusy` — 503, and no lockout strike. PBKDF2 is single-threaded, so a
slot really is a core. The budget is `derive`'s own rather than `password`'s because this
package is standard-library-only by design and importing `password` would pull `x/crypto`
into it. `SyntheticSalt` lower-cases the username, because keying anything off the raw string
lets one account present as many and quietly multiplies any per-account budget above it.

`AuthSecretContext` bounds the wait for a slot. The budget stays separate from
`password`'s — the two bound different resources, and this package importing `password`
would pull `x/crypto` into it — but `derive.MaxConcurrent`, `password.MaxMemoryKiB` and
`password.MaxLanes` are exported so a product running both can add them up.

## recoveryclient

The product side of the suite's backup contract with KyRecovery. Four products carried
divergent copies of this code, two of them hand-rolled with their own key-pin and token
semantics; a prune that deletes every `.kycap` in a directory, or a pin that accepts a second
key, loses data silently, which is the admission bar. kysignon-server was the reference and
is the first consumer.

The product supplies four things: a `Settings` row store (mapping its not-found error to
`recoveryclient.ErrNotFound`), a `Sealer` under its deployment key (or `NewAESGCMSealer`),
a `collect` func that says what to seal, and a `checks` func for the drill. Config, HTTP
handlers, step-up, UI, audit API, compose and docs stay in the product.

```go
sealer, _ := recoveryclient.NewAESGCMSealer(cfg.EncryptionKey, "myapp:setting:kyrecovery_token")
client := recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: cfg.AllowPrivateRecovery})
res, err := recoveryclient.Run(ctx, recoveryclient.RunConfig{
	DataDir: cfg.DataDir, AppName: cfg.AppName, AppVersion: version,
	BackupDir: cfg.BackupDir, Keep: cfg.BackupKeep, Sealer: sealer,
}, settings, collectPayload, client)
action, outcome, details := recoveryclient.Outcome(res, err)
```

What it pins, each by a named test:

- One run seals once and delivers to every configured destination; a key with nowhere to
  go is `ErrNoDestination`, and `collect` never runs before that is known
  (`TestRunNeedsAKeyThenADestination`, `TestRunPairedDeliversToBothAndRecordsReceipt`).
- A failed local copy never cancels the deposit; it rides in `Result.LocalError`
  (`TestRunLocalFailureDoesNotCancelTheDeposit`).
- Local copies are `<AppName>.<capsule-id>.kycap` at 0600 (the app name escaped reversibly
  into `[A-Za-z0-9-_]`, so distinct names never share a prefix and no name can be another's
  prefix plus the delimiter), written by temp file and rename,
  and only that prefix is listed or pruned (`TestWriteLocalCopyPrunesOwnPrefixOnly`,
  `TestLocalCopiesOfAPrefixedAppNameAreInvisibleToTheShorterName`,
  `TestLocalCopiesOfCollidingNamesStaySeparate`). A
  retention count below one is refused before anything is written, so a zero value can never
  mean "delete everything" (`TestWriteLocalCopyRetention`).
- The schedule is bounded in whole seconds before any `Duration` math, on the way in and on
  the way out, so a stored 2^55 seconds cannot wrap to zero and read as off and a stored
  negative cannot make every tick due (`TestSetIntervalBoundsSeconds`,
  `TestIntervalRefusesAStoredValueOutsideTheBound`); the next run counts
  from the last attempt (`TestNextRunCountsFromLastAttempt`).
- The key pin is write-once and the settings row decides, not the file
  (`TestStoreRecoveryKeyIsWriteOnce`, `TestLoadRecoveryKeyDetectsSwappedFile`).
- URLs are HTTPS without credentials, query or fragment; private and carrier-grade NAT
  destinations need `Options.AllowPrivate`; loopback, link-local, multicast, unspecified and
  reserved never pass (`TestValidateURL*`). Redirects are refused (`TestClientRefusesRedirect`).
  `errors.Is(err, recoveryclient.ErrPrivateDestination)` identifies literal-IP and
  DNS-time refusals where enabling `AllowPrivate` would admit an address, including
  errors returned by `ClaimPairing` and `Deposit`. Products use this to name their own
  environment setting and container recreation instructions. It does not match addresses
  that remain forbidden, lookup failures, or connection/TLS/server errors.

- A receipt must describe the bytes sent, and one naming another capsule is `ErrRemote` and
  unrecorded (`TestDepositRefusesReceiptThatDoesNotDescribeBytesSent`,
  `TestRunReceiptForOtherCapsuleIsRemoteAndUnrecorded`).
- `ClearPairing` removes the URL and token rows and nothing else; the key pin and receipts
  stay, and a half-cleared pairing still clears (`TestClearPairingKeepsKeyPinAndReceipt`,
  `TestClearPairingHalfClearedStillClears`). A pairing whose key will not resolve is
  `ErrKeyPinMissing`, reported, not skipped (`TestLoadPairingReportsKeyPinMissing`).
- `Drill` seals to a throwaway key generated and dropped inside the call, hands the checks
  the manifest as read back from the opened capsule so they see the JSON-shaped recipe a real
  restore sees. Recipe values are authenticated but caller-authored, so checks validate types
  and clean relative paths before acting (`TestDrillHandsChecksTheOpenedManifest`), works in a 0700
  scratch directory under a root the product names (its data directory, never the system
  temp dir), wipes it, and sweeps a killed drill's residue first
  (`TestDrillOpensWhatItSealedAndWipesScratch`, `TestDrillUsesTheCallerScratchRoot`). `Restore` checks the
  manifest's service name before combining shares (`TestRestoreRefusesOtherServiceBeforeCombine`).
- `SQLiteSnapshot` copies through the live handle with `VACUUM INTO`; copying the file misses
  every commit still in the write-ahead log. The lib has no SQLite driver, so the
  row-in-the-WAL case is proven in each product's tests.
- `guardtest.NoDecryptOutside` walks a product's repository from an absolute root, fails on
  fewer than ten files, and names any call of `capsule.Open`, `recoverykey.Combine`,
  `recoverykey.FromSeed` or `recoveryclient.Restore` outside the functions the product lists
  (`TestGuardCatchesPlantedOpen`). The lib runs it on itself.

## syncauth

One definition of how KySignOn signs a directory-sync event and how a product verifies it.
Before this, the sender signed the timestamp and body and at least one receiver verified the
body alone, so the two sides could not agree; and the signing secret also travelled as the
bearer token on every request. A receiver that accepts a forged deprovision, or that never
sees a real one, cannot tell either from a good event, which is the admission bar.

Scheme v1: HMAC-SHA256 over a canonical string binding the timestamp, the event type, the
event ID and the SHA-256 of the body, carried as `X-KySignOn-Signature: v1=<hex>` with the
timestamp, type and ID in their own headers. The key travels nowhere.

```go
// sender
h, _ := syncauth.Sign(secret, time.Now(), "user.deprovisioned", eventID, body)
h.Apply(req)

// receiver
mux.Handle("POST /api/sync", syncauth.Middleware(keyFn, syncauth.Options{Replay: syncauth.NewMemoryReplay(0, 0)}, 0, logReject)(handler))
```

Pinned: every bound field changes the verdict (`TestVerifyBindsEveryField`); a missing
signature, a timestamp outside the window in either direction, and a short key each refuse
(`TestVerifyRefusesMissingStaleAndShort`); the replay guard forgets only what has left the window and refuses with
`ErrReplayGuardFull` rather than forget an ID it must remember (`TestReplayGuard`); the middleware reads a bounded body, fails closed when the key is not
configured, and hands the handler exactly the bytes that were signed
(`TestMiddlewareVerifiesAndReplaysTheBodyToTheHandler`); `FuzzVerify` accepts only the
original tuple.

## oidcverify

Verifies the RS256 tokens KySignOn issues against its JWKS, on the standard library. Five
products parsed these with their own code, and at least one read the claims without checking
the signature. One wrong check of `alg`, `aud`, `iss`, `exp` or `kid` accepts a token it
should not.

```go
v := &oidcverify.Verifier{Issuer: cfg.IssuerURL, Audience: cfg.ClientID}
claims, err := v.VerifyWithNonce(ctx, idToken, session.Nonce)
mux.Handle("GET /api/me", v.Middleware(logReject)(handler))
```

Pinned: the issuer and JWKS URL must be HTTPS and the fetch follows no redirect, checked
before any request is made (`TestPlaintextIssuerIsRefusedWithoutARequest`,
`TestJWKSRedirectIsRefused`); the algorithm is RS256 or nothing, so `none`, `HS256` and an empty signature segment
are refused before any key work (`TestVerifyRefusesAlgorithmConfusionAndBadSignatures`);
each standard claim is checked with one minute of leeway and an audience array is refused
unless the product opts in (`TestVerifyRefusesEachBadClaim`); base64url must be unpadded so
one token has one encoding; JWKS entries that are not RSA signing keys are ignored even under
the right `kid` (`TestJWKSIgnoresNonRSAKeysUnderTheSameKid`); an unknown `kid` triggers at
most one rate-limited refresh whether the fetch succeeds or fails, the fetch runs outside
the lock so concurrent verifications share it, and a stale key set outlives an issuer outage
(`TestJWKSRefreshIsRateLimitedAndStaleSetSurvivesOutage`, `TestUnknownKidDoesNotStallVerification`,
`TestConcurrentUnknownKidsShareOneFetch`).


### Back-channel logout

`VerifyLogout` is the dedicated verifier for the KySignOn profile of
[OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation):

```go
logout, err := v.VerifyLogout(ctx, logoutToken)
// On success, atomically record (logout.Issuer, logout.JWTID) and invalidate
// matching sessions. Keep the replay record through logout.ReplayUntil.
```

It shares the verifier's RS256 signature checks, HTTPS JWKS cache, issuer/audience checks,
clock and leeway. It requires exact `typ: logout+jwt`, numeric `iat` and `exp`, a nonempty
`jti`, a nonempty `sub` or `sid` (or both), and an `events` object whose
`http://schemas.openid.net/event/backchannel-logout` member is an object. `nonce` and
`token_use` must be absent, including null or empty values. Expiration must follow
issuance; tokens older than `MaxLogoutTokenAge` (five minutes) plus leeway are refused,
even with a later expiration. KySignOn currently issues two-minute tokens per attempt.
`ReplayUntil` is the earlier expiration/freshness cutoff, including leeway (one minute
by default). `ErrTokenType` reports a wrong token purpose; `ErrLogoutClaims` reports a
logout-specific claim failure; common signature, issuer, audience and time errors are
shared with `Verify`.

The returned `LogoutClaims` is separate from authentication `Claims`. With `SessionID`,
match the local sessions for this issuer/client and that session ID, checking `Subject`
when present. Without `SessionID`, end all this client's sessions for `Issuer` and
`Subject`. Never broaden an unknown session ID into a subject-wide logout. A missing
local session is an idempotent success. The receiving product owns the HTTP body limit,
durable replay check, session invalidation and audit transaction; this primitive verifies
only and deliberately holds no replay database. Store replay IDs across restart and check
them atomically with invalidation so concurrent deliveries cannot replay a logout.

**Authentication compatibility:** `Verify`, `VerifyWithNonce` and `Middleware` now accept
only an absent/empty `typ`, `JWT`, or `at+jwt`, and reject any `events` claim. An ID token
with a logout type cannot authenticate, and ordinary ID/access tokens cannot authorize
logout. Numeric dates must be JSON numbers rather than quoted numbers, nulls or values
outside the supported integer range; payloads must be a single JSON object. Existing
KySignOn ID/access tokens use `JWT` and remain compatible. Neither authentication API
becomes an access-token-only verifier: products must still enforce their token-use policy.

The `oidcverify/logout_test.go` suite checks both logout scopes, malformed claims,
signatures, purpose separation through all three authentication APIs, JWKS reuse, and
exact freshness/replay boundaries with an injected clock.

## scim

The SCIM 2.0 client KySignOn provisions accounts with, and the RFC 7643 User type it shares
with a server. Before this the types, paths and status handling sat in KySignOn's sync engine,
where a 409 on create counted as a delivered account, later calls used local IDs the server
never issued, and generic targets got the suite signature instead of their bearer token. An
account that does not exist recorded as provisioned is the bar.

```go
c := &scim.Client{BaseURL: sys.URL, Token: sys.Token, HTTPClient: netguard.Client(5 * time.Second)}
created, err := c.CreateUser(ctx, user)          // keep created.ID; it is the handle from here on
if errors.Is(err, scim.ErrConflict) {
	created, err = c.FindUser(ctx, "externalId", user.ExternalID)
}
_, err = c.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: false})
err = c.DeleteUser(ctx, created.ID)              // errors.Is(err, scim.ErrNotFound): already gone
```

Users only; groups, listing and bulk wait for a caller. `FindUser` takes `externalId` or
`userName`, the two attributes whose match it can check on the way back. `HTTPClient` is the
product's, so its outbound policy applies; the client adds what every product must not get
wrong.

Pinned: the base URL is HTTPS with a host and nothing else, and an empty token is refused,
before any request (`TestPlaintextOrMalformedBaseURLIsRefusedWithoutARequest`); a redirect is
refused and the bearer does not follow it (`TestRedirectIsRefusedAndTokenNotReplayed`);
resource IDs are path-escaped and an empty or dot ID never reaches the wire
(`TestResourceIDsAreEscapedAndRequired`); the filter value is quoted with `\` and `"` escaped
and any other attribute is refused (`TestFilterIsEscapedAndAttributeRestricted`); zero matches
is `ErrNotFound`, two is `ErrAmbiguous`, and one that does not carry the value is
`ErrMalformedResponse`, so a server that ignores the filter cannot hand back someone else
(`TestFindUserZeroAndManyResults`, `TestFindUserRefusesAUserThatDoesNotMatch`); 409 is
`ErrConflict` and a 2xx create without an `id` is `ErrMalformedResponse`
(`TestCreateConflictIsAnErrorNotSuccess`, `TestCreateWithoutAnIDIsAnError`); only 200, 201 and
204 are success, so a 3xx without `Location` or a 202 is not a completed delete, and `Ping`
needs a JSON object (`TestUnexpectedStatusesAreNotSuccess`); bodies are read to 1 MiB, error
detail is printable and short with the bearer token redacted out of it, and `Retry-After` is
surfaced capped at an hour and never negative (`TestOversizedSuccessBodyIsRefused`,
`TestErrorBodyIsBoundedAndPrintable`, `TestTokenIsRedactedFromErrorDetail`,
`TestRetryAfterIsBoundedAndNonNegative`); a transport error names the path, not the query
that carries a user identifier (`TestTransportErrorsDoNotCarryTheQuery`); the round trip
against a server that mints unrelated IDs uses those IDs throughout
(`TestLifecycleAgainstServerMintedIDs`).

## offsite nested module

One client for copying opaque data to S3-compatible storage, pinned SFTP,
signed SMB 2/3, or a local directory. It is a nested module so products that
only use the root primitives do not inherit the SFTP and SMB dependency trees.

```go
target, err := offsite.Parse(offsite.Config{
	URL: "sftp://backup@vault.example/copies",
	Secret: privateKey,
	HostKey: "SHA256:...",
})
err = target.Put(ctx, "attachments/object-id", body, size)
```

See [`offsite/README.md`](offsite/README.md) for URL forms and the security
contract. Release tags are namespaced for the nested module: `offsite/v0.1.0`.
Consumers install that release with
`go get github.com/Busnes-app/ky-primitives/offsite@v0.1.0`.

## Contributing

Nothing in this repository builds its consumers. The check that does lives in each of them:
`.github/workflows/ky-primitives-compat.yml` in `gridlock-server`, `kybookmarks-server` and
`kypassword-server` builds and tests that consumer against this module's default branch
instead of the version it pins. It runs on a daily schedule and on `workflow_dispatch`, not
on pull requests -- in either repository.

It lives there rather than here because the dependency only points one way without a
credential. A consumer, public or private, can read this repository anonymously; reaching a
private consumer from here needed an organisation token, which is why the job that used to
do it never ran.

**The cost is immediacy.** A change that breaks a consumer will not fail your pull request.
It will fail in that consumer's scheduled run, up to a day later, in a repository you may not
watch, and the person who sees it red will be someone whose own work is unrelated. If you are
making a change you expect to break a consumer, do not wait for the schedule: open the
consumer's PR alongside yours and run its compatibility workflow by hand from the Actions tab
once this change is on `master`.

The other six suite repositories do not import this module and have no such workflow; adding
one is a copy of the file with the cron minute changed.
