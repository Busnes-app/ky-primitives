# Passwords, TOTP, key files and derivation

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

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
6 digits, 30-second period — so their generated enrolments stay valid across a migration
onto this one. `Code` and `Validate` refuse decoded secrets shorter than 16 bytes (128 bits),
the minimum in RFC 4226 section 4; `GenerateSecret` continues to generate 20 bytes.
An imported undersized secret must be replaced by re-enrolling with its issuer. The library
does not rewrite a secret or delete a stored enrolment. Applications must preserve such
records and explain the refusal rather than dropping them while loading a vault.

The implementations disagreed on everything around the arithmetic, and two of those
differences outlive the request.

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
