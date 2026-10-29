# Backup container and recovery key

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

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
destination, archives over 256 MiB expanded (the tar stream, so per-member headers and
padding count, and `Seal` measures the same bytes), members over 64 MiB, more than 4096
files, and any restore into a non-empty directory. File modes are clamped to owner-only — a
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
