# Recovery shares, codes and client

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

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
  (`TestStoreRecoveryKeyIsWriteOnce`, `TestLoadRecoveryKeyDetectsSwappedFile`). Pairing a
  different key is a `*PinnedError` with code `recovery_key_pinned` and both key IDs
  (`TestPairingADifferentKeyIsRecoveryKeyPinned`).
- `RepinRecoveryKey` is the only way to a new key, for a KyRecovery rotation or rebuild. The
  recovery key cannot sign, so the operator is the proof: they type the full ID of the
  pinned key and of the new key from the new cards, and the product gates the action on an
  administrator with fresh step-up and never prefills the new ID. The product's audit
  recorder runs before anything changes and its failure refuses the re-pin
  (`TestRepinRefusedWithoutConfirmation`, `TestRepinRefusesAForgedKey`,
  `TestRepinRefusedWhenAuditFails`). The key ID row is written last, so a crash leaves the
  old pin with nothing sealable; re-running finishes it, or naming the old key rolls it back
  (`TestRepinInterruptedFailsClosedThenCompletesOrRollsBack`, `TestRepinRerunIsIdempotent`).
  Capsules already deposited stay sealed to the old key and need the old cards.
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
