# Capsule fixtures

[Overview](../../README.md) · [Backup container and recovery key](../../docs/CAPSULE.md#fixtures)

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

Earlier fixtures (`kysignon.kycap` for `kycap/1` and `kyrecovery.kycap`, a tar of
`manifest.json`, `nonce.bin` and `payload.enc`) were real output from `kysignon-server`
and `kyrecovery-server` and are no longer retained. Both authenticated their ciphertext
and left the manifest outside the AEAD, so `capsule_id`, `service_name`, `threshold`,
`total_shares` and the verification recipe could be rewritten by anyone who could reach
the file. Neither server needs its old capsules read.
