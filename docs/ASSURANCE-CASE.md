# Assurance case

[Overview](../README.md) · [Verifying releases](VERIFYING-RELEASES.md) · [Contributing](../CONTRIBUTING.md) · [Strong configuration](STRONG-CRYPTO.md)

This is the argument that ky-primitives meets its security requirements: what it protects,
from whom, where the trust boundaries are, and why the design and the code hold at each one.
The detailed contract of each package is in the pages listed under [Packages](../README.md#packages) and
[offsite/README.md](../offsite/README.md); this page ties them together and points at the
evidence. Paths are relative to the repository root.

ky-primitives is a library. It runs inside the Ky products that import it, with their
privileges, and it has no network listener, configuration or storage of its own. A product can
still misuse it; the requirements below are what the library promises when called as
documented.

## Security requirements

1. **Backups stay secret and unmodified.** A capsule opens only with the suite recovery private
   key, and any change to its ciphertext or to any manifest field makes `Open` fail.
2. **Restoring a backup cannot write outside the target directory** or exhaust memory, whatever
   the archive contains.
3. **The recovery key cannot be rebuilt from fewer custodian shares than the threshold**, and a
   wrong, repeated or mistyped share is an error, not a wrong key.
4. **Passwords are stored as slow, salted hashes**, and a stored hash cannot make a login
   request run out of memory or CPU.
5. **A token or event is accepted only if its issuer signed it for this receiver**: OIDC tokens
   (`oidcverify`) and directory-sync events (`syncauth`).
6. **Key files are never silently replaced, weakened or guessed.** A corrupt, short or
   world-readable key file is an error.
7. **Outbound clients do not leak credentials or follow an attacker somewhere else**: SCIM,
   JWKS and offsite targets.
8. **Logs and audit chains cannot be forged** by the values written into them.

## Threat model

| Attacker | Can | Wants |
|---|---|---|
| Someone who can write a capsule file or a backup store | Supply any bytes to `capsule.Open` | Restore their data, write outside the target, crash the restore |
| Someone who can write a product's database | Supply any stored password hash, audit record or share | Make verification pass, or make it exhaust resources |
| Anonymous network client of a product | Send tokens, sync events and login attempts | Sign in or deprovision without the issuer's key |
| Network attacker or hostile server on an outbound path | Answer JWKS, SCIM, SFTP, SMB or S3 requests | Steal a bearer token or secret, redirect a request, swallow or serve data |
| Custodian error | Type a share wrong, reuse one, mix two kits | (not hostile) get a wrong key without being told |

Out of scope: an attacker who runs code inside the importing process, and a product that
ignores this library's documented contract (for example skipping `capsule` manifest checks
[CAPSULE.md](CAPSULE.md#capsule) tells it to make). Durable replay storage and session invalidation belong to the
receiving product (see [AGENTS.md](../AGENTS.md)).

## Trust boundaries

1. **Capsule bytes → `capsule.Open`.** Everything in a capsule is untrusted until the AEAD
   check passes; `ReadUnverifiedManifest` returns a separate type, `UnverifiedManifest`, so a
   caller cannot treat an unchecked manifest as a checked one.
2. **Stored values → `password`, `auditchain`, `shamir`, `keyfile`.** A stored hash, chain or
   share is parsed strictly and bounded before any expensive work.
3. **Inbound requests → `oidcverify`, `syncauth`.** Signatures and claims are checked before
   the handler sees the request; bodies are read through a size limit.
4. **This process → remote servers** (`oidcverify` JWKS, `scim`, `offsite`). Each client
   refuses redirects and requires HTTPS or a pinned key, except the S3 endpoint override (see
   Residual risk).
5. **This module → its dependencies.** The root module may depend only on `golang.org/x/crypto`
   and the `golang.org/x/sys` it needs, and only `password` may import it. `offsite` is a separate
   module so its SFTP, SMB and AWS SigV4 signer (`aws-sdk-go-v2`, no S3 client) dependencies
   reach only products that import it.

## Secure design principles applied

- **Fail-safe defaults.** A malformed stored hash is an error, never a fallback to default
  parameters. A corrupt key file is an error, never regenerated. An SFTP target with no pinned
  host key cannot connect. A full replay guard refuses rather than forgets.
- **Economy of mechanism.** The standard library provides HPKE, HKDF, PBKDF2, HMAC and RSA; the
  root module's only third-party code is Argon2 from `golang.org/x/crypto`.
- **Least common mechanism.** One implementation of each primitive replaces the suite's
  divergent copies; the package pages record each copy's flaw.
- **Complete mediation.** `oidcverify` checks `alg`, `iss`, `aud`, `exp` and `kid` on every
  token; `syncauth` binds the timestamp, type, event ID and body hash into every signature.
- **Separation of privilege.** The recovery key exists only as Shamir shares held by different
  custodians; `capsule.Seal` refuses a threshold below 2 (`capsule/seal.go`).
- **Open design.** Only published algorithms: X-Wing (ML-KEM-768 with X25519), HKDF-SHA256,
  AES-256-GCM, Argon2id, PBKDF2-SHA256, HMAC-SHA256, RS256, and HMAC-SHA1 for TOTP, which
  RFC 6238 authenticators require.
- **Psychological acceptability.** Shares are self-describing and carry a check field, so a
  custodian's typing mistake is caught at the card, not after a wrong restore.

## Common weaknesses and how they are countered

| Weakness | Counter | Where |
|---|---|---|
| Tampered or substituted backup | HPKE X-Wing seal; the manifest's exact bytes are the AEAD's associated data, so the AEAD check covers every manifest field. (The recovery key ID compare before decapsulation only gives a clearer error for the wrong kit; it is not the check.) | `capsule/seal.go` (`sender.Seal(manifestBytes, payload)`), `capsule/hpke.go`, `capsule/container.go`, `recoverykey/recoverykey.go` (`hpke.MLKEM768X25519`) |
| Path traversal and symlink escape on restore (CWE-22, CWE-59) | Every write goes through an `os.Root` handle; absolute paths, backslashes and `..` are refused; only regular files are written; modes clamped to owner-only | `capsule/extract.go` (`os.OpenRoot`, `writeInto`) |
| Decompression bomb (CWE-409) | 256 MiB expanded, 64 MiB per member, 4096 members; the limit counts the tar stream | `capsule/extract.go` (`MaxExpandedBytes`, `MaxFileBytes`, `MaxFiles`) |
| Weak password storage (CWE-916) | Argon2id, m=64 MiB, t=3, p=4, random salt from `crypto/rand`; constant-time comparison | `password/password.go` (`DefaultParams`, `subtle.ConstantTimeCompare`) |
| Resource exhaustion via stored parameters (CWE-400) | Stored parameters bounded to 8–256 MiB, t≤10, p≤16; derivations share a 256 MiB and 16-lane budget and return `ErrBusy` instead of queuing; PBKDF2 iterations bounded to 100,000–12,000,000 | `password/password.go`, `derive/derive.go` (`MinIterations`, `MaxIterations`, `ErrBusy`) |
| Algorithm confusion and unsigned tokens (CWE-347) | RS256 only, checked before any key work; non-RSA JWKS entries ignored | `oidcverify/oidcverify.go` (`header.Alg != "RS256"`), `TestVerifyRefusesAlgorithmConfusionAndBadSignatures` |
| Forged or replayed sync events (CWE-294) | HMAC-SHA256 over timestamp, type, ID and body hash; constant-time compare; time window; replay guard | `syncauth/syncauth.go` (`hmac.Equal`), `TestVerifyBindsEveryField`, `FuzzVerify` |
| Credential sent to a redirect target or over plain HTTP | JWKS and SCIM clients require `https` and refuse redirects; the SCIM bearer token is redacted from error text | `oidcverify/oidcverify.go` (`CheckRedirect`), `scim/client.go` (`CheckRedirect`), `TestRedirectIsRefusedAndTokenNotReplayed`, `TestTokenIsRedactedFromErrorDetail` |
| SFTP man-in-the-middle or legacy cryptography | Pinned SHA-256 host fingerprint, supported SSH algorithms, minimum key sizes and SHA-2 RSA authentication; an undersized key is refused even when pinned | `offsite/sftp.go` (`HostKeyCallback`, `strongSFTPKey`), `offsite/sftp_policy_test.go` |
| Undersized imported TOTP secret | Code generation and validation refuse secrets below RFC 4226's 128-bit minimum, without rewriting stored enrolments | `totp/totp.go`, `TestRejectsUndersizedSecrets` |
| Undersized HTTPS peer keys | The supported Go process configuration enables runtime TLS filters over the complete verified chain, including supplied roots. Normal hostname/trust checks remain required; insecure/custom bypass clients are outside the profile | `docs/STRONG-CRYPTO.md`, `crypto_profile_test.go` (`TestStrongTLSProfile`) |
| SMB downgrade | Message signing required; SMB1 never negotiated | `offsite/smb.go` (`RequireMessageSigning: true`) |
| Weak or predictable randomness (CWE-338) | `crypto/rand` for salts, Shamir coefficients, set IDs, recovery codes and generated keys; a `crypto/rand` error is never discarded when generating a key | `shamir/shamir.go`, `recoverycode/recoverycode.go`, `keyfile/keyfile.go` (`cryptoRandRead`), `password/password.go` |
| Secret-dependent timing in Shamir | GF(2^8) multiply and inverse are branch-free and table-free | `shamir/shamir.go` (`mul`, `inverse`) |
| Silent wrong secret from bad shares | Duplicate, truncated and index-0 shares are errors; shares carry threshold, set ID and a check field | `shamir/shamir.go`, `FuzzCombineNeverPanics`, `FuzzParseShareNeverPanics`, `TestRoundTripEveryIndexSubset` |
| Key file weakened or replaced | Refuses a file that is not exactly the expected size or is not mode 0600; creation by temp file and `os.Link`, so a race cannot leave a partial key; `Store` never overwrites | `keyfile/keyfile.go` |
| Audit-log tampering or truncation | HMAC chain with a 32-byte minimum key; an anchor records the last sequence number and hash | `auditchain/auditchain.go` (`minKeyBytes`, `hmac.Equal`) |
| Log injection (CWE-117) | Control characters and invalid UTF-8 in field values are replaced, and values are capped at 256 bytes, before any handler renders them | `logging/field.go` (`sanitize`), `FuzzFieldValuesCannotForgeALine` |
| Oversized response bodies | Request and response bodies read through `io.LimitReader` | `syncauth/syncauth.go`, `scim/client.go`, `oidcverify/oidcverify.go` |
| Vulnerable or unexpected dependencies | Dependency allowlist enforced by tests; `govulncheck` on both modules in CI; Dependabot | `nodeps_test.go` (`TestModuleDependenciesAreAllowlisted`, `TestOnlyPasswordImportsADependency`), `.github/workflows/ci.yml` (`vulncheck`) |
| Tampered release | Versions are fixed by the Go checksum database | [VERIFYING-RELEASES.md](VERIFYING-RELEASES.md) |

## Residual risk

- **The recovery private key cannot be erased from memory in Go.** The ceremony host must run
  with swap off and core dumps disabled, and be destroyed afterwards ([CAPSULE.md](CAPSULE.md#recoverykey)).
- **SMB can accept an unsigned guest session** that `go-smb2` lets a server grant. Use SMB only
  on a trusted network (offsite/README.md, "SMB limitation"). Its NTLMv2 compatibility
  path also uses MD4/MD5-derived authentication and RC4 session-key exchange. The
  strong-cryptography profile selects pinned SFTP or HTTPS S3 instead of SMB.
- **The S3 endpoint override accepts `http://`** (`offsite/s3.go`, `newS3Target`), for local
  MinIO. SigV4 does not send the secret key, but objects and signed requests then travel
  unencrypted, and a network attacker can drop or replay them. Products send encrypted
  capsules, and should not configure a plain-HTTP endpoint across an untrusted network.
- **`DummyVerify` does not hide account existence under load**: `ErrBusy` returns without
  deriving ([CREDENTIALS.md](CREDENTIALS.md#password)).
- **Replay protection for back-channel logout is the receiving product's job**; `oidcverify`
  only verifies.
- No independent security audit has been done.

## Evidence

- **Tests:** every package has tests; CI runs both modules under the race detector on Linux and
  macOS with Go 1.26 and the latest stable Go. The package pages name the test that pins each
  security property.
- **Fuzzing:** four fuzz targets (`FuzzCombineNeverPanics`, `FuzzParseShareNeverPanics`,
  `FuzzOpenNeverPanics`, `FuzzFieldValuesCannotForgeALine`) run for 10 minutes each every night
  (`.github/workflows/fuzz.yml`); their seed corpora run with every `go test`.
- **Static analysis:** CodeQL code scanning, `go vet`, and `govulncheck` on both modules.
- **Supply chain:** OpenSSF Scorecard weekly and on every push to `master`
  (`.github/workflows/scorecard.yml`).
- **Releases:** module versions fixed by the Go checksum database
  ([VERIFYING-RELEASES.md](VERIFYING-RELEASES.md)).

A pull request that changes a trust boundary or a security requirement must update this page in
the same change.
