# ky-primitives

## Purpose and ownership

Shared security primitives for the Ky suite. Package contracts and usage live in
[README.md](README.md); `offsite/` is a separately versioned nested module.

## Local contracts

- Keep the root module's dependency budget and package import boundary enforced by
  `nodeps_test.go`. `oidcverify` remains standard-library-only.
- `docs/STRONG-CRYPTO.md` owns the library's supported key/TLS configuration.
  Preserve ordinary TLS trust/hostname verification and the existing application
  formats; do not replace those with a pin-only verifier or claim FIPS certification.
- `totp.Code` and `totp.Validate` refuse decoded secrets below 16 bytes; generated
  secrets stay 20 bytes. Callers preserve weak legacy records and require issuer
  re-enrolment rather than rewriting or dropping them.
- `offsite` SFTP uses only supported SSH algorithms, RSA keys of at least 2048 bits
  and non-SHA-1 RSA authentication/certificate signatures; host pins never waive
  key strength. SMB remains an explicit compatibility destination outside the
  strong-cryptography profile documented in `offsite/README.md`.
- Before a root or offsite module tag, update `CHANGELOG.md` with the released
  changes, upgrade/format impact, migration steps and known vulnerability IDs.
  Keep the two version streams and unpublished source changes separate.
- `applysetup` owns shared installer boundaries and opt-in immutable Linux metadata
  staging; products retain envelope validation, credential generation and native setup.
- `oidcverify.VerifyLogout` returns logout-only claims. Share signature/JWKS verification
  with authentication while retaining separate purpose checks; logout tokens must fail
  `Verify`, `VerifyWithNonce`, and `Middleware`.
- `recoveryclient.LoadRecoveryKey` validates retained custodian topology at the persistence-read boundary (`2 <= k <= n <= 255`) without repairing missing or corrupt pins/settings.
- `suitedir` follows KyIdentity-server `docs/SUITE-DIRECTORY.md`. It validates at the
  boundary: invalid apps are dropped, a peer needs an HTTPS URL and a 32-byte secret.
  HTTPS issuer (loopback http for tests), no redirects, bounded body; no caching.
- REUSE: `REUSE.toml` names every file's license and copyright; `LICENSES/` holds the
  texts. Copied third-party files (e.g. `recoverykey/testdata/xwing-vector.json`) keep
  their original license via an override entry; never relabel them MIT. CI runs `reuse lint`.
- Receivers own durable replay prevention and session invalidation. Preserve the
  issuer/client/session scope and the leeway-inclusive replay cutoff documented under
  the Back-channel logout section of [docs/IDENTITY.md](docs/IDENTITY.md#back-channel-logout); verification alone never claims offboarding.

## Verification

Use the build, vet, race-test and vulnerability commands in `.github/workflows/ci.yml`.
Both modules also run fresh race tests with `GODEBUG=fips140=on`. The root
`TestStrongTLSProfile` uses separate processes and actual verified TLS handshakes
to check the configured certificate-chain floors alongside accepted modern keys.
For OIDC changes, run `go test -race ./oidcverify`; keep clock-boundary tests deterministic
and use signed tokens against the HTTPS JWKS fixture for trust-boundary regressions.

## Child DOX Index

- `applysetup/AGENTS.md`: container-local installer bundle/capability/report boundaries.
