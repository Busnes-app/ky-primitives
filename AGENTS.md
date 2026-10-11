# ky-primitives

## Purpose and ownership

Shared security primitives for the Ky suite. Package contracts and usage live in
[README.md](README.md); `offsite/` is a separately versioned nested module.

## Local contracts

- Keep the root module's dependency budget and package import boundary enforced by
  `nodeps_test.go`. `oidcverify` remains standard-library-only.
- `applysetup` owns shared installer boundaries and opt-in immutable Linux metadata
  staging; products retain envelope validation, credential generation and native setup.
- `oidcverify.VerifyLogout` returns logout-only claims. Share signature/JWKS verification
  with authentication while retaining separate purpose checks; logout tokens must fail
  `Verify`, `VerifyWithNonce`, and `Middleware`.
- `recoveryclient.LoadRecoveryKey` validates retained custodian topology at the persistence-read boundary (`2 <= k <= n <= 255`) without repairing missing or corrupt pins/settings.
- Receivers own durable replay prevention and session invalidation. Preserve the
  issuer/client/session scope and the leeway-inclusive replay cutoff documented under
  README's Back-channel logout section; verification alone never claims offboarding.

## Verification

Use the build, vet, race-test and vulnerability commands in `.github/workflows/ci.yml`.
For OIDC changes, run `go test -race ./oidcverify`; keep clock-boundary tests deterministic
and use signed tokens against the HTTPS JWKS fixture for trust-boundary regressions.

## Child DOX Index

- `applysetup/AGENTS.md`: container-local installer bundle/capability/report boundaries.
