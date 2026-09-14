# ky-primitives

## Purpose and ownership

Shared security primitives for the Ky suite. Package contracts and usage live in
[README.md](README.md); `offsite/` is a separately versioned nested module.

## Local contracts

- Keep the root module's dependency budget and package import boundary enforced by
  `nodeps_test.go`. `oidcverify` remains standard-library-only.
- `oidcverify.VerifyLogout` returns logout-only claims. Share signature/JWKS verification
  with authentication while retaining separate purpose checks; logout tokens must fail
  `Verify`, `VerifyWithNonce`, and `Middleware`.
- Receivers own durable replay prevention and session invalidation. Preserve the
  issuer/client/session scope and the leeway-inclusive replay cutoff documented under
  README's Back-channel logout section; verification alone never claims offboarding.

## Verification

Use the build, vet, race-test and vulnerability commands in `.github/workflows/ci.yml`.
For OIDC changes, run `go test -race ./oidcverify`; keep clock-boundary tests deterministic
and use signed tokens against the HTTPS JWKS fixture for trust-boundary regressions.
