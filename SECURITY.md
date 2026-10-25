# Security Policy

ky-primitives provides shared security primitives (capsule sealing, the recovery client, key pinning) used across the suite. Because many products import it, its trust boundaries are the suite's trust boundaries.

## Reporting vulnerabilities

Report security vulnerabilities privately through GitHub Security Advisories:
<https://github.com/Busnes-app/ky-primitives/security/advisories>. Do not open a public issue.
Include the affected area, reproduction steps, impact, and affected versions.
We aim to acknowledge reports within two business days and will coordinate a fix
and disclosure.

## Trust boundaries and limitations

- The library handles key material and sealed containers. No public API may let a caller extract a private key, seed, or share, and the library must not log them.
- Capsule sealing binds a container to the pinned recovery public key; a change must preserve that binding and the integrity proof that `capsule.Open` enforces.
- The recovery client refuses non-HTTPS recovery URLs and, by default, private, loopback, and link-local targets; an explicit opt-in exists for operator LANs with loopback still refused.
- Public functions are a boundary: validate there, and keep error text free of secret material.

## Handling requirements

- Callers pin the recovery public key write-once; a second pairing to a different key must fail, not overwrite.
- Callers keep local copies, receipts, and audit records; never log tokens.
- Restore drills seal to a throwaway key generated and discarded inside the drill.

## Security-sensitive changes

Changes to sealing/opening, key handling, the recovery client, key pinning, or the sealed pairing record require tests for both the expected path and the relevant
failure or attack path, plus a description of the trust boundary in the pull
request.

## Related documents

- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution and review requirements
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community expectations
- [README.md](README.md) — what this project is and how to run it

