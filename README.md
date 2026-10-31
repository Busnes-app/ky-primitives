# ky-primitives

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15936/badge)](https://www.bestpractices.dev/projects/15936)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Busnes-app/ky-primitives/badge)](https://scorecard.dev/viewer/?uri=github.com/Busnes-app/ky-primitives)

Shared security primitives for the Busness.app suite.

The `offsite/` directory is a separately versioned nested module. Its transport
dependencies are not requirements of this root module.

- [Contributing](CONTRIBUTING.md) — how to propose a change and what it must pass.
- [Verifying releases](docs/VERIFYING-RELEASES.md) — check a module version against this repository and the Go checksum database.
- [Release notes](CHANGELOG.md) — changes and upgrade impact for every root/offsite module tag.
- [Assurance case](docs/ASSURANCE-CASE.md) — threat model, trust boundaries, and why the security requirements are met.
- [Strong-cryptography configuration](docs/STRONG-CRYPTO.md) — required source/key sizes, verified TLS peer policy and excluded compatibility destinations.

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

## Packages

Each package's contract, the flaws it replaced and the tests that pin it are in the linked page.

| Package | What it is |
| --- | --- |
| [`capsule`](docs/CAPSULE.md#capsule) | Reads and writes the suite's encrypted backup container. |
| [`recoverykey`](docs/CAPSULE.md#recoverykey) | The suite's recovery keypair; its private key exists only while it is split into shares or combined for a restore. |
| [`shamir`](docs/RECOVERY.md#shamir) | Splits a secret into custodian shares and reconstructs it. |
| [`recoverycode`](docs/RECOVERY.md#recoverycode) | One-time codes that bypass every other factor, so their strength is the account's strength. |
| [`recoveryclient`](docs/RECOVERY.md#recoveryclient) | The product side of the suite's backup contract with KyRecovery. |
| [`auditchain`](docs/AUDIT-AND-LOGGING.md#auditchain) | Builds and verifies a tamper-evident hash chain over audit records. |
| [`logging`](docs/AUDIT-AND-LOGGING.md#logging) | Emits JSON lines on stderr. |
| [`health`](docs/AUDIT-AND-LOGGING.md#health) | Serves `/healthz` in the suite's one shape, `ky.health/1`, which kyPulse reads. |
| [`password`](docs/CREDENTIALS.md#password) | Hashes and verifies passwords with Argon2id. |
| [`totp`](docs/CREDENTIALS.md#totp) | RFC 6238 one-time passwords. |
| [`keyfile`](docs/CREDENTIALS.md#keyfile) | Loads a long-lived secret from disk, creating it on first use. |
| [`derive`](docs/CREDENTIALS.md#derive) | The login secret a client sends in place of a password: PBKDF2-SHA256 stretched, then HKDF-SHA256 expanded. |
| [`syncauth`](docs/IDENTITY.md#syncauth) | One definition of how KySignOn signs a directory-sync event and how a product verifies it. |
| [`oidcverify`](docs/IDENTITY.md#oidcverify) | Verifies the RS256 tokens KySignOn issues against its JWKS, on the standard library. |
| [`scim`](docs/IDENTITY.md#scim) | The SCIM 2.0 client KySignOn provisions accounts with, and the RFC 7643 User type it shares with a server. |
| [`suitedir`](docs/IDENTITY.md#suitedir) | Asks KyIdentity which suite apps a user may open, and for a paired app's URL and shared syncauth secret. |

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

## License

ky-primitives is released under the [MIT License](LICENSE.txt).

[![OctoCounts](https://api.octocounts.com/badge/Busnes-app/ky-primitives/branch/master)](https://octocounts.com/github/Busnes-app/ky-primitives/tree/master)

## Documentation

- [Backup container and recovery key](docs/CAPSULE.md) — the `kycap/3` encrypted backup container and the suite recovery keypair. <a id="capsule"></a><a id="extraction-hardening"></a><a id="fixtures"></a><a id="recoverykey"></a>
- [Recovery shares, codes and client](docs/RECOVERY.md) — custodian shares, one-time recovery codes and the product side of the KyRecovery contract. <a id="shamir"></a><a id="recoverycode"></a><a id="recoveryclient"></a>
- [Audit chain, logging and health](docs/AUDIT-AND-LOGGING.md) — the tamper-evident audit chain, JSON logging and the `/healthz` shape. <a id="auditchain"></a><a id="logging"></a><a id="health"></a>
- [Passwords, TOTP, key files and derivation](docs/CREDENTIALS.md) — Argon2id password hashing, TOTP, key-file loading and client-side login-secret derivation. <a id="password"></a><a id="totp"></a><a id="keyfile"></a><a id="derive"></a>
- [Sync signing, OIDC, SCIM and suite directory](docs/IDENTITY.md) — directory-sync signatures, OIDC token verification and back-channel logout, the SCIM client and the suite directory client. <a id="syncauth"></a><a id="oidcverify"></a><a id="back-channel-logout"></a><a id="scim"></a><a id="suitedir"></a>
- [Container-local installer setup](docs/INSTALLER-SETUP.md) — `applysetup` bundle decoding, refusals and staged preparation. <a id="container-local-installer-setup"></a>
- [offsite](offsite/README.md) — the nested module that copies backups to SFTP, S3 or SMB destinations.
- [Logging policy](logging/LOGGING.md) — the JSON log format every Ky product emits.
- [Strong cryptography](docs/STRONG-CRYPTO.md) — the supported key and TLS configuration.
- [Verifying releases](docs/VERIFYING-RELEASES.md) — check a release tag against its source.
- [Assurance case](docs/ASSURANCE-CASE.md) — threat model, trust boundaries, and why the security requirements are met.
- [Contributing](CONTRIBUTING.md) — how to propose a change and what it must pass.
- [Security policy](SECURITY.md) — how to report a vulnerability privately.
- [Release notes](CHANGELOG.md) — what changed in each release, and its upgrade impact.
