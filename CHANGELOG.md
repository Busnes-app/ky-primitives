# Release notes

The root Go module and the nested `offsite` module have separate versions. These
human summaries were reconstructed from the published tags and source history on
2026-10-26; they do not claim the original tags shipped with release notes. Tags
are unchanged. Read [verification instructions](docs/VERIFYING-RELEASES.md) before
selecting a version. This history describes older behavior, not a recommendation
to deploy a superseded version.

Before tagging either module, add its changes, compatibility impact and any
required migration here. Name known vulnerability identifiers when applicable.
Keep unpublished changes separate from tagged releases.

## Unreleased source changes

- Root/offsite: document the supported strong-key/TLS process configuration and
  run both modules' race suites in that mode. A real-handshake regression checks
  certificate-chain key floors while preserving ordinary trust/hostname checks.
  The library does not change an embedding application's runtime environment:
  operators enable the documented profile and verify each product's extra
  integrations. Capsule formats, credentials and retained keys are unchanged.
- Root: Shamir splitting now samples every polynomial coefficient uniformly,
  including zero, instead of conditioning the leading coefficient to be nonzero.
  This restores the intended share distribution without changing `ky2` encoding
  or the ability to combine existing shares. [Source change](https://github.com/Busnes-app/ky-primitives/commit/ad09877).
- Offsite: S3 requests use the AWS SDK SigV4 signer, including standard object-path
  escaping, rather than the local signer. The target API is unchanged; operators
  should verify their S3-compatible endpoint during adoption.
  [Source change](https://github.com/Busnes-app/ky-primitives/commit/f39c65a).
- Root: `totp.Code` and `totp.Validate` refuse decoded secrets below 16 bytes
  (RFC 4226's minimum). Generated secrets are unchanged at 20 bytes. Callers must
  keep weak legacy records and have users re-enrol rather than rewrite them.
- Offsite: SFTP refuses SHA-1 key exchange and signatures, DSA, HMAC-SHA1-96 and
  RSA keys below 2048 bits, with no legacy fallback; a matching host pin does not
  waive key strength. Replace weak server/client keys or old SSH servers before
  adopting, then re-verify and re-pin the host fingerprint.
- Contributor/security documentation, pinned CI actions and live assurance badges
  were added. These changes do not publish a new module version.

## Root module

### [v0.10.1 — 2026-10-23](https://github.com/Busnes-app/ky-primitives/tree/v0.10.1)

Capsule sealing now counts tar headers, padding, the member list and trailer in
the expanded-size budget. It refuses oversized payloads before producing a capsule
that `Open` would reject. Installer setup exposes bounded, secret-free refusal
reasons so an operator can diagnose a rejected request. Release verification,
licensing and assurance documentation were added; Go dependencies were refreshed.

Upgrade impact: callers must handle the existing size-limit error for payloads
near the expanded limit, including many small files. Already valid `kycap/3`
containers retain their format. This tag requires Go 1.26.6. Offsite transport fixes
at the same repository revision have their own module versions below.

### [v0.10.0 — 2026-10-11](https://github.com/Busnes-app/ky-primitives/tree/v0.10.0)

Adds `applysetup`: shared installer bundle parsing, capabilities, protected credential
file references, private Unix-socket transport and opt-in Linux metadata staging.
Products still implement validation of their extended envelope, account/configuration
mutations and activation. Keyfile loading refuses FIFOs; recovery-key loading refuses
invalid retained threshold/share topology rather than repairing it. Dependencies
and CI toolchains were refreshed.

Upgrade impact: product adapters must validate their own inputs before invoking
setup operations. Staging reports metadata preparation, not a completed installation.
An installation with a FIFO key path or corrupt recovery topology now fails closed;
repair from a verified backup or the documented product procedure, not a new random
key. Go 1.26.6 is required. Capsule/share wire formats remain `kycap/3` and `ky2`.

### [v0.9.0 — 2026-09-26](https://github.com/Busnes-app/ky-primitives/tree/v0.9.0)

Adds the `health` package and the `ky.health/1` readiness contract: bounded dependency
checks, reason codes, panic/hung-check containment and an HTTP handler with a shared
five-second result cache and bounded diagnostic logging.

Upgrade impact: products opt into the handler and supply their own dependency checks.
Wire clients should use the documented health contract rather than parse log text.
Existing capsule, account and audit data need no format migration.

### [v0.8.0 — 2026-09-16](https://github.com/Busnes-app/ky-primitives/tree/v0.8.0)

Moves the module namespace to `github.com/Busnes-app/ky-primitives` after the
organization rename.

Upgrade impact: update Go import paths and the module requirement together, then
tidy and test each consumer. This is a module-identity change, not a rewrite of
stored capsules, custodian cards or audit records. Use the current repository
coordinates in the verification guide.

### [v0.7.0 — 2026-09-14](https://github.com/Busnes-app/ky-primitives/tree/v0.7.0)

Adds verification of OIDC back-channel logout tokens, with logout-specific claims
and validation kept separate from ordinary authentication tokens.

Upgrade impact: a receiving product must still persist replay prevention and revoke
the correct local sessions. Verifying a logout token alone does not implement
offboarding. Existing authentication-token verification remains a separate API.

### [v0.6.0 — 2026-09-05](https://github.com/Busnes-app/ky-primitives/tree/v0.6.0)

Adds the standard-library SCIM 2.0 client and user wire model for provisioning.
The client bounds Retry-After, verifies user-search results, redacts bearer tokens
from errors and refuses unexpected response statuses.

Upgrade impact: consumers opt into the new client and retain their own provisioning
policy, retries and account/role mapping. No existing backup or audit format changes.

### [v0.5.2 — 2026-09-05](https://github.com/Busnes-app/ky-primitives/tree/v0.5.2)

Recovery requests distinguish private-destination refusals, allowing products to
explain a network-policy failure separately from a generic remote failure. The sync
signature tamper test was corrected to always mutate the signature.

Upgrade impact: handle the private-destination error with an explicit operator
explanation; do not silently disable HTTPS or destination protection. No container
or share migration is needed.

### [v0.5.1 — 2026-09-05](https://github.com/Busnes-app/ky-primitives/tree/v0.5.1)

Restore-drill callbacks receive the authenticated opened manifest. Recovery pairing
refuses whitespace-only tokens, audit notes were clarified, and `LocalPrefix` is
exported for product-controlled local-copy migrations. The separate offsite module
was introduced at a nearby repository revision.

Upgrade impact: adapt drill callback signatures and validate any product-specific
recipe fields before using them. A passing throwaway-key drill does not demonstrate
custodian-card availability. Importing the root module does not add offsite transport
dependencies.

### [v0.5.0 — 2026-09-04](https://github.com/Busnes-app/ky-primitives/tree/v0.5.0)

Adds `recoveryclient` for pairing, write-once key pinning, sealing, local copies,
scheduled deposits, receipts, restore and drills. Adds `syncauth` for the shared
directory-event signature and `oidcverify` for RS256/JWKS token validation. OIDC
issuer/key discovery requires HTTPS and refuses redirects; local-copy app-name
escaping and retained interval validation are bounded.

Upgrade impact: use product adapters for payload collection, settings, audit and
administrative UI. Send a stable service name when pairing and retain the suite
key pin and deposit receipt. Products must supply durable replay protection and
session revocation for directory events; the helpers do not own their stores.

### [v0.4.1 — 2026-09-03](https://github.com/Busnes-app/ky-primitives/tree/v0.4.1)

Exports capsule file, expanded-payload and container size limits so callers can
validate and explain the same limits enforced by the library.

Upgrade impact: replace duplicated limit values with exported constants where
appropriate. There is no capsule/share format migration in this patch.

### [v0.4.0 — 2026-09-03](https://github.com/Busnes-app/ky-primitives/tree/v0.4.0)

Introduces `kycap/3` and the suite `recoverykey` package. Products seal to the suite's
X-Wing public key through HPKE/HKDF-SHA256/AES-256-GCM instead of receiving a new raw
decryption key for each backup. Custodians split/recombine the recovery seed; the
manifest binds the recovery key ID and encapsulation. Zero-value keys are refused.
Adds `keyfile.Store` and the shared structured logging package.

Upgrade impact: this changes the sealing/opening API and retires `kycap/2` reading.
Run the suite ceremony and wire public-key pinning; products must never retain a
custodian share/private seed. Do not expect this release to restore old-format
containers: retain and test the appropriate prior recovery path before upgrading
any installation that has them. A successful open proves integrity to the key,
not the sender's identity or backup freshness. The ceremony host's memory cannot
be reliably erased by Go; follow the ephemeral-host procedure in the README.

### [v0.3.0 — 2026-09-03](https://github.com/Busnes-app/ky-primitives/tree/v0.3.0)

Moves per-file names, sizes and SHA-256 digests from the plaintext manifest into
the encrypted payload, preventing those fields from acting as offline content
confirmation oracles. Marks v0.2.0 retracted in Go module metadata.

Upgrade impact: stop selecting v0.2.0. A new library cannot remove information from
old exported capsules; generate replacement backups with a supported version and
handle old copies under the product's retention policy. This is the transitional
`kycap/2` release; v0.4.0 subsequently replaces its raw-key API with `kycap/3`.

### [v0.2.0 — 2026-09-02 — retracted](https://github.com/Busnes-app/ky-primitives/tree/v0.2.0)

Adds derivation, TOTP, recovery-code and keyfile helpers, bounded password/derivation
work, streaming audit verification/replay and anchored persistence callbacks.
Capsules use `kycap/2`, authenticate the manifest and expose authenticated versus
unverified manifest types. Shamir cards move to self-describing `ky2` shares with
threshold, split-set identity and a transcription check.

Upgrade impact: capsule, audit and share APIs change from v0.1.0, and older
capsule/share readers are retired. **Do not deploy this version:** its cleartext
per-file manifest leaks names, sizes and digests. v0.3.0 retracts it and removes
that exposure; use a current supported version and its migration guidance.

### [v0.1.0 — 2026-09-02](https://github.com/Busnes-app/ky-primitives/tree/v0.1.0)

Initial library release: common backup container handling, Shamir splitting,
tamper-evident audit chains and Argon2id password hashing. Password work uses
bounded parameters and admission control; capsule extraction validates paths,
member types, permissions and size limits.

Upgrade impact: this is the original API, with legacy capsule and share formats
superseded by later releases. Integrators should start with the current API rather
than adopt the old examples or assume later versions read every earlier format.

## Offsite module

The versions below apply to `github.com/Busnes-app/ky-primitives/offsite` only.
Updating the root module does not select a new offsite version automatically.

### [offsite/v0.2.2 — 2026-10-23](https://github.com/Busnes-app/ky-primitives/tree/offsite/v0.2.2)

SMB endpoint parsing now rejects ambiguous brackets, empty hosts and invalid,
empty or out-of-range ports while retaining bare/bracketed IPv6 and the default
port 445. The scanner configuration documents why GO-2026-5932, concerning unused
deprecated OpenPGP code, is not reachable in this module.

Upgrade impact: correct malformed stored SMB endpoints that previously passed
parsing but could not be dialed consistently. Valid endpoints and opaque object
formats are unchanged; the scanner exception is not a fix to an imported package.

### [offsite/v0.2.1 — 2026-10-23](https://github.com/Busnes-app/ky-primitives/tree/offsite/v0.2.1)

Moves SMB to the maintained cloudsoda/go-smb2 fork to address the upstream
[GO-2026-5051 advisory](https://pkg.go.dev/vuln/GO-2026-5051), and refreshes SSH-related
dependencies. The public target interface stays the same.

Upgrade impact: update the nested module explicitly, tidy its new transitive
dependencies and verify the selected SMB server. Message signing and the documented
unsigned-guest/NTLM compatibility limitations still apply; this is not a claim that
every SMB mode is secure for untrusted networks.

### [offsite/v0.2.0 — 2026-09-16](https://github.com/Busnes-app/ky-primitives/tree/offsite/v0.2.0)

Moves the nested module namespace to `github.com/Busnes-app/ky-primitives/offsite`.

Upgrade impact: change its Go module requirement/import paths together. Object
names, credentials and transport behavior do not change merely because of the
organization rename. The independently versioned root module moves in v0.8.0.

### [offsite/v0.1.0 — 2026-09-05](https://github.com/Busnes-app/ky-primitives/tree/offsite/v0.1.0)

Initial separately versioned transport module: one opaque-object target interface
for local files, S3, pinned SFTP and SMB. Paths are confined; local writes use
owner-only staging/rename. SMB names use a constrained canonical grammar and
existing destinations are refused instead of deleting a prior replica.

Upgrade impact: products own sealed credentials, scheduling, logging and payload
confidentiality. Use immutable SMB object names and verify SFTP host fingerprints
out of band. Read the [transport limitations](offsite/README.md#smb-limitation)
before selecting a destination.
