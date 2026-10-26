# Supported strong-cryptography configuration

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Offsite](../offsite/README.md)

This configuration covers the current root module and optional `offsite` module.
It adds a tested TLS peer-key policy to the library's existing key-size guards.
It is a configuration for applications embedding the library, not a FIPS
certification or an assertion that every Ky product already uses it.

## Select source with the key guards

Use a revision containing [the TOTP and SFTP minimums](https://github.com/Busnes-app/ky-primitives/commit/1c0be6a96fb7729c6d9d4338b65d3c17f293f601).
Root `v0.10.1` and `offsite/v0.2.2` predate those guards. Until a later module
release includes them, select that source revision explicitly for each module
you use; updating the root module does not update `offsite`.

The minimum supported Go version is the version in each module's `go.mod`.
The TLS policy below is tested with Go 1.26 and current stable Go on the CI
Linux/macOS matrix. Use an operating system supported by Go's FIPS runtime mode;
consult [Go's platform and mode documentation](https://go.dev/doc/security/fips140).

## Set the process TLS policy

Set this before starting the embedding application's Go process:

```sh
GODEBUG=fips140=on ./your-application
```

If the application already has a `GODEBUG` value, retain its other settings and
set its `fips140` entry to `on` exactly once. In Compose, set it in the actual
application service's `environment`; in Kubernetes, set it in the application's
container `env`. A shell variable on the container host does not configure an
already running container. Recreate/restart the application after changing it:
Go fixes this policy at process startup.

Go then filters TLS 1.2/1.3 negotiations and verified certificate chains. RSA
keys must be at least 2048 bits; the permitted certificate EC curves are P-256,
P-384 and P-521, with fixed-size Ed25519 also supported. The chain filter includes
intermediates and trusted roots, even roots supplied explicitly by the caller.
A pinned fingerprint or trusted private CA does not waive these limits.

Keep ordinary certificate-chain and hostname verification enabled. Do not supply
an `InsecureSkipVerify` client, an HTTP endpoint, or a custom TLS transport that
bypasses Go's verifier. This applies to configured HTTP clients passed to the
library as well as the clients it creates for recovery, OIDC/JWKS, SCIM and S3.
Keep the existing redirect, origin and destination-address checks.

The profile uses `fips140=on`. Go documents `fips140=only` as a diagnostic mode
that can introduce errors/panics for otherwise working application algorithms;
it is not this production configuration. Argon2id, interoperable HMAC-SHA1 TOTP
and X-Wing recovery remain part of the library's design. Enabling a TLS policy
does not turn the whole library or an embedding application into a validated
FIPS application.

## Keys and enabled transports

| Boundary | Supported configuration and enforcement |
|---|---|
| Capsule/recovery key | Keep the fixed X-Wing, HKDF-SHA256 and AES-256-GCM suite. Generate the suite key through `recoverykey`; products hold only its public key. Preserve custodian thresholds, key pins and historical restore formats. |
| TOTP | `totp.GenerateSecret` produces 20 random bytes. `Code`/`Validate` refuse decoded secrets below 16 bytes for all supported HMAC choices. Preserve weak legacy records and require issuer re-enrolment; never pad or rewrite a secret. |
| Stored symmetric keys | `keyfile` creation/loading/storing has a 16-byte floor and loads exactly the caller's declared size. Use 32 random bytes for application encryption and audit keys; `auditchain` itself requires 32 bytes. Do not replace an unreadable retained key. |
| Directory-sync HMAC | Use an independently generated 32-byte secret. `syncauth` signing and verification refuse fewer than 16 bytes. Length checks do not prove a hand-written string has enough entropy. |
| OIDC/JWKS signatures | `oidcverify` accepts RS256 and RSA modulus sizes of at least 2048 bits. Use its normal verified HTTPS client under the process policy above. |
| Offsite destinations | Choose local `file://`, pinned SFTP, or S3 over verified HTTPS. SFTP's supported-algorithm and host/client/CA-key guards remain mandatory; compare host fingerprints out of band. Do not configure S3's plaintext HTTP override. |
| SMB compatibility | Do not configure an `smb://` target in this profile. Its NTLM compatibility mechanisms remain as described in the [offsite limitations](../offsite/README.md#smb-limitation); enabling Go's TLS mode does not remove them. A host-mounted share also needs the host's own transport policy. |

Password-derived credentials and one-time recovery codes have their own
authentication rules; they are not raw cipher/HMAC keys. Keep the existing
password KDF, salts, hashing, one-time redemption and rate limits. Generic Shamir
splitting does not select a cipher key; use `recoverykey` for suite recovery keys.

Products must additionally inventory their own imported signing keys, SAML,
database, mail, SSH and other integrations. Their inbound HTTPS reverse proxy is
outside this library and needs its own strong certificate/key/TLS configuration.
The Go setting does not configure browsers, native Qt/OpenSSL or Android/Apple
TLS stacks, or change intentionally retained archive-decryption behavior.

## Verification and rollout

Run both modules' full checks, including the configured process policy:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
GODEBUG=fips140=on go test -race -count=1 ./...
# Repeat in offsite/ when that module is used.
```

`TestStrongTLSProfile` starts separate processes with the setting off and on.
Real TLS 1.2 and 1.3 requests demonstrate that RSA-1024/2047 leaves, an RSA-1024
intermediate/root and a P-224 root work in the baseline but fail under the
profile, before an authenticated HTTP request reaches the fixture. RSA-2048,
P-256 and Ed25519 leaves continue working; hostname and trust failures still
fail. No insecure verifier is substituted by the test. Both modules also run
their full race suites in the configured mode, covering capsule restore, TOTP,
password derivation and the permitted offsite algorithms. In configured mode,
`x/crypto/ssh` refuses creation of a SHA-1 certificate fixture itself; the
ordinary-mode suite still checks refusal of that certificate over a real SSH
connection.

Before enabling this policy in an existing product, inventory and upgrade its
external peer certificates and CA chains, and run that product's integration
checks under the setting. A refused peer requires a new certificate/key or a
supported endpoint, not disabling verification. Roll out one product at a time;
do not regenerate application keys, rewrite enrolled secrets or re-seal historical
archives as a workaround. Test a known restore and normal authentication before
declaring that product's whole configuration verified.

Primary references: [Go runtime mode](https://go.dev/doc/security/fips140),
[Go 1.26.10 TLS filters](https://github.com/golang/go/blob/go1.26.10/src/crypto/tls/defaults_fips140.go),
[complete-chain enforcement](https://github.com/golang/go/blob/go1.26.10/src/crypto/tls/common.go#L1824),
[RFC 4226 key requirement](https://www.rfc-editor.org/rfc/rfc4226#section-4).
