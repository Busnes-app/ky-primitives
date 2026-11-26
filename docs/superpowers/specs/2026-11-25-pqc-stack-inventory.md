# Ky stack crypto inventory for the PQC migration

Worker: samphire (read-only), for saltmarsh. Date: 2026-11-25. Scope: every non-archived Busnes-app repo
(`gh repo list Busnes-app --limit 200`; KyVault-server, KyMark-server, KyForge-Server are archived and skipped).
KyPost OpenPGP is out of scope (another worker); KyPost TLS, DKIM, push, JWT and device-approval crypto are included.
Read through `git show`/`git grep` on `origin/<default>` after `git fetch`, or `gh api` for repos absent on the build host.
Nothing was built, run or edited.

> Public copy. Rows and notes for private repos (infrastructure, launch, dashboard, demo and site repos) are kept out of this public repository; the owner holds the private copy.

## Snapshots (origin/default short SHA)

| repo | branch | sha | | repo | branch | sha |
|---|---|---|---|---|---|---|
| .github | main | b2ee038 (gh api) | | KyMessage-Server | master | 439babc |
| Busnes.app-site | master | 23e10f6 | | kymessages-desktop | main | 0c3de83 (gh api) |
| go-webdav | kycalendar | 7f1337b | | KyMessages-Native | main | 9202576 |
| ky-primitives | master | 871828c | | KyPost-for-Android | main | 01f304bb |
| ky-server-base | master | eceb24e | | KyPost-for-Linux | main | ae383bf |
| ky-ui | main | 1b0e466 | | KyPost-for-Mac | main | 165148e |
| KyAuth-android | main | 559e687 | | KyPost-Server | main | 928ba0be |
| KyAuth-iOS | master | f31cc76 | |  |  |  |
| KyAuth-Linux | master | c2efea6 | | KyPulse-server | master | 7a45d37 |
| KyCalendar | main | 7bce306 | | KyQuickStart | master | 950c3f8 |
| KyDNS-server | main | cdaae83 | | KyQuickStart-AI | master | 3a7b8ef |
| kydrive-desktop | main | 9596d67 | | KyRecovery-server | main | 45dfe28 |
| KyDrive-for-Android | main | 60e755b | | KyVault-backend | main | c0a86c2a |
| kydrive-server | master | 9d5a468 | | KyVault-web | main | 1344eb7 |
| kyguard-server | main | 37b302b | | KyYard-server | master | 8148a97 |
| KyIdentity-server | master | 6e7df38 | |  |  |  |

Other refs cited: ky-primitives pins seen in consumers (`9f4bc58` in KyIdentity-server, `b5f5853` in kydrive-server; see
the import map in §2); kyguard-server branch heads for open PRs #13/#14; kydrive-server local unpushed branch
`feat/per-org-keys` @ `ac85499` (the build host only, not on GitHub).

**Citation convention.** Locations are `Repo:path:line @ sha`. Where a table cell gives a bare `path:line`, the repo is
the row's app/repo and the SHA is the snapshot above (for KyIdentity-server rows: `@ 6e7df38`; KQS/KQA/infra/launch =
KyQuickStart / KyQuickStart-AI / the private infra repo / the private launch repo). Quantum exposure values: **HNDL (confidentiality)** =
classical key exchange / public-key encryption / key wrap, recordable today and decryptable by a future CRQC;
**forgery-only (signatures)** = classical signature or asymmetric auth, broken only once a CRQC exists (no retroactive
harm except where signatures protect long-lived trust, e.g. CA roots, release keys); **PQ-hybrid already** = ML-KEM
hybrid in use (peer-dependent where noted); **symmetric, PQ-safe at 256-bit**; **symmetric, 128-bit: … review** (AES-128,
or HMAC/secret floors of 16 bytes); **n/a**.

## Headline findings

**Cross-cutting Go fact (verified in Go source).** Every Go service builds with Go 1.26.x/1.27.x (`go.mod` toolchain
lines, e.g. `KyIdentity-server:go.mod:3-5 @ 6e7df38`, `KyPost-Server:backend/go.mod:3-5 @ 928ba0be`), and **no Go repo
sets `tls.Config.CurvePreferences` except kyguard-server** (which puts `X25519MLKEM768` first:
`kyguard-server:internal/brokerproto/tls.go:12-13,25,44 @ 37b302b`), and none sets `GODEBUG=tlsmlkem=0` (grep of all
repos' `go.mod`, Dockerfiles, YAML and Go files). So every Go TLS 1.3 client and listener offers X25519MLKEM768 first:
`crypto/tls/defaults.go:23-43` enables it unless `tlsmlkem=0` and puts it first in `curvePreferenceOrder`
(https://github.com/golang/go/blob/go1.27.3/src/crypto/tls/defaults.go#L23-L43; read from the local go1.27.3 GOROOT on
the build host, the K hosts run 1.27.4: identical content unverified but expected for a patch release). The suite-wide
"strong-crypto" profile runs with `GODEBUG=fips140=on` (e.g. `ky-server-base:docker-compose.strong-crypto.yml:6 @ eceb24e`,
`KyQuickStart:Dockerfile:27 @ 950c3f8`). Under it, `common.go:1301` filters to `allowedCurvePreferencesFIPS`
(`defaults_fips140.go:35-43`: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM1024, P-256, P-384, P-521):
**the hybrid stays first, only plain X25519 is dropped** (https://github.com/golang/go/blob/go1.27.3/src/crypto/tls/defaults_fips140.go#L35-L43).
This settles the "fips140=on may turn hybrid off" doubt raised in the KyPost part. Exception: Go **1.24** FIPS lists were
P-256/P-384 only (see KyQuickStart-AI `kubectl-policy` row). Go 1.27 also ships `crypto/mldsa`
(`src/crypto/mldsa/mldsa_fips140v1.26.go:27`) and `crypto/hpke` with `MLKEM768X25519()` = X-Wing, KEM 0x647a
(`src/crypto/hpke/pq.go:21,39-41`). Most first-party servers serve plain HTTP behind an operator TLS proxy, so inbound
PQ depends on that proxy (nginx/NPM/cloudflared, see the infra part).

**Already PQ-hybrid.** ky-primitives `recoverykey` and `capsule` (X-Wing via stdlib `crypto/hpke`, HKDF-SHA256,
AES-256-GCM, info `kycap/3`; `ky-primitives:recoverykey/recoverykey.go:14-21,27,40-41 @ 871828c`), used for backup
capsules by every product that pins ky-primitives; kyguard-server envelopes (X-Wing HPKE) and signed objects
(ML-DSA-65 + Ed25519) and its broker listener; KyCalendar's X-Wing content-key library (on main, not yet wired in);
Go SSH clients (x/crypto v0.59.0 offers `mlkem768x25519-sha256` first: KyQuickStart, ky-primitives/offsite,
KyRecovery SFTP, kyguard SSH connector branch); KyQuickStart-AI's OpenSSH policy keeps OpenSSH's PQ defaults.

**HNDL priorities (classical confidentiality, recordable now), roughly by blast radius:**
1. **KyVault-web** (Bitwarden model): org-key shares, admin reset, emergency access, login-with-device, trusted devices
   are **RSA-2048-OAEP** wraps stored server-side. Upstream-bound (Bitwarden sdk-internal).
2. **KyNotes** team container-key envelopes and device linking: HPKE mode_auth **DHKEM(X25519)** stored on the server
   (`KyNotes-server:web/src/teamKeys.ts:10 @ 88c85c8`, verified); one envelope + CRQC = every note in the container.
   Also the Go MCP bridge (X25519 identity).
3. **KyMessages** Olm (Curve25519 X3DH-style) and Megolm key backup `m.megolm_backup.v1.curve25519-aes-sha2`;
   vodozemac 0.11.2 / matrix-sdk-crypto 0.19.1 have no PQ (only an abandoned upstream `poljar/pq` branch).
   Calls: classical DTLS-SRTP (LiveKit/pion), planned SFrame-like E6 not built.
4. **KyPost device key delivery**: HPKE **DHKEM(P-256)** carries users' OpenPGP private keys to devices (web, Android
   Keystore, Linux OpenSSL HPKE, Apple CryptoKit/Secure Enclave). The ciphertext transits the server.
5. **KyIdentity-server**: AD password queue to the DC agent, HPKE **DHKEM(X25519)** carrying plaintext AD passwords to a
   static key (`KyIdentity-server:internal/adpass/adpass.go:25,58-82 @ 6e7df38`, verified). Drop-in fix: stdlib
   `hpke.MLKEM768X25519()`. Keyring device transfer and cross-origin handoff (PRs #295/#296, merged) use **P-256 ECDH**
   + HKDF + AES-256-GCM; device transfer is mitigated: the HKDF salt is a 256-bit approval secret that never reaches the server, so a
   recorded transfer cannot be opened by breaking P-256 alone. The handoff uses a zero salt (sealed key in the URL fragment).
6. **Web Push RFC 8291** everywhere (KyIdentity→KyAuth approvals, KyPost, KyMessages-Native): **P-256 ECDH + AES-128-GCM**;
   no PQ variant of RFC 8291 exists (unverified that none is in draft).
7. **KyAuth-android** vault-key KEK: RSA-2048-OAEP in AndroidKeyStore (on-device only; low exposure, never transmitted).
8. Transport legs that stay classical: SMTP/MX/IMAP peers (KyPost), Synapse federation, CNPG PostgreSQL TLS
   (P-256 group default), LDAPS to AD, KyVault-backend rustls with the **ring** provider (no ML-KEM), native mobile TLS
   (iOS hybrid only on iOS 26+, Android Conscrypt unverified, Linux needs OpenSSL ≥ 3.5).

**Signatures (forgery-only), the PQ-signature backlog.** OIDC/JWT RS256 RSA-2048 in KyIdentity (single key, never
rotated, unencrypted 0600 file) and verifiers that accept RS256 only (`ky-primitives:oidcverify`), KyVault RS256, MAS
RSA-2048/P-256, Synapse Ed25519 federation keys, WebAuthn ES256 only (no PQ COSE alg in authenticators), KyAuth device
keys ECDSA P-256 (StrongBox/TEE/Secure Enclave, hardware cannot do ML-DSA today), VAPID/APNs ES256, FCM RS256, DKIM
RSA-2048 (no ed25519), Ed25519 TLS pins and KyYard agent identity, internal broker CA Ed25519 (kyguard), DNSSEC
validation (KyDNS validates only, no signing), release signing (Sigstore attestations in 13 repos; Flatpak GPG RSA-4096
never-expiring; apksigner; Apple codesign). Long-lived trust anchors (release keys, CA roots, DKIM) are the ones that
matter first.

**Symmetric at rest.** AES-256-GCM with 32-byte keys nearly everywhere (KyDrive, KyRecovery, KyPulse, KyYard,
KyMessages-Native, KyPost, KyIdentity secrets, KyAuth vaults); KyVault items AES-256-CBC-HMAC or XChaCha20-Poly1305.
128-bit review items: HMAC secret floors of 16 bytes (syncauth, session/PoW), TOTP HMAC-SHA1 (RFC 6238), KyNotes
128-bit recovery code (PBKDF2), AES-128 in RFC 8291 and SRTP, LiveKit/MatrixRTC 16-byte media keys.

**Not found.** No WireGuard plans or config in any repo (only a test comment, `KyDNS-server:internal/adminapi/dhcp_test.go:383`),
no Rosenpass anywhere; no Himmelblau/XCreds HPKE queue in KyIdentity (the only HPKE queue is the AD password queue);
no SAML; no cert-manager/ingress/mesh/sealed-secrets in the private infra repo (stale repo); no MTA-STS/DANE/ARC in KyPost;
no `KY_CELLS` in KyMessage-Server; kydrive step K (per-org keys) has **no PR and no pushed branch** (local WIP only).

**OpenSSF docs.** The six the workstation docs (copied to ``) were cross-checked per repo; each part's
notes list stale claims. In-repo equivalents exist as `docs/STRONG-CRYPTO.md` in most server repos, KyQuickStart-AI
`docs/STRONG-SSH.md`/`STRONG-KUBERNETES-TLS.md`, KyAuth-iOS `docs/native-tls-evidence.md`, kyguard-server `docs/SPEC.md`
(identical to KYGUARD_PAM_DESIGN_SPEC.md); there is no in-repo copy of the OPENSSF_* reviews themselves
(see the workstation OPENSSF_* docs).

The table below is the union of eight per-area sweeps, in this order: shared libraries; KyIdentity; KyAuth and KyVault;
KyMessages; KyDrive, KyNotes and KyRecovery; KyGuard, KyDNS, KyCalendar, KyPulse, KyYard and go-webdav; installer and
infra; KyPost (non-OpenPGP). Release-signing and deployment keys for all repos are in §2 under the KyPost part ("release
signing and deployment keys").

## 1. Inventory (one row per crypto use)

| app/repo | use | location (file:line) | algorithm today | who holds the key | quantum exposure | notes |
|---|---|---|---|---|---|---|
| ky-primitives | Suite recovery keypair (KEM) | `ky-primitives:recoverykey/recoverykey.go:42 @ 871828c` | X-Wing = HPKE KEM `MLKEM768-X25519`, ID 0x647a, from Go stdlib `crypto/hpke` (`hpke.MLKEM768X25519()`) | Private key: a 32-byte seed, split into Shamir custodian shares (`recoverykey/shares.go:11-16`); it exists only during the ceremony and during a restore. Public key: every product | PQ-hybrid already | Public key is 1216 raw bytes (ML-KEM-768 ek 1184 + X25519 32) (`recoverykey.go:27`). Encapsulation is 1120 bytes (`:29`). Private key is the 32-byte seed (`:25`, `:82`). Key ID is hex SHA-256 of the public key bytes (`:136-143`). Test vector from draft-ietf-hpke-pq, KEM 0x647a (`recoverykey/testdata/xwing-vector.json`). Not CIRCL, not filippo.io/hpke: the only imports are `crypto/hpke` and `crypto/sha256` (`recoverykey.go:14-21`). X-Wing has been in every tag since v0.5.0 and in every pinned consumer commit (see section 2) |
| ky-primitives | Capsule (backup) sealing, kycap/3 | `ky-primitives:capsule/hpke.go:15-17`, `capsule/seal.go:60,104`, `capsule/container.go:27,131,137 @ 871828c` | HPKE base mode (`hpke.NewSender`/`NewRecipient`, no PSK, no auth). KEM X-Wing 0x647a, KDF HKDF-SHA256 0x0001, AEAD AES-256-GCM 0x0002. `info` = `"kycap/3"`. AAD = exact manifest JSON bytes | Sender: any product holding the public key. Opener: whoever recombines the seed | PQ-hybrid already | Nothing is wrapped. The whole payload (files plus file list, at most 256 MiB plaintext) is sealed directly in one HPKE context. No DEK, no key wrap. Encapsulated key is std-base64 in manifest `encapsulated_key` (`capsule/manifest.go:55-57`). Ciphertext is std-base64 (`capsule/encoding.go:14-24`). No sender authentication: "Authenticity comes from the channel" (`seal.go:35-37`). No recipient forward secrecy (RFC 9180 §9.1.1) |
| ky-primitives | Capsule AEAD (symmetric part) | `ky-primitives:capsule/hpke.go:16 @ 871828c` | AES-256-GCM, inside HPKE | Ephemeral HPKE key schedule | symmetric, PQ-safe at 256-bit | |
| ky-primitives | Custodian shares | `ky-primitives:shamir/shamir.go:10,150,188 @ 871828c` | Shamir over GF(2^8), poly 0x11b, coefficients from crypto/rand, 2-byte SHA-256 card checksum | Custodians | n/a | Information-theoretic |
| ky-primitives | Product settings-value sealer (KyRecovery bearer token) | `ky-primitives:recoveryclient/sealer.go:27-55 @ 871828c` | HKDF-SHA256(deployment key, label) → AES-256-GCM, random 12-byte nonce | The product's deployment key (min 32 bytes) | symmetric, PQ-safe at 256-bit | Used by ky-server-base and the private dashboard repo (rows below) |
| ky-primitives | KyRecovery client HTTPS (pair, deposit) | `ky-primitives:recoveryclient/client.go:62,110,300 @ 871828c` | Go `http.Transport` with a custom DialContext and no TLSClientConfig, so Go defaults apply: X25519MLKEM768 offered first when CurvePreferences is nil (Go ≥1.24, https://go.dev/doc/go1.24#crypto-tls). HTTPS is mandatory | KyRecovery server cert | PQ-hybrid already | Key exchange only, and only if the peer supports it. Certificate auth is in the next row. Bearer token in the `Authorization` header |
| ky-primitives | TLS certificate auth for every outbound Go client (recovery, JWKS, SCIM, S3, suitedir) | `ky-primitives` has no `tls.Config` anywhere (grep `tls\.\|CurvePreferences\|MinVersion` on non-test .go files: none) | Go default verifier. With `GODEBUG=fips140=on` (docs/STRONG-CRYPTO.md:24-43): RSA ≥2048, P-256/384/521, Ed25519 | Peer CAs | forgery-only (signatures) | Nothing overrides CurvePreferences. Local Go 1.27.3 `crypto/tls/defaults_fips140.go:35-43` lists X25519MLKEM768 as allowed under fips140. For Go 1.26 this is unverified |
| ky-primitives | Recovery-key pin | `ky-primitives:recoveryclient/pin.go:26,60-74 @ 871828c` | SHA-256 key ID compare, `recovery.pub` via keyfile | Product data dir and settings row | n/a | |
| ky-primitives | OIDC ID/logout token verification (`oidcverify`) | `ky-primitives:oidcverify/oidcverify.go:169,193-194,445,468 @ 871828c` | RS256 only (`rsa.VerifyPKCS1v15` SHA-256). JWKS keys filtered to kty=RSA, alg RS256 or empty, use sig or empty. Modulus ≥2048, e ≥3 | KyIdentity/KySignOn signing key | forgery-only (signatures) | No EC/EdDSA/ML-DSA path. JWKS must be HTTPS (`:376-399`). Logout tokens need typ `logout+jwt` (`logout.go:36-42`). Imported by KyPost-Server, KyNotes-server, KyCalendar |
| ky-primitives | Password hashing | `ky-primitives:password/password.go:29,51-58,333,370-374 @ 871828c` | Argon2id (x/crypto/argon2 v0.59.0): m=64 MiB, t=3, p=4, 16-byte salt, 32-byte key, PHC string | Server DB | n/a | Bounds: m 8–256 MiB, t 1–10, p 1–16 (`:64-69`) |
| ky-primitives | Login-secret derivation (client-side KDF mirror) | `ky-primitives:derive/derive.go:142-149,182,186 @ 871828c` | PBKDF2-HMAC-SHA256 (100k–12M iterations, 16–64 byte salt) → HKDF-SHA256 per-product label, 32 bytes | User password | n/a | Stdlib `crypto/pbkdf2` and `crypto/hkdf`. Used by KyNotes-server |
| ky-primitives | Synthetic per-user salt | `ky-primitives:derive/derive.go:205-224 @ 871828c` | HMAC-SHA256, key ≥32 bytes, truncated to 16 bytes | Server | symmetric, PQ-safe at 256-bit | Anti-enumeration |
| ky-primitives | Audit hash chain | `ky-primitives:auditchain/auditchain.go:37,281`, `verify_record.go:32 @ 871828c` | HMAC-SHA256 chain, key ≥32 bytes | Product audit key (keyfile) | symmetric, PQ-safe at 256-bit | `cmd/kyauditverify/main.go:57` verifies offline. Used by KyPulse, kyguard, KyRecovery |
| ky-primitives | Directory-sync webhook auth (`syncauth`) | `ky-primitives:syncauth/syncauth.go:11-13,48,115,188 @ 871828c` | HMAC-SHA256 over timestamp, type, id and SHA-256(body). Header `X-KySignOn-Signature: v1=…`. Replay window | Shared sync secret, min 16 bytes; KySignOn mints 32 (`:47`) | symmetric, 128-bit: Grover → ~64-bit, review | The 16-byte floor is what earns "review". 32-byte secrets as minted are PQ-safe |
| ky-primitives | TOTP | `ky-primitives:totp/totp.go:23,36-42,111-117 @ 871828c` | RFC 6238 HMAC-SHA1, 6 digits, 30 s, ±1 step. Generated secret 20 bytes, floor 16 | User authenticator plus server DB (caller stores) | symmetric, 128-bit: Grover → ~64-bit, review | Floor is 128-bit, generated is 160-bit. An online 6-digit code is the real bound. HMAC-SHA1 PRF is not collision-dependent |
| ky-primitives | Recovery codes | `ky-primitives:recoverycode/recoverycode.go:25-31,43,114 @ 871828c` | 12 symbols × 5 bits = 60 bits, crypto/rand, constant-time match. Hashing is left to the caller | Server | n/a | Callers: the private dashboard repo stores bare SHA-256 (row below) |
| ky-primitives | Key/secret file storage | `ky-primitives:keyfile/keyfile.go:38,148-152,274,313 @ 871828c` | crypto/rand generation. File must be 0600 and owner-only. Min 16 bytes | Product host | n/a | Holds AES keys, audit keys, pairing secrets |
| ky-primitives | S3 request signing (root `s3`) | `ky-primitives:s3/sign.go:13,41,44 @ 871828c` | AWS SigV4 HMAC-SHA256. PUT uses UNSIGNED-PAYLOAD under TLS | S3 secret key (provider) | symmetric, PQ-safe at 256-bit | Transport uses Go default TLS (PQ-hybrid when the peer supports it). Key length is provider-defined, unverified |
| ky-primitives/offsite | Offsite S3 | `ky-primitives:offsite/s3.go:19,52,152,161 @ 871828c` | aws-sdk-go-v2 v1.48.0 SigV4 signer. HTTPS virtual-host URL | Operator S3 creds | symmetric, PQ-safe at 256-bit | Separate module, `offsite/go.mod` |
| ky-primitives/offsite | SFTP transport key exchange | `ky-primitives:offsite/sftp.go:68-75 @ 871828c` | x/crypto/ssh v0.59.0 `SupportedAlgorithms()` for KEX, ciphers, MACs and host keys. Includes `mlkem768x25519-sha256` (x/crypto v0.59.0 `ssh/common.go:62,87`, read from the local module cache) | SFTP server | PQ-hybrid already | Only if the server offers mlkem768x25519. Otherwise classical curve25519/ECDH: HNDL for transport. Payloads are already X-Wing capsules |
| ky-primitives/offsite | SFTP host-key pin and client auth | `ky-primitives:offsite/sftp.go:35-60,78-84,115-145 @ 871828c` | Host key pinned by SHA-256 fingerprint. Host/CA/client keys: RSA ≥2048 (client signs with rsa-sha2-512/256 only), ECDSA ≥224-bit, Ed25519 | Operator (client key), SFTP server (host key) | forgery-only (signatures) | |
| ky-primitives/offsite | SMB target | `ky-primitives:offsite/smb.go:88-89 @ 871828c` | go-smb2 (cloudsoda pseudo-version 2026-11-05), NTLMv2 auth, message signing required. NTLM internals (MD4/HMAC-MD5/RC4) per OpenSSF review, not re-checked | Operator password | n/a | No transport-confidentiality guarantee. A guest session can bypass signing (`offsite/README.md:75-80`). STRONG-CRYPTO.md says not to configure smb:// in the strong profile |
| ky-primitives | Strong-crypto CI profile | `ky-primitives:.github/workflows/ci.yml:45,62`, `crypto_profile_test.go:30-60 @ 871828c` | Tests run with `GODEBUG=fips140=on` (TLS filter) | n/a | n/a | Process policy, not a code-level tls.Config |
| ky-primitives | Release integrity | `ky-primitives:docs/VERIFYING-RELEASES.md:5-27 @ 871828c` | Git tags only, not GPG-signed. Relies on sum.golang.org plus GitHub-signed merge commits | Go checksum DB, GitHub | forgery-only (signatures) | sumdb note-signature algorithm unverified here. Whether the repo is reachable by the public proxy and sumdb is unverified |
| ky-primitives | OpenSSF Scorecard results publish | `ky-primitives:.github/workflows/scorecard.yml:23 @ 871828c` | `id-token: write` (Sigstore keyless via scorecard-action, unverified) | GitHub OIDC / Fulcio | forgery-only (signatures) | |
| ky-server-base | Inbound HTTP server | `ky-server-base:cmd/server/main.go:215-228 @ eceb24e`; `deploy/replicas/haproxy.cfg:37` | Plain HTTP `ListenAndServe`. No tls.Config in repo. TLS terminates at the operator proxy | Operator proxy | n/a | `docker-compose.strong-crypto.yml:12-13` binds 127.0.0.1 only. Proxy TLS groups are out of repo: unverified |
| ky-server-base | Outbound TLS (OIDC discovery, JWKS, KyRecovery) | `ky-server-base:internal/sso/oauth.go:43,58-73,131-145 @ eceb24e` | `http.DefaultClient`/DefaultTransport, so Go defaults (X25519MLKEM768 offered). Under fips140, HTTPS is required and redirects are refused | IdP / KyRecovery certs | PQ-hybrid already | Key exchange only, when the peer supports it. Cert chain auth is forgery-only, same as the ky-primitives row |
| ky-server-base | OIDC ID-token and back-channel logout verification | `ky-server-base:internal/sso/oauth.go:73`, `internal/sso/backchannel.go:24-50`, `internal/sso/jwks_strength.go:46-62 @ eceb24e` | coreos/go-oidc v3.21.0 + go-jose v4.1.9. `oidc.Config{ClientID}` sets no SupportedSigningAlgs, so it accepts the provider's discovered `id_token_signing_alg_values_supported` ∩ {RS256/384/512, ES256/384/512, PS256/384/512, EdDSA}, and RS256 if discovery lists none (go-oidc v3.21.0 `oidc/oidc.go:180-191`, `oidc/verify.go:85-88,137-143,300-303`, local mod cache). JWKS RSA moduli must be ≥2048 (`jwks_strength.go:60`) | KyIdentity/KySignOn or generic OIDC IdP | forgery-only (signatures) | Does not use ky-primitives `oidcverify`. Nonce checked (`oauth.go:112`). PKCE S256 (`internal/crypto/crypto.go:109-118`) |
| ky-server-base | SAML | `ky-server-base:internal/sso/saml.go:14-44`, `internal/api/server.go:314 @ eceb24e` | SP metadata XML only. No assertion/signature verification code found | n/a | n/a | `/saml/acs` is advertised (`server.go:156`) but has no handler (grep). No XML-DSig |
| ky-server-base | Session cookie | `ky-server-base:internal/auth/session.go:61-93 @ eceb24e` | 32 random bytes (hex). DB stores SHA-256. HttpOnly, SameSite=Lax, `__Host-` prefix on https | Server DB (hash) | n/a | Bearer header is also accepted (`:115-119`) |
| ky-server-base | CSRF | `ky-server-base:internal/auth/session.go:95-106,160-167`, `internal/api/server.go:405 @ eceb24e` | Double-submit cookie, 24 random bytes, constant-time compare | Browser | n/a | |
| ky-server-base | PoW captcha challenge signature | `ky-server-base:internal/auth/pow.go:71,134 @ eceb24e`; `internal/config/config.go:154-163` | HMAC-SHA256 keyed by `KY_SESSION_SECRET` (string bytes, min 16; dev default 32 random hex) | Server env | symmetric, 128-bit: Grover → ~64-bit, review | At the 16-byte floor. Short-lived challenges |
| ky-server-base | Deployment encryption key (at rest) | `ky-server-base:internal/config/config.go:56,172-177 @ eceb24e` | 32-byte key (`KY_ENCRYPTION_KEY` or `data/encryption.key` via keyfile) | Server host | symmetric, PQ-safe at 256-bit | Copied into every backup capsule as hex (`internal/backup/payload.go:97-102`), so its offsite protection is X-Wing |
| ky-server-base | AES-256-GCM helpers | `ky-server-base:internal/crypto/crypto.go:27-65 @ eceb24e` | AES-256-GCM, 12-byte random nonce, exact 32-byte key | Deployment key | symmetric, PQ-safe at 256-bit | No non-test caller of `EncryptAESGCM`/`DecryptAESGCM` in ky-server-base (grep). `totp_secret_enc` column remains (`internal/store/migrations/migrations.go:34`); docs say local TOTP is unused |
| ky-server-base | KyRecovery token sealing | `ky-server-base:internal/backup/settings.go:79 @ eceb24e` | ky-primitives `NewAESGCMSealer` (HKDF-SHA256 → AES-256-GCM) | Deployment key | symmetric, PQ-safe at 256-bit | |
| ky-server-base | Backups | `ky-server-base:internal/backup/payload.go:15-16`, `internal/api/backup_handlers.go:15-16 @ eceb24e` | ky-primitives capsule kycap/3 (X-Wing/HKDF-SHA256/AES-256-GCM) at pseudo-version 9f4bc5875e04 | Custodians | PQ-hybrid already | |
| ky-server-base | Replica config fingerprint | `ky-server-base:internal/config/replica.go:61-84 @ eceb24e` | HMAC-SHA256 keyed by the 32-byte encryption key. `hmac.Equal` compare | Server | symmetric, PQ-safe at 256-bit | |
| ky-server-base | Password hashing | `ky-server-base:cmd/server/main.go:166`, `internal/api/auth_handlers.go:111-113 @ eceb24e` | ky-primitives Argon2id | DB | n/a | |
| ky-server-base | SCIM bearer token | `ky-server-base:internal/scim/handler.go:69,79`, `internal/config/config.go:265 @ eceb24e` | Static bearer (default 24 random bytes hex), constant-time compare | Server env and IdP | n/a | |
| ky-server-base | PostgreSQL connection | `ky-server-base:internal/config/config.go:150 @ eceb24e` | Default DSN `sslmode=disable` | Operator | n/a | No DB TLS by default. Unverified what operators set |
| ky-server-base | Container image provenance | `ky-server-base:.github/workflows/ci.yml:405-406,434,445,489 @ eceb24e` | `actions/attest-build-provenance` v4.2.2 (Sigstore keyless; ECDSA P-256 Fulcio cert per Sigstore, unverified here), verified with `gh attestation verify` | GitHub OIDC / Fulcio / Rekor | forgery-only (signatures) | No cosign key, no GPG |
| ky-ui | none | `ky-ui` grep for crypto.subtle/getRandomValues/hmac/jwt/jose/argon/cosign/attest/gpg (non-lock, non-review): only base64 PNG false-positives in `src/appmarks.js` and the word "provenance" in `AGENTS.md:60` @ 1b0e466 | none | n/a | n/a | `src/update.js:43` fetches same-origin HTML with `redirect: 'manual'`. No integrity hashing. Scorecard `id-token: write` (`.github/workflows/scorecard.yml:23`) is the only signing-adjacent item |
| .github (org) | none | `gh api repos/Busnes-app/.github/git/trees/HEAD?recursive=1` @ b2ee038: only `.github/FUNDING.yml`, `.github/dependabot.yml`, `AGENTS.md`, `CONTRIBUTING.md`, `FUNDING.yml`, `SECURITY.md`, `profile/README.md` | none | n/a | n/a | No workflows, so no reusable signing/cosign/attestation/GPG/release workflows at org level. SECURITY.md has no PGP key |
| KyIdentity-server | OIDC id_token / access_token / logout_token signing | internal/crypto/crypto.go:270-305, :380; internal/oauth/oauth.go:690, :719; internal/oauth/backchannel.go:42; internal/oauth/device_assertion.go:369, :404 | RS256 (RSASSA-PKCS1-v1_5 SHA-256), RSA-2048 generated; loads PKCS#1/PKCS#8 >=2048 | Server: PEM file `data/jwt_rs256.key` (`KYIDENTITY_RSA_KEY_PATH`, config.go:198), mode 0600 via CreateKeyFile (keyfile.go:12-41), **not encrypted at rest** | forgery-only (signatures) | No rotation: one key, one `kid` = hex(SHA-256(SPKI))[:8] (crypto.go:328-329). The key is copied into backup capsules (backup/payload.go:25, :186-194) |
| KyIdentity-server | JWT verification (own access tokens, logout id_token_hint) | internal/crypto/crypto.go:407; internal/oauth/oauth.go:748, :770, :874 | RS256 only (`jwt.WithValidMethods{"RS256"}`) | Server public key | forgery-only (signatures) | `token_use` and `iss` are enforced |
| KyIdentity-server | JWKS endpoint / discovery | internal/api/server.go:154; internal/crypto/crypto.go:354-369; internal/oauth/oauth.go:113, :116 | `GET /.well-known/jwks.json`, single RSA JWK `alg=RS256`; `id_token_signing_alg_values_supported=["RS256"]` | Server | forgery-only (signatures) | No ES256/EdDSA/ML-DSA alternative is advertised |
| KyIdentity-server | Access token format | internal/oauth/oauth.go:22, :690 | RS256 JWT, TTL 15 min | Server | forgery-only (signatures) | Revocation is checked via `/oauth/userinfo` |
| KyIdentity-server | Refresh tokens, auth codes, device codes, session tokens, account (activation/reset) tokens, step-up grants, platform/SCIM/forward tokens | internal/oauth/oauth.go:281-291, :457-461, :623-649; internal/oauth/device_grant.go:117-127; internal/api/auth_handlers.go:323-329; internal/store/onboarding.go:51, :68; internal/api/stepup.go:30; internal/store/platform_tokens.go:84; internal/store/scim_inbound.go:222; internal/api/forward_handlers.go:99 | Opaque 32 random bytes (hex); stored as SHA-256 | Server DB (hash only) | symmetric, PQ-safe at 256-bit | Single-use refresh rotation with family reuse detection |
| KyIdentity-server | OAuth client authentication | internal/oauth/oauth.go:118, :324-328 | `client_secret_post`, `client_secret_basic`, `none` (PKCE S256). Secret stored as SHA-256, compared in constant time | Server DB (hash) and the RP | n/a | **No `client_secret_jwt` / `private_key_jwt`**: neither is advertised or implemented |
| KyIdentity-server | KyAuth device sign-on (RFC 7523 jwt-bearer) | internal/oauth/device_assertion.go:120-150, :214 | ES256 JWS; header pinned to exactly `alg,typ,kid`; optional `cnf.spki#S256` | KyAuth app holds the P-256 private key; server holds the SPKI | forgery-only (signatures) | `iss=device:<kid>`; refused for workstation apps |
| KyIdentity-server | KyAuth push approve/deny signature | internal/mfa/mfa.go:582-600, :700-729; internal/crypto/crypto.go:250-261 | ECDSA P-256 / SHA-256, ASN.1 DER; message `kyidentity-push-v2\|origin\|user\|device\|challenge\|purpose\|...` | KyAuth device holds the private key; server holds the public key (SPKI, parsed at mfa.go:317) | forgery-only (signatures) | The signature is the only authentication on that endpoint |
| KyIdentity-server | KyAuth pairing proof | internal/mfa/pairing_proof.go:21-45; internal/mfa/mfa.go:249 | HMAC-SHA-256, K = HMAC(token, "kyidentity-pair-key/1"); K sealed in DB | Server (sealed) and KyAuth (from QR token) | symmetric, PQ-safe at 256-bit | Pairing token 24 random bytes (mfa.go:237); PIN is SHA-256 of a 6-digit value (mfa.go:242, :259) |
| KyIdentity-server | Push payload encryption to device (FCM/APNs relay path and ubuntupush) | internal/mfa/push_relay.go:93-101; internal/mfa/push_ubuntupush.go:119-180 | RFC 8291 Web Push: ephemeral P-256 ECDH + HKDF-SHA-256 + **AES-128-GCM** (`aes128gcm`), own implementation | Device holds the P-256 `p256dh` private key and auth secret; the server makes a per-message ephemeral key | HNDL (confidentiality) | Also "symmetric, 128-bit: Grover → ~64-bit, review" for the CEK. Payload carries the challenge and username, padded |
| KyIdentity-server | Push payload encryption (UnifiedPush) | internal/mfa/push_unifiedpush.go:61-76 | RFC 8291 via webpush-go v1.4.0 (P-256 ECDH, AES-128-GCM) | Device | HNDL (confidentiality) | AES-128 CEK, same note as above |
| KyIdentity-server | VAPID (UnifiedPush sender auth) | internal/mfa/push_unifiedpush.go:98-139 | ES256 (P-256) VAPID JWT | Server: file `KYIDENTITY_VAPID_KEY_PATH` / data dir, mode 0600, not encrypted at rest | forgery-only (signatures) | Included in backup capsules (payload.go:47, :226) |
| KyIdentity-server | Server → push relay auth | internal/mfa/push_relay.go:126; push-relay-shared/push-relay-common.ts:233, :286-294 | Bearer relay key (32 random bytes hex); relay stores SHA-256 | Server DB (sealed, `SealRelayKey`) and relay | symmetric, PQ-safe at 256-bit | Relay URLs `https://fcm.relay.kyauth.busnes.app`, `https://apn.relay.kyauth.busnes.app` (config.go:171-172) |
| KyIdentity-server (workers/fcn) | FCM OAuth service-account JWT | workers/fcn/src/fcm.ts:43-82 | RS256 (RSASSA-PKCS1-v1_5), >=2048-bit modulus checked | Cloudflare Worker secret `FCM_PRIVATE_KEY` (wrangler.toml.example:89-91) | forgery-only (signatures) | Google-issued key |
| KyIdentity-server (workers/apns) | APNs provider token | workers/apns/src/apns.ts:42-80 | ES256 (P-256) JWT | Worker secret `APNS_AUTH_KEY` (.p8) (wrangler.toml.example:82-83) | forgery-only (signatures) | Apple-issued key |
| KyIdentity-server | WebAuthn / passkeys (login factor) | internal/webauthn/webauthn.go:39-40, :187-225 | go-webauthn v0.18.2; `pubKeyCredParams` = **[-7] (ES256) only**; attestation `none` | Authenticator holds the private key; server stores P-256 SPKI | forgery-only (signatures) | COSEAlgorithmIdentifier list: `-7`. No -8/-257/ML-DSA |
| KyIdentity-server | Keyring PRF passkey | web/src/keyringPRF.ts:3-5, :34-36 | Separate passkey, `pubKeyCredParams [{alg:-7}]`; PRF eval at SHA-256("ky-keyring/1:webauthn-prf") | Authenticator | forgery-only (signatures) | The PRF output (32 B) is symmetric wrapping input (see the wrapper row) |
| KyIdentity-server | Zero-knowledge keyring: SRK / recovery / device / PRF wrappers | web/src/keyringCrypto.ts:14, :52-73, :84-90; web/src/keyringDevice.ts:44-50; docs/KEYRING.md | HKDF-SHA-256 (32 zero-byte salt, info = JSON AAD) → AES-256-GCM; envelope `nonce[12]\|ct[32]\|tag[16]`. SRK, device secret and recovery key are each 32 random bytes | **Client-held**: SRK, device secret (non-extractable HKDF CryptoKey in IndexedDB `kyidentity-keyring`), recovery key (`KYR1-` 64 hex, printed Emergency Kit), PRF output. **Server-held**: ciphertext only | symmetric, PQ-safe at 256-bit | Wrapping is AEAD (AES-256-GCM), not AES-KW. Device capability: 32 random bytes; server stores SHA-256 `device_hash` (keyringCrypto.ts:104-108) |
| KyIdentity-server | Keyring per-app subkeys | web/src/keyringCrypto.ts:94-102 | 32-byte random subkey per (client_id, key_version), sealed with HKDF-SHA-256(SRK) → AES-256-GCM | Client-held; the server stores the envelope (`keyring_app_keys`) | symmetric, PQ-safe at 256-bit | `GET /api/keyring/app` returns the envelope only to a bearer token for the same client (docs/KEYRING.md) |
| KyIdentity-server | Keyring device-to-device transfer | web/src/keyringCrypto.ts:119-177; server point validation internal/api/keyring.go:137-140, :335, :360 | Ephemeral **ECDH P-256** both sides; request MAC HMAC-SHA-256 keyed by a 256-bit approval secret; HKDF-SHA-256 (salt = approval secret, info = transfer AAD) → AES-256-GCM sealing the SRK | Client-held: ephemeral private keys and the `KYT1.<id>.<secret>` code (out-of-band). Server relays public points and the sealed blob | HNDL (confidentiality) | Mitigated: the HKDF salt is a 256-bit secret that never reaches the server, so the server-side ciphertext alone cannot be opened even if P-256 falls. The secret's channel is user-chosen |
| KyIdentity-server | Keyring cross-origin OIDC key handoff (PR #296) | web/src/keyringCrypto.ts:193-238; internal/api/keyring_handoff.go:61-62; internal/api/oauth_handlers.go:148-153 | App's ephemeral P-256 `keyring_pk` (query param) + KyIdentity page's ephemeral P-256 → ECDH → HKDF-SHA-256 (**zero salt**) → AES-256-GCM over the 32-byte app subkey; AAD binds code, redirect_uri, both keys | Client-held only; the sealed subkey travels in the URL fragment `#kh=` (never sent to a server) | HNDL (confidentiality) | Classical P-256 only, with no secret salt. Exposure depends on someone capturing the fragment (browser history, app JS). Not on the wire |
| KyIdentity-server | Row secrets at rest (TOTP, connector tokens, mail settings, relay keys, HR writeback, pairing proof) | internal/crypto/crypto.go:109-113, :136-200; internal/store/sealed.go:16-40 | AES-256-GCM `v2:` envelope; key = HMAC-SHA-256(encryption.key, "kyidentity:seal:"+purpose); AAD = purpose\|row | Server: `encryption.key` (32 B, file or `KYIDENTITY_ENCRYPTION_KEY[_FILE]`, config.go:24, :242, :600-630) | symmetric, PQ-safe at 256-bit | Legacy un-bound AES-256-GCM still readable for migration (crypto.go:121-125) |
| KyIdentity-server | KyRecovery pairing token / recovery pubkey pin at rest | internal/backup/adapter.go:190-198, :285, :327 | AES-256-GCM (unbound legacy format) under DeriveKey(encryption.key, label) | Server | symmetric, PQ-safe at 256-bit | Label fixed forever (adapter.go:72-74) |
| KyIdentity-server | Backup capsules | internal/backup/adapter.go; ky-primitives:recoverykey/recoverykey.go:5, :42 @ 9f4bc58; ky-primitives:capsule/hpke.go:15-16 @ 9f4bc58 | HPKE with **X-Wing / MLKEM768-X25519** (`hpke.MLKEM768X25519()`), HKDF-SHA-256, AES-256-GCM, `kycap/3` | Recipient private key is split into custodian shares (Shamir); the server holds only the public key pin | PQ-hybrid already | The server never decrypts (`TestNothingInTheServerDecrypts`). Capsules contain the RSA, VAPID, secret and encryption keys |
| KyIdentity-server | AD password queue to DC agent | internal/adpass/adpass.go:25-83; cmd/kyidentity-dc-agent/main.go:36, :151 | HPKE RFC 9180 `DHKEM(X25519, HKDF-SHA256)`, HKDF-SHA256, AES-256-GCM via stdlib `crypto/hpke`, single-shot; info binds connector\|user\|seq | DC agent holds the X25519 private key (file 0600); the server holds only the public key | HNDL (confidentiality) | Carries plaintext AD passwords. Prime PQ candidate: stdlib `hpke.MLKEM768X25519()` is already used by ky-primitives |
| KyIdentity-server | AD queue entry signing | internal/adpass/adpass.go:100-133; internal/store/ad.go:53-71 | Ed25519; seed = DeriveKey(encryption.key, "kyidentity:ad-entry-signing") | Server (derived); the agent pins the `ed25519:` public key | forgery-only (signatures) | The agent verifies before opening |
| KyIdentity-server | AD agent public-key integrity in DB | internal/store/ad.go:58-64 | HMAC-SHA-256 under DeriveKey(encryption.key, "kyidentity:ad-agent-key-mac") | Server | symmetric, PQ-safe at 256-bit | Stops DB writers swapping the agent key |
| KyIdentity-server | Session cookie | internal/api/auth_handlers.go:323-384; internal/api/middleware.go:359 | 32 random bytes hex; stored SHA-256; HttpOnly, SameSite=Lax, Secure on HTTPS | Browser and server (hash) | symmetric, PQ-safe at 256-bit | |
| KyIdentity-server | CSRF token / authorization-browser cookie | internal/api/middleware.go:496-516; internal/api/authorization_interactions.go:28, :47 | Double-submit; token = HMAC-SHA-256(secret.key, SHA-256(session)) | Server `secret.key` (32 B, config.go:237) | symmetric, PQ-safe at 256-bit | |
| KyIdentity-server | Device-grant user code hash | internal/oauth/device_grant.go:58, :83 | HMAC-SHA-256 under DeriveKey(secret.key, "kyidentity:device-user-code") | Server | symmetric, PQ-safe at 256-bit | Device code: SHA-256 of 32 random bytes |
| KyIdentity-server | MFA recovery codes | internal/mfa/mfa.go:185-231 | HMAC-SHA-256 keyed by DeriveKey(encryption.key, "kyidentity:recovery-code") over user\|code | Server | n/a | Codes are 8 alphanumeric chars (~40 bits). Legacy SHA-256 still accepted |
| KyIdentity-server | TOTP | internal/mfa/mfa.go:107-182; ky-primitives:totp/totp.go:23, :36-38 @ 9f4bc58 | RFC 6238 HMAC-SHA1, 6 digits, 30 s, 20-byte secret, ±1 step; counter replay blocked | Server: secret sealed AES-256-GCM (`SealTOTP`) | n/a | HMAC-SHA1 as a PRF; symmetric |
| KyIdentity-server | Password hashing | internal/auth/password.go:23-29, :46-55 | Argon2id m=64 MiB, t=3, p=4, salt 16 B, key 32 B (x/crypto) | Server DB | n/a | Concurrency is capped at 8 |
| KyIdentity-server | Directory sync / webhook / HR / platform-event / recovery-evidence signing | internal/sync/sync.go:594; internal/sync/hr.go:112; internal/sync/platform_events.go:56; internal/api/recovery_evidence.go:56; ky-primitives:syncauth/syncauth.go:9, :115 @ 9f4bc58 | HMAC-SHA-256 over `ky-sync-v1\n` + ts + type + id + SHA-256(body) | Shared secret: server (sealed `SealConnector`) and peer | symmetric, PQ-safe at 256-bit | Generated secrets are 32 random bytes (sync.go:320); a 16-byte minimum is enforced (docs/STRONG-CRYPTO.md) |
| KyIdentity-server | Suite peer shared secret | internal/api/suite_handlers.go:175-177, :204 | HMAC-SHA-256 DeriveKey(encryption.key, "kyidentity:suite-peer:v1:a\|b") | Server, handed to both apps | symmetric, PQ-safe at 256-bit | |
| KyIdentity-server | Replica config fingerprint | internal/config/replica.go:120-140 | HMAC-SHA-256 under encryption.key and its subkey | Server | symmetric, PQ-safe at 256-bit | |
| KyIdentity-server | Android key attestation verification | internal/attest/verify.go:56, :142-151; internal/attest/roots.go; internal/crypto/certificate_keys.go:13-30; config.go:306 | X.509 chain signature checks (Google roots; RSA-2048+/EC-224+/Ed25519 floor) + status list from `https://android.googleapis.com/attestation/status` | Google / device TEE | forgery-only (signatures) | Device keys P-256 |
| KyIdentity-server | Apple App Attest verification | internal/appattest/appattest.go:177-199; internal/appattest/apple_app_attestation_root_ca.pem | X.509 chain to the pinned Apple root (P-384 per Apple; unverified here), leaf P-256 | Apple / Secure Enclave | forgery-only (signatures) | |
| KyIdentity-server | Inbound HTTPS (browser, OIDC RPs, KyAuth) | internal/api/server.go:83-91, :94, :563; docs/STRONG-CRYPTO.md "Configure the independent HTTPS edge" | **Server speaks plain HTTP**; TLS is terminated at an operator proxy (nginx example `TLSv1.2 TLSv1.3`, `DEFAULT@SECLEVEL=2`) | Operator's edge cert | n/a | The repo ships no edge TLS config with `ssl_ecdh_curve`. PQ depends on the operator proxy (unverified) |
| KyIdentity-server | Platform provisioning API listener (multi-tenant) | internal/api/server.go:93-95, :563; internal/config/config.go:144-146 | Plain HTTP on `KYIDENTITY_PLATFORM_LISTEN` (IP:port) | n/a | n/a | Token auth (SHA-256 hashed bearer). No TLS in-process |
| KyIdentity-server | Outbound HTTPS: callbacks, SCIM, logout, UnifiedPush, ubuntupush | internal/netguard/netguard.go:62-71 | `http.Transport` with **no TLSClientConfig** → Go defaults (TLS 1.2+ client, default curves incl. X25519MLKEM768) | System roots | PQ-hybrid already | Only if the peer supports X25519MLKEM768; otherwise classical ECDHE (HNDL). No CurvePreferences override anywhere in the repo |
| KyIdentity-server | Outbound HTTPS: attestation fetch, push relay, platform events, HR | cmd/kyidentity/main.go:1261-1264; internal/mfa/push_relay.go:112, :293; internal/sync/platform_events.go:23 | Default `http.Client` → Go default TLS | System roots | PQ-hybrid already | Same peer-dependence caveat |
| KyIdentity-server | SMTP | internal/mail/mail.go:142 | `tls.Config{MinVersion: TLS12}` implicit TLS or required STARTTLS; no CurvePreferences | System roots | PQ-hybrid already | Peer-dependent (most SMTP servers are classical → HNDL) |
| KyIdentity-server | LDAPS to AD (server-side sync) | internal/sync/ad.go:178 | `tls.Config{RootCAs: operator CA PEM, MinVersion: TLS12}` | Operator CA | HNDL (confidentiality) | Go offers X25519MLKEM768, but AD DCs (Schannel) almost certainly negotiate classical ECDHE (unverified). Carries the bind password |
| KyIdentity-server (dc-agent) | DC agent → KyIdentity HTTPS and → DC LDAPS | cmd/kyidentity-dc-agent/main.go:216-227, :316 | `tls.Config{MinVersion: TLS12}` (+ optional CA file); LDAPS same | System roots / CA file | PQ-hybrid already | To KyIdentity: PQ only if the edge proxy offers it. To the DC: HNDL as above |
| KyIdentity-server | PostgreSQL connection | DSN from `KYIDENTITY_DATABASE_URL` (operator) | pgx v5; sslmode operator-set (CI uses `sslmode=disable`, ci.yml:158) | Operator | n/a | Not configured in-repo (unverified in deployments) |
| KyIdentity-server | Release image signing | .github/workflows/release-image.yml:176-193; docs/VERIFYING-RELEASES.md:10-20 | GitHub `attest-build-provenance` (Sigstore keyless; Fulcio cert, ECDSA P-256 per Sigstore, unverified) + BuildKit SBOM (unsigned) | GitHub OIDC / Sigstore | forgery-only (signatures) | No cosign key |
| KyIdentity-server | Random identifiers / codes | internal/crypto/crypto.go:26-77 | crypto/rand, rejection-sampled | n/a | n/a | |
| KyIdentity-server | Test-only TLS / certs | internal/ldaptest/ldaptest.go:68; scripts/e2e-himmelblau.sh:41-43; scripts/e2e-samba-ad.sh:90-94 | P-256 / RSA-2048 throwaway certs | Test | n/a | Not production |
| KyAuth-android | Device signing key (push approvals, push-token refresh, unpair, sign-on assertion) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/pairing/DeviceSigningKey.kt:52-53,115-139 @ 559e687 | ECDSA P-256 / SHA-256 (`SHA256withECDSA`, `secp256r1`). AndroidKeyStore, StrongBox first, then TEE, then a plain Keystore key. Each use needs auth (`setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)`) | Phone's Keystore (StrongBox/TEE), non-exportable. KyIdentity holds the SPKI | forgery-only (signatures) | Alias `kysignon-device-signing-v1`. Key attestation chain sent at pairing (challenge = SHA-256 of `kyidentity-attest-v1\|`+credential, pairing/AttestationChallenge.kt:16-17) |
| KyAuth-android | Push approve/deny message signed by device key | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/mfa/MfaChallenge.kt:29,44-55 @ 559e687; MainActivity.kt:1488-1497 | ECDSA P-256 over `kyidentity-push-v2\|origin\|userId\|deviceId\|challengeId\|purpose\|expiresAtMs\|approve/deny\|digits` | Device key (above) | forgery-only (signatures) | DER signature, base64. Sent through mfa/MfaResponseClient.kt:29-37 |
| KyAuth-android | Push-token refresh and device revoke signatures | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/pairing/PushRefreshClient.kt:17-27 @ 559e687; pairing/DeviceRevokeClient.kt:22-25 | ECDSA P-256 over `kyidentity-push-token-v2\|...\|sha256(token)\|p256dh\|auth` and the revoke prefix | Device key | forgery-only (signatures) | |
| KyAuth-android | Sign-on JWT assertion (RFC 7523 jwt-bearer) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/signon/DeviceAssertion.kt:46-58 @ 559e687; signon/SignOnActivity.kt:121-133 | JWS ES256 (header `alg: ES256`), DER to r‖s; optional `cnf.spki#S256` binding | Device key | forgery-only (signatures) | 120 s TTL |
| KyAuth-android | QR pairing proof (request/reply MAC) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/pairing/PairingProof.kt:20-46 @ 559e687 | HMAC-SHA256. K = HMAC-SHA256(token, `kyidentity-pair-key/1`). Request and reply MACs; constant-time compare | Token from QR, shared with KyIdentity | symmetric, PQ-safe at 256-bit | No asymmetric key exchange at pairing. Token entropy unverified |
| KyAuth-android | FCM push payload decryption (RFC 8291 Web Push) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/mfa/WebPush.kt:25-35 @ 559e687; mfa/IncomingPush.kt:53 | ECDH P-256 + HKDF-SHA256 (Tink `Hkdf`) + AES-128-GCM (aes128gcm) | Phone generates the P-256 receive key and 16-byte auth (pairing/PushKeys.kt:47-51, PushStore.kt:37-38). KyIdentity holds the public half | HNDL (confidentiality) | The content key is AES-128, but the long-term exposure is the classical ECDH. No forward secrecy for the recipient (the OpenSSF review notes this) |
| KyAuth-android | UnifiedPush payload decryption | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/mfa/KyAuthUnifiedPushService.kt:14-24 @ 559e687 | RFC 8291 inside the `org.unifiedpush.android:connector:3.3.6` library (keys `pubKeySet`) | Connector library on the phone | HNDL (confidentiality) | Connector internals not read (unverified). The app drops messages that did not decrypt |
| KyAuth-android | FCM push keys sealed at rest | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/PushKeyWrap.kt:17-50 @ 559e687; pairing/PushStore.kt:33-38 | AES-256-GCM Keystore key, AAD `kyauth-fcm-push-keys-v1`. Not auth-bound | AndroidKeyStore | symmetric, PQ-safe at 256-bit | |
| KyAuth-android | TOTP vault file | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/totp/TotpVault.kt:19-20,78-79 @ 559e687 | AES-256-GCM, 12-byte nonce, AAD `kyauth-totp-v1`‖version | 32-byte random vault key (security/CredentialCipher.kt:90-94) held wrapped (next two rows) | symmetric, PQ-safe at 256-bit | |
| KyAuth-android | Vault-key KEK (biometric/device-credential unlock) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/VaultKek.kt:26,70-90,106-107 @ 559e687; security/AppLockManager.kt:242 | RSA-2048 OAEP (SHA-256 / MGF1-SHA1), AndroidKeyStore, auth-bound per use | AndroidKeyStore private key. Software public key used to wrap | HNDL (confidentiality) | Local wrapping only. The ciphertext sits in app prefs and never crosses a network. RSA is used so that wrapping needs no prompt. For PQ, the realistic threat is a seized device, not HNDL from traffic |
| KyAuth-android | PIN-derived vault-key wrap | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/CredentialCipher.kt:17,96-101,120-136 @ 559e687; AppLockManager.kt:117-122 | PBKDF2-HMAC-SHA256 150,000 iterations, 16-byte salt, then HMAC-SHA256 pepper (Keystore HMAC key, `setUnlockedDeviceRequired`), then AES-256-GCM | User PIN + Keystore pepper | symmetric, PQ-safe at 256-bit | Password hashing |
| KyAuth-android | PIN verifier | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/CredentialCipher.kt:112-117,153-162 @ 559e687 | PBKDF2-HMAC-SHA256 150k + Keystore HMAC-SHA256 pepper | Keystore pepper `kyauth_pin_pepper` | n/a | Password hashing |
| KyAuth-android | Legacy v0.1 wrap key (migration only) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/CredentialCipher.kt:109-110 @ 559e687; AppLockManager.kt:258-267 | HMAC-SHA256(pepper, salt) used as an AES-256-GCM key | Keystore pepper | symmetric, PQ-safe at 256-bit | One-shot migration path |
| KyAuth-android | TOTP code generation | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/totp/TotpGenerator.kt:13-14,37-40,70-71 @ 559e687 | HMAC-SHA1/256/512 (RFC 6238). Minimum secret 10 bytes (80-bit), warning below 16 | Issuer secret, in the vault | n/a | HMAC key ≥80 bit. Grover is irrelevant to OTP |
| KyAuth-android | TLS to KyIdentity | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/pairing/ServerTls.kt:20-34 @ 559e687; pairing/ServerHttp.kt:44-47 | Platform Conscrypt `SSLContext("TLS")` + platform trust + app floor (leaf/chain RSA ≥2048, EC ≥256). Key-exchange groups are not set | System CAs | HNDL (confidentiality) | No groups configured. Whether Conscrypt on minSdk 31–36 offers X25519MLKEM768 is unverified. No pinning. Release has no network-security-config (cleartext is off by default for targetSdk 36). The debug config allows only loopback cleartext (app/src/debug/res/xml/debug_network_security.xml:1-9) |
| KyAuth-android | Sign-on caller pinning | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/signon/TrustedConsumers.kt:14-21 @ 559e687 | SHA-256 of the caller's signing certificate | n/a | n/a | Digest pin, not crypto key use |
| KyAuth-android | Backup / export | KyAuth-android:app/src/main/AndroidManifest.xml:14-16 @ 559e687; res/xml/backup_rules.xml:2-4; res/xml/data_extraction_rules.xml:3-7 | No backup (`allowBackup=false`, all domains excluded). No export feature found | n/a | n/a | |
| KyAuth-android | Passkey (removed) | KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/RemovedPasskey.kt:11-24 @ 559e687 | Deletes old `kyauth_identity_passkey_*` Keystore aliases | n/a | n/a | No FIDO/passkey today |
| KyAuth-android | APK/AAB release signing | KyAuth-android:app/build.gradle.kts:46-56,112-113 @ 559e687; .github/workflows/release.yml:34-63 | Upload keystore from `KYAUTH_KEYSTORE_BASE64` secret; `apksigner verify`, `jarsigner -verify`. Key algorithm not in the repo (unverified) | Owner (GitHub env secret). Play builds are re-signed by Google Play App Signing | forgery-only (signatures) | |
| KyAuth-android | Release provenance | KyAuth-android:.github/workflows/release.yml:73-88 @ 559e687 | `actions/attest-build-provenance` v4.2.2 (Sigstore, keyless, Fulcio ECDSA P-256 per Sigstore defaults, unverified) + SHA256SUMS | Sigstore / GitHub OIDC | forgery-only (signatures) | |
| KyAuth-android | Crypto libraries | KyAuth-android:app/build.gradle.kts:136-142 @ 559e687 | JCA/AndroidKeyStore/Conscrypt (platform); `com.google.crypto.tink:tink:1.24.0` (HKDF only); `org.unifiedpush.android:connector:3.3.6`; `firebase-messaging:26.0.2`; `androidx.biometric:1.1.0` | n/a | n/a | minSdk 31, targetSdk 36 (build.gradle.kts:38-39) |
| KyAuth-iOS | Device signing key | KyAuth-iOS:KyAuth/Pairing/DeviceSigningKey.swift:33-42,56-64 @ f31cc76 | ECDSA P-256 (`SecureEnclave.P256.Signing`), `.privateKeyUsage`+`.userPresence`, `WhenPasscodeSetThisDeviceOnly` | Secure Enclave (Keychain holds only the wrapped handle). Software P-256 in the simulator only | forgery-only (signatures) | Fails closed without an SE (DeviceKeyError.unavailable) |
| KyAuth-iOS | Push approve/deny, push-token refresh, sign-on assertion | KyAuth-iOS:KyAuth/Mfa/MfaChallenge.swift:25,54 @ f31cc76; KyAuth/Pairing/PushRefreshClient.swift:7,36; KyAuth/SignOn/DeviceAssertion.swift:36,48; KyAuth/App/AppModel.swift:445,505,625 | ECDSA P-256. Same `kyidentity-push-v2` / `kyidentity-push-token-v2` strings as Android; JWS ES256 | Secure Enclave key | forgery-only (signatures) | |
| KyAuth-iOS | App Attest at pairing | KyAuth-iOS:KyAuth/Pairing/AppAttestor.swift:13-28 @ f31cc76; KyAuth/KyAuth_Release.entitlements:8-9 | Apple App Attest (`DCAppAttestService`). clientDataHash = SHA-256(`kyidentity-appattest-v1\|cred\|pubkey`). Apple's attestation is P-256/X.509 (per Apple, unverified here) | Apple SE + Apple CA | forgery-only (signatures) | Optional. Never fails a pairing |
| KyAuth-iOS | QR pairing proof | KyAuth-iOS:KyAuth/Pairing/QrPairing.swift:42-43 @ f31cc76; KyAuth/Pairing/PairingProof.swift:23-41 | HMAC-SHA256 (CryptoKit), same contract as Android | QR token / KyIdentity | symmetric, PQ-safe at 256-bit | |
| KyAuth-iOS | APNs push payload decryption (RFC 8291) | KyAuth-iOS:Shared/PushCrypto.swift:12-13,60-75 @ f31cc76; KyAuthPush/NotificationService.swift:14 | ECDH P-256 (CryptoKit) + HKDF-SHA256 + AES-128-GCM | Phone-generated P-256 key and auth (KyAuth/App/AppModel.swift:347-348), stored in Keychain access group `group.org.kysecurity.authenticator.push` (Shared/Keychain.swift:117-126), `AfterFirstUnlockThisDeviceOnly` (Keychain.swift:27) | HNDL (confidentiality) | The private scalar is a plain Keychain item, not in the SE |
| KyAuth-iOS | TOTP vault | KyAuth-iOS:KyAuth/Totp/TotpVault.swift:17-34,73-83 @ f31cc76; Shared/Keychain.swift:35-47 | AES-256-GCM (CryptoKit), AAD `kyauth-totp-vault-v1`. 256-bit key in a `.userPresence`, `WhenPasscodeSetThisDeviceOnly` Keychain item | Keychain (passcode-bound) | symmetric, PQ-safe at 256-bit | Excluded from backup. No export |
| KyAuth-iOS | PIN verifier | KyAuth-iOS:KyAuth/Security/PinPolicy.swift:106,121-126,158-170 @ f31cc76 | PBKDF2-HMAC-SHA256 310,000 iterations, 16-byte salt (CommonCrypto). Verifier in a protected Keychain item | Keychain | n/a | Password hashing |
| KyAuth-iOS | TOTP codes | KyAuth-iOS:KyAuth/Totp/TotpEntry.swift:65-69,103 @ f31cc76 | HMAC-SHA1/256/512 (CryptoKit). Minimum 10 decoded bytes | Issuer secret | n/a | |
| KyAuth-iOS | TLS to KyIdentity | KyAuth-iOS:KyAuth/Networking/HTTPClient.swift:42-50,91-115 @ f31cc76 | URLSession ephemeral + ATS defaults (no ATS exceptions in KyAuth/Info.plist) + `SecTrustEvaluateWithError` + app floor (every chain cert RSA ≥2048 / EC ≥256). Groups not set | System trust | PQ-hybrid already (iOS 26+ only, unverified) / HNDL (confidentiality) on iOS 17–18 | Deployment target 17.0 (project.pbxproj:411). Apple documents X25519MLKEM768 by default in URLSession on iOS 26 (https://support.apple.com/en-us/122756, unverified). It only helps if KyIdentity's TLS terminator also offers it. No pinning |
| KyAuth-iOS | APNs | KyAuth-iOS:KyAuth/KyAuth_Release.entitlements:6-7 @ f31cc76 | APNs production. Transport is Apple's | Apple | n/a | Payload E2E-sealed by RFC 8291 (row above) |
| KyAuth-iOS | App signing | KyAuth-iOS:KyAuth.xcodeproj/project.pbxproj:400,454 @ f31cc76; .github/workflows/release.yml:27-36,174-177 | Apple automatic signing (team TATYN4X57D). Dev cert .p12 from secret; distribution cert is cloud-managed | Apple / owner | forgery-only (signatures) | Cert key algorithm unverified |
| KyAuth-iOS | Crypto libraries | KyAuth-iOS:Fuzz/Package.resolved @ f31cc76 | App: CryptoKit, Security, CommonCrypto, DeviceCheck (system). Fuzz target only: apple/swift-crypto 5.1.1, swift-asn1 1.7.4 | n/a | n/a | The app has no SPM dependencies |
| KyAuth-Linux | Device signing key | KyAuth-Linux:src/core/crypto.cpp:151-161,179-190 @ c2efea6; src/app/controller.cpp:623,716 | ECDSA P-256 / SHA-256 (OpenSSL 3 EVP), software key | Stored in the scrypt+AES-GCM vault (`pairing.key`) | forgery-only (signatures) | No hardware key store |
| KyAuth-Linux | Push answers / token refresh signatures | KyAuth-Linux:src/core/protocol.cpp:248,261 @ c2efea6; src/app/controller.cpp:562 | ECDSA P-256 over `kyidentity-push-v2` / `kyidentity-push-token-v2` | Vault key | forgery-only (signatures) | No ES256 sign-on assertion in Linux |
| KyAuth-Linux | QR pairing proof | KyAuth-Linux:src/core/protocol.cpp:171-186 @ c2efea6 | HMAC-SHA256 (Qt `QMessageAuthenticationCode`) | QR token | symmetric, PQ-safe at 256-bit | |
| KyAuth-Linux | Push decryption (UnifiedPush D-Bus + Ubuntu Touch/Lomiri push) | KyAuth-Linux:src/core/crypto.cpp:58-71,111-121,205-222 @ c2efea6; src/app/controller.cpp:181-182,527 | RFC 8291: ECDH P-256 + HKDF-SHA256 + AES-128-GCM (OpenSSL) | App-generated `pushKey` + `pushAuth` in the vault | HNDL (confidentiality) | qml/UbuntuPush.qml:2-11 |
| KyAuth-Linux | Vault (all secrets) | KyAuth-Linux:src/core/crypto.h:35-44 @ c2efea6; src/core/vault.cpp:12,94-95,140-144; src/core/crypto.cpp:273-296 | scrypt N=2^17, r=8, p=1, 16-byte salt, then AES-256-GCM, AAD `kyauth-linux-vault-v1` | User passcode | symmetric, PQ-safe at 256-bit | Password hashing (KDF) |
| KyAuth-Linux | TOTP codes | KyAuth-Linux:src/core/totp.cpp:96-102 @ c2efea6; src/core/totp.h:12-13 | HMAC-SHA1/256/512. Minimum 10 bytes | Vault | n/a | |
| KyAuth-Linux | TLS to KyIdentity | KyAuth-Linux:src/app/controller.cpp:785-806 @ c2efea6; src/app/controller.cpp:64-73; src/core/crypto.cpp:232-248; src/app/main.cpp:141-143 | Qt + OpenSSL ≥3.0 (required at runtime). `TlsV1_2OrLater`, `DEFAULT@SECLEVEL=2`, VerifyPeer, anchors filtered by key floor, every peer cert checked on `encrypted` (RSA/DSA/DH ≥2048, EC ≥224, Ed25519/Ed448 allowed), session tickets off. Groups not set | System CAs | HNDL (confidentiality) on OpenSSL <3.5; PQ-hybrid already on OpenSSL ≥3.5 (unverified) | Code sets no groups, so the runtime's OpenSSL default decides. OpenSSL 3.5 puts X25519MLKEM768 in its default keyshares (https://github.com/openssl/openssl/blob/openssl-3.5.0/NEWS.md, unverified). Runtimes: Flatpak `org.kde.Platform` 6.11 (packaging/flatpak/app.busnes.kyauth.yaml:2-3), Ubuntu Touch `ubuntu-touch-24.04-1.x` (clickable.yaml:3). OpenSSL versions of both unverified. EC floor is 224 here vs 256 on Android/iOS |
| KyAuth-Linux | Flatpak repo signing | KyAuth-Linux:packaging/flatpak/gen-signing-key.sh @ c2efea6 (gpg block); .github/workflows/release.yml:161-211 | GPG RSA-4096 sign-only, no expiry | Owner (`FLATPAK_GPG_PRIVATE_KEY` secret) | forgery-only (signatures) | |
| KyAuth-Linux | Release provenance | KyAuth-Linux:.github/workflows/release.yml:154-155 @ c2efea6 | Sigstore keyless attestation | Sigstore / GitHub OIDC | forgery-only (signatures) | |
| KyAuth-Linux | Crypto libraries | KyAuth-Linux:CMakeLists.txt:17-18,48 @ c2efea6 | OpenSSL ≥3.0 (libcrypto EVP), Qt5.15/Qt6 Network + QCryptographicHash | n/a | n/a | |
| KyVault-backend | Login password verifier (server side) | KyVault-backend:src/crypto.rs:9-24 @ c0a86c2a; src/db/models/user.rs:166-170,210; src/config.rs:663 | PBKDF2-HMAC-SHA256 (ring 0.17.14) over the client's masterPasswordHash. Default 600,000 iterations, floor 100k (config.rs:993) | Server DB | n/a | Password hashing. The server never sees the master key |
| KyVault-backend | Session / refresh / invite / misc JWTs | KyVault-backend:src/auth.rs:44,52,70-100,123-131 @ c0a86c2a; src/config.rs:535 | RS256, RSA-2048 generated by openssl (`Rsa::generate(2048)`) into `data/rsa_key.pem`. jsonwebtoken 11.1.0 (rust_crypto) | Server (`rsa_key.pem`) | forgery-only (signatures) | One key for every token type |
| KyVault-backend | Stored vault key material (opaque) | KyVault-backend:src/db/models/user.rs:49-51,63-66 @ c0a86c2a; src/db/models/organization.rs:36-37,52,55; src/db/models/emergency_access.rs:24; src/db/models/auth_request.rs:33-35; src/db/models/send.rs:37; src/db/models/cipher.rs:337 | Stores client EncStrings only: user key wrapped by stretched master key (AES-256-CBC-HMAC), user/org RSA-2048 key pairs (private half wrapped), org keys, reset-password keys, emergency-access keys and auth-request keys wrapped to RSA public keys | Clients. Server holds ciphertext | HNDL (confidentiality) | Anything RSA-wrapped stored or sent today (org-key shares, admin reset, emergency access, login-with-device, trusted-device) can be opened later by a CRQC. See the KyVault-web rows |
| KyVault-backend | Admin page token | KyVault-backend:src/api/admin.rs:235-240 @ c0a86c2a; src/config.rs:1351-1359 | Argon2 PHC verify (argon2 0.6.0), or a plain token | Operator | n/a | Password hashing |
| KyVault-backend | Authenticator 2FA (server-side TOTP) | KyVault-backend:src/api/core/two_factor/authenticator.rs:113,139 @ c0a86c2a | TOTP HMAC-SHA1, 30 s, 6 digits (totp-lite 2.0.1) | Server DB (plaintext secret) | n/a | |
| KyVault-backend | WebAuthn 2FA | KyVault-backend:src/api/core/two_factor/webauthn.rs:41-46 @ c0a86c2a | webauthn-rs 0.5.5 with default COSE algs (ES256/RS256 etc. per crate defaults, unverified) | Authenticator | forgery-only (signatures) | |
| KyVault-backend | Duo (legacy + OIDC) | KyVault-backend:src/crypto.rs:29-33 @ c0a86c2a; src/api/core/two_factor/duo.rs:178; src/api/core/two_factor/duo_oidc.rs:35-38,140,294 | HMAC-SHA1 (legacy), JWT HS512 (Duo OIDC) | Duo shared secret | symmetric, PQ-safe at 256-bit | |
| KyVault-backend | YubiKey OTP, email 2FA | KyVault-backend:Cargo.toml:152 @ c0a86c2a; src/crypto.rs:98-101 | yubico_ng 1.0.0 (Yubico API); numeric email tokens | Yubico / server | n/a | |
| KyVault-backend | SSO (OIDC RP) | KyVault-backend:src/sso_client.rs:11,228-245 @ c0a86c2a; Cargo.toml:238 | openidconnect 4.1.0; ID-token signature verified against the IdP JWKS (algs per the IdP, likely RS256 from KyIdentity, unverified) + PKCE | IdP (KyIdentity) | forgery-only (signatures) | |
| KyVault-backend | Outbound TLS (reqwest, lettre SMTP, opendal) | KyVault-backend:src/main.rs:75,203-207 @ c0a86c2a; Cargo.toml:128,165-193 | rustls 0.23.46 with the **ring** crypto provider installed as process default. ring provider offers X25519/P-256/P-384 only. No aws-lc-rs in Cargo.lock | System roots (rustls-native-certs 0.8.5) | HNDL (confidentiality) | Classical even against PQ-capable peers. Switching to the aws-lc-rs provider would add X25519MLKEM768 (rustls docs; unverified for 0.23.46) |
| KyVault-backend | Inbound TLS (optional `ROCKET_TLS`) | KyVault-backend:src/auth.rs:611,1201 @ c0a86c2a; Cargo.toml:83 | rocket 0.5.2 `tls` feature on rustls 0.23 (ring provider by the line above, unverified) | Operator cert | HNDL (confidentiality) | Normally TLS terminates at a reverse proxy (not in repo) |
| KyVault-backend | Mobile push relay | KyVault-backend:src/api/push.rs:53-62,119,149,175 @ c0a86c2a | OAuth2 client-credentials to `push_identity_uri` with installation id/key, over TLS. Bitwarden push relay → FCM/APNs | Operator + Bitwarden | n/a | Notification bodies are sync hints, not vault data. Not E2E encrypted |
| KyVault-backend | Random IDs / API keys | KyVault-backend:src/crypto.rs:40-107 @ c0a86c2a | ring SystemRandom; `rand` 0.10.3 | n/a | n/a | |
| KyVault-backend (PR #1, not merged) | Personal Recovery Kit storage | KyVault-backend:src/api/core/tenancy.rs:2-5,44-46,153-185 @ 891fe945; MULTI_TENANCY.md:43-46 | Server stores an opaque `wrappedUserKey` / `wrappedPrivateKey` + `kdf_params_json`. Wrapping is client-side. Algorithm not defined in the backend (unverified; client not in KyVault-web main) | User (offline recovery secret) | unverified | No admin or server escrow in hosted mode |
| KyVault-backend (PR #1) | Internal tenancy API bearer | KyVault-backend:src/api/internal_tenancy.rs:17,52 @ 891fe945 | Shared secret, constant-time compare | Worker + vault | n/a | |
| KyVault-backend (PR #1) | Worker: webhooks, back-channel logout, S3 | KyVault-backend:worker/cmd/kyvault-worker/main.go:77,91 @ 891fe945; worker/internal/s3clean/s3clean.go:9-11,280; MULTI_TENANCY.md:111-113 | ky-primitives `syncauth` (HMAC-signed webhooks, unverified), `oidcverify` (RS256 logout JWT via JWKS), own SigV4 (HMAC-SHA256). Go 1.26.6 net/http default TLS (no tls.Config found) | KyIdentity / S3 | forgery-only (signatures) for RS256; PQ-hybrid already for Go default TLS (X25519MLKEM768 is the Go ≥1.24 default; peer must support it) | ky-primitives v0.10.2-0.20261124022836-b5f5853be771 (worker/go.mod) |
| KyVault-backend | Web-vault shipped in the image | KyVault-backend:docker/Dockerfile.debian:30 @ c0a86c2a | `docker.io/vaultwarden/web-vault:v2026.10.1` pinned by digest | n/a | n/a | The backend image ships **upstream** web-vault, not KyVault-web |
| KyVault-web | Master key derivation + server auth hash | KyVault-web:libs/legacy-crypto/src/models/kdf-config.ts:18,71-73,175 @ 1344eb7; libs/legacy-crypto/src/services/legacy-compat-key.service.ts:83,119; libs/legacy-crypto/src/services/web-crypto-function.service.ts:51-79 | PBKDF2-SHA256 default 600,000 (range 600k–2M) or Argon2id (default 32 MiB, 6 iter, p=4), salt = email. HKDF-expand stretch; masterPasswordHash = PBKDF2(masterKey, password, 1) | User's master password, client only | symmetric, PQ-safe at 256-bit | Client-side (zero-knowledge) model inherited from Bitwarden |
| KyVault-web | User key / item encryption | KyVault-web:libs/legacy-crypto/src/enums/encryption-type.enum.ts:7-16 @ 1344eb7; libs/legacy-crypto/src/services/legacy-compat-key.service.ts:40-46; libs/legacy-crypto/src/models/symmetric-crypto-key.ts:95-107; apps/web/src/app/key-management/key-rotation/user-key-rotation.service.ts:468-472 | V1: AES-256-CBC + HMAC-SHA256 (EncString type 2, 64-byte key). V2: XChaCha20-Poly1305 in COSE Encrypt0 (type 7), plus a user signing key pair | User key, wrapped by the master key | symmetric, PQ-safe at 256-bit | Per-cipher item keys (`cipher.key`) wrap under the user/org key. V2 signing-key algorithm comes from the SDK (Ed25519 per Bitwarden SDK, unverified here) |
| KyVault-web | Org key share, admin password reset, emergency access, login-with-device, trusted device, key-connector | KyVault-web:libs/legacy-crypto/src/services/encrypt.service.implementation.ts:206-220 @ 1344eb7; libs/legacy-crypto/src/services/web-crypto-function.service.ts:163-193; apps/web/src/app/admin-console/organizations/members/components/bulk/base-bulk-confirm.component.ts:88; libs/admin-console/src/common/organization-user/services/default-organization-user.service.ts:50; libs/common/src/auth/services/password-reset-enrollment.service.implementation.ts:63; apps/web/src/app/auth/emergency-access/services/emergency-access.service.ts:571; libs/auth/src/common/services/auth-request/auth-request.service.ts:145; libs/common/src/key-management/device-trust/services/device-trust.service.implementation.ts:178,186 | RSA-2048 OAEP (`encapsulate_key_unsigned`, `rsaEncrypt(_, _, "sha1")`), EncString type 4 = Rsa2048_OaepSha1 (per SDK, unverified). Key pairs from `PureCrypto.rsa_generate_keypair()` | Recipient's RSA private key (user/org/device), itself wrapped symmetrically | HNDL (confidentiality) | **Main PQ exposure in KyVault.** Every shared org key and recovery path is RSA-wrapped and stored on the server for years |
| KyVault-web | Stored passkeys (vault FIDO2 authenticator) | KyVault-web:libs/common/src/platform/services/fido2/fido2-authenticator.service.ts:75,473-498,613 @ 1344eb7 | ECDSA P-256 / ES256 only (WebCrypto `generateKey`/`sign`) | Vault item (encrypted under the user/org key) | forgery-only (signatures) | |
| KyVault-web | SSH key items | KyVault-web:libs/vault/src/cipher-form/components/sshkey-section/sshkey-section.component.ts:124 @ 1344eb7 | Ed25519 generation via SDK | Vault item | forgery-only (signatures) | User data |
| KyVault-web | Send | KyVault-web:libs/legacy-crypto/src/services/legacy-compat-key.service.ts:148 @ 1344eb7 | Random AES-256-CBC-HMAC key; key in the URL fragment | Link holder | symmetric, PQ-safe at 256-bit | Disabled in PR #1 multi-tenant mode |
| KyVault-web | Crypto libraries | KyVault-web:package.json:189,221 @ 1344eb7; package-lock.json:5216-5219,37482-37485 | `@bitwarden/sdk-internal` 0.2.0-main.1126 (Rust/WASM `PureCrypto`), `node-forge` 1.4.0 (MD5 helper), browser WebCrypto | n/a | n/a | Commercial SDK removed (commit 5871834). No PQ algorithms anywhere in libs/apps TS |
| KyMessages-Native | Olm pairwise session setup (device to device) | `KyMessages-Native:web/crypto/src/lib.rs:116-139 @ 9202576` (`create_outbound_session` / `create_inbound_session`, `OlmConfig::version_1()`) | vodozemac 0.11.2 Olm v1: triple Curve25519 DH (X3DH-style) with identity key, one-time key or fallback key, then a Double Ratchet. Messages use AES-256-CBC and truncated HMAC-SHA-256 ([Olm spec](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md)) | Each browser device (vodozemac `Account` in IndexedDB) | HNDL (confidentiality) | Pinned as `vodozemac = "=0.11.2"` with `wasm_js` (`web/crypto/Cargo.toml:12`; `Cargo.lock` vodozemac 0.11.2, x25519-dalek 3.0.0, curve25519-dalek 5.0.0, ed25519-dalek 3.0.0, aes 0.9.4, hkdf/hmac 0.13.0, sha2 0.11.1). Olm carries every room key, so recording Olm traffic exposes every room. |
| KyMessages-Native | Device identity and one-time/fallback keys | `KyMessages-Native:web/crypto/src/lib.rs:56-114 @ 9202576`; `web/src/crypto/engine.ts:358,372 @ 9202576` | Curve25519 identity key and one-time keys, Ed25519 signing key | The device. Public halves are on the server (`e2ee_devices`, `e2ee_one_time_keys`) | HNDL (confidentiality) | The client publishes 50 signed one-time keys plus one fallback key (PR #32 body). PR #32 lists as a follow-up that the fallback key is never rotated. |
| KyMessages-Native | Device and one-time-key self-signatures, checked by the server | `KyMessages-Native:internal/api/e2ee_handlers.go:42,46,58 @ 9202576` | Ed25519 (Go `crypto/ed25519`) over `kymessages.device.v1\n…` and `kymessages.otk.v1\n…` | Signed by the device. The server only verifies | forgery-only (signatures) | The server refuses uploads with a bad signature, and a re-uploaded identity key gets `409`. |
| KyMessages-Native | Device and one-time-key signatures, checked by clients | `KyMessages-Native:web/src/crypto/engine.ts:424,476 @ 9202576`; `web/crypto/src/lib.rs:37-44 @ 9202576` | Ed25519 (vodozemac `Ed25519PublicKey::verify`) | Peers verify | forgery-only (signatures) | Trust is per-device pinning only. Master-key signing (E3) is not built, so the server can still add a device and receive new room keys (PR #32 "Known gap"; `docs/PRODUCT.md:174-175`). |
| KyMessages-Native | Megolm room message encryption | `KyMessages-Native:web/crypto/src/lib.rs:226-260,293-334 @ 9202576`; `web/src/crypto/engine.ts:18-19,542 @ 9202576` | Megolm v1: HMAC-SHA-256 hash ratchet, AES-256-CBC with HMAC-SHA-256, rotated after 100 messages or 7 days | Sending device (outbound). Recipients hold inbound sessions | symmetric, PQ-safe at 256-bit | The session key travels only over Olm as to-device `kymessages.room_key.v1`, so its real exposure is HNDL through the Olm row. Envelope `e2ee_room_v1` is shape-checked server-side, never opened (`internal/api/e2ee_messages.go`). |
| KyMessages-Native | Megolm message authenticity | `KyMessages-Native:web/crypto/src/lib.rs:258-260 @ 9202576` | Ed25519 signature on every Megolm message (vodozemac) | Sending device | forgery-only (signatures) | — |
| KyMessages-Native | Encryption of pickled sessions and accounts at rest | `KyMessages-Native:web/crypto/src/lib.rs:24-26,66-68,197-199 @ 9202576` | vodozemac encrypted pickle (AES-256-CBC and HMAC-SHA-256 keys derived from a 32-byte pickle key) | Browser (IndexedDB) | symmetric, PQ-safe at 256-bit | vodozemac's internal pickle cipher is from upstream docs (unverified at the tag). |
| KyMessages-Native | Pickle-key wrapping in the browser | `KyMessages-Native:web/src/crypto/store.ts:3-5,113-116 @ 9202576` | WebCrypto AES-256-GCM, non-extractable key, 96-bit IV, wrapping a random 32-byte pickle key | Browser IndexedDB (`meta:wrap`, `meta:pickle_key`) | symmetric, PQ-safe at 256-bit | Sign-out deletes the store. PR #56 (`9202576`) asks the browser for persistent storage. There is no OS Keychain or Keystore: the product is web-only. |
| KyMessages-Native | On-device search index at rest | `KyMessages-Native:web/src/chat/searchIndex.ts:66,142-143 @ 9202576` | WebCrypto AES-256-GCM, non-extractable key | Browser | symmetric, PQ-safe at 256-bit | Server search was removed (PR #31). |
| KyMessages-Native | Key backup with a recovery key (planned E3, not on main) | `KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md:42-45,172-173 @ 9202576` | Planned: random 256-bit recovery key encrypts the key backup and an Ed25519 user master key. The wire format is not specified (it is not Matrix `m.megolm_backup.v1`) | The user only | symmetric, PQ-safe at 256-bit | The spec says it is symmetric under the recovery key. No asymmetric backup-encryption key is specified. |
| KyMessages-Native | Device verification (planned E3) | `KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md:47-57 @ 9202576` | Planned: QR code payload "signed end to end" over `internal/devices` pairing, or the recovery key. TOFU pinning of colleagues' master keys. No SAS | The user's devices | forgery-only (signatures) | The signature algorithm is not named (presumably the Ed25519 master key; unverified). |
| KyMessages-Native | Attachment encryption (planned E5) | `KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md:83-86 @ 9202576` | Planned: client AES-256-GCM per file, random key, SHA-256 of the ciphertext inside the Megolm message | Sender and recipients (via Megolm) | symmetric, PQ-safe at 256-bit | Today files are plaintext to the server, labelled "File not encrypted" (`docs/PRODUCT.md:49-50`). |
| KyMessages-Native | Call media encryption (planned E6, not built) | `KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md:100-113 @ 9202576`; signal slot `internal/chat/protocol.go:130 @ 9202576` | Planned: LiveKit `ExternalE2EEKeyProvider` (insertable streams / `RTCRtpScriptTransform`) under a random 256-bit call key sent over Olm. Guests get the key encrypted to an ephemeral X25519 key, with a 4-word code to compare | Call participants. The guest holds an ephemeral key | HNDL (confidentiality) | Exposure is through the Olm and X25519 key transport. The frame cipher is not chosen. livekit-client 2.25.0 (`web/package-lock.json:2355-2356`). |
| KyMessages-Native | Call transport today (P2P and SFU) | `KyMessages-Native:web/src/rtc/hybridCall.ts:863 @ 9202576`; `internal/rtc/livekit.go:24 @ 9202576` | Browser WebRTC DTLS-SRTP. The browser picks the DTLS version, certificate key and SRTP profile. Default ICE is `stun:stun.l.google.com:19302`, with no TURN credentials issued | Browser per call. The SFU (operator-supplied LiveKit) also holds media keys | HNDL (confidentiality) | The SFU can read media until E6 ships. DTLS cert algorithm, version and SRTP profiles are unverified (browser-dependent). |
| KyMessages-Native | LiveKit access tokens (join and Twirp admin) | `KyMessages-Native:internal/rtc/livekit.go:74-75,189-198 @ 9202576`; config `internal/config/config.go:561-582 @ 9202576` | HS256 JWT (HMAC-SHA-256), TTL 15 min (`livekit.go:19`) | Server and LiveKit share `KY_LIVEKIT_API_SECRET` | symmetric, PQ-safe at 256-bit | Only empty values and control characters are refused. There is no length floor in Native, unlike KyMessage-Server's 32–256 bytes. |
| KyMessages-Native | Web Push payload encryption | `KyMessages-Native:internal/push/crypto.go:51-65,77,85,124-136 @ 9202576` | RFC 8291: ephemeral ECDH P-256 and HKDF-SHA-256, then RFC 8188 `aes128gcm` (16-byte CEK) | Browser subscription key (`p256dh`/`auth`). The server mints an ephemeral key per message | HNDL (confidentiality) | The content key is AES-128 (Grover leaves ~64-bit, review). The payload is only "New message" plus the room name (PR #32), which limits exposure. |
| KyMessages-Native | VAPID authentication to push services | `KyMessages-Native:internal/push/vapid.go:21-35,183,203,221 @ 9202576`; key file `internal/api/push_handlers.go:470 @ 9202576` | ES256 (ECDSA P-256) JWT, RFC 8292 | Server: `data/vapid.key` (0600). Multi mode needs the shared key | forgery-only (signatures) | The push services are browser vendors' (FCM for Chrome, Mozilla autopush, Apple Web Push). There is no direct FCM/APNs/UnifiedPush client. |
| KyMessages-Native | Push subscription ownership proof | `KyMessages-Native:internal/store/chat_push.go:199-205 @ 9202576` | Constant-time compare of `p256dh`/`auth` (`hmac.Equal`) | — | n/a | PR #34. This is a comparison, not a MAC. |
| KyMessages-Native | Outbound HTTPS (OIDC, KyRecovery, S3, Web Push) | `KyMessages-Native:internal/push/sender.go:165,180-188 @ 9202576` (`TLSClientConfig` only in tests); no other `tls.Config` in non-test Go | Go 1.27.4 crypto/tls defaults (`Dockerfile:12`). There is no `CurvePreferences`, `MinVersion` or `GODEBUG` override, so X25519MLKEM768 is offered first ([go1.27.4 defaults.go](https://github.com/golang/go/blob/go1.27.4/src/crypto/tls/defaults.go)) | Ephemeral | PQ-hybrid already | Hybrid only when the peer supports it. Certificate checks are classical (next row). `chat_ws.go:177` and `meeting_handlers.go:720` `InsecureSkipVerify` are coder/websocket Origin-check options, not TLS. |
| KyMessages-Native | Outbound TLS server authentication | same as above | WebPKI RSA/ECDSA certificate chains (Go default verifier) | Remote CAs | forgery-only (signatures) | — |
| KyMessages-Native | Inbound HTTPS | none (no `ListenAndServeTLS`) | Plain HTTP behind an operator TLS proxy | Operator's edge | n/a | The edge's TLS policy is out of repo. |
| KyMessages-Native | KyIdentity SSO ID tokens | `KyMessages-Native:internal/sso/oauth.go:47,97 @ 9202576` | go-oidc v3.21.0. `SupportedSigningAlgs` is unset, so the provider's advertised algorithms are used (KyIdentity signs RS256 per KyMessage-Server docs) | KyIdentity | forgery-only (signatures) | There is no JWKS RSA-size floor here (KyMessage-Server has `jwks_strength.go`). go-jose v4.1.9 is indirect. |
| KyMessages-Native | Back-channel logout token | `KyMessages-Native:internal/sso/logout.go:17,52 @ 9202576` | RS256 only | KyIdentity | forgery-only (signatures) | PR #36 |
| KyMessages-Native | PKCE | `KyMessages-Native:internal/crypto/crypto.go:105-115 @ 9202576`; `internal/api/sso_handlers.go:41 @ 9202576` | S256 | — | n/a | — |
| KyMessages-Native | Session cookies, CSRF, bot tokens | `KyMessages-Native:internal/auth/session.go:56-57,93,142 @ 9202576`; `internal/api/agent_handlers.go:47-53 @ 9202576` | Random 256-bit tokens stored as SHA-256. CSRF is 192-bit random. Bot `kybot_` token is 256-bit random, stored as SHA-256 | Server DB holds the hashes | n/a | — |
| KyMessages-Native | Proof-of-work captcha challenge signing | `KyMessages-Native:internal/auth/pow.go:70,138 @ 9202576`; `internal/crypto/crypto.go:73-83 @ 9202576` | HMAC-SHA-256 under `KY_SESSION_SECRET` | Server (shared across replicas in multi mode) | symmetric, PQ-safe at 256-bit | Production requires a non-empty value only. Development generates 32 bytes (`config.go:341-350`). There is no length floor (Server has one). |
| KyMessages-Native | Local TOTP second factor | `KyMessages-Native:internal/auth/totp.go:10-20 @ 9202576` (ky-primitives/totp) | RFC 6238 HMAC-SHA1 (ky-primitives) | Server and the user's authenticator | symmetric, PQ-safe at 256-bit | HMAC key is 160-bit (ky-primitives default; unverified here). Grover does not apply meaningfully to a MAC. |
| KyMessages-Native | TOTP secret at rest | `KyMessages-Native:internal/api/totp_handlers.go:52,75 @ 9202576`; `internal/api/auth_handlers.go:191 @ 9202576`; `internal/crypto/crypto.go:22-62 @ 9202576` | AES-256-GCM, 96-bit random nonce | Deployment key `KY_ENCRYPTION_KEY` or `data/encryption.key` (32 bytes; `internal/config/config.go:352-366 @ 9202576`) | symmetric, PQ-safe at 256-bit | The deployment key is used directly, not through `DeriveKey`. |
| KyMessages-Native | KyRecovery token sealed at rest | `KyMessages-Native:internal/backup/settings.go:34-37 @ 9202576` | ky-primitives `recoveryclient.NewAESGCMSealer` (AES-256-GCM, label `…:kyrecovery_token`) | Deployment key | symmetric, PQ-safe at 256-bit | — |
| KyMessages-Native | Recovery codes (account) | `KyMessages-Native:internal/auth/recovery.go:21-48 @ 9202576` | ky-primitives/recoverycode, SHA-256 digests | Server holds the digests | n/a | — |
| KyMessages-Native | Password hashing | `KyMessages-Native:internal/api/auth_handlers.go`, `password_handlers.go` (ky-primitives/password) | Argon2id (per ky-primitives; the KyMessage-Server STRONG-CRYPTO.md:40 states the same package) | Server DB | n/a | — |
| KyMessages-Native | S3 attachment objects at rest (multi mode) | `KyMessages-Native:internal/blobs/seal.go:12,24-54 @ 9202576`; `internal/blobs/s3.go:47 @ 9202576`; key `internal/config/config.go:814-821 @ 9202576` | AES-256-GCM, AAD `kymessages-attachments/v1\0`+org/object key | `KY_ATTACHMENTS_S3_SEAL_KEY_FILE`, 32 bytes, the same on every replica (never auto-created) | symmetric, PQ-safe at 256-bit | PR #50. One deployment-wide key, with no per-org keys. Org binding is through AAD only. |
| KyMessages-Native | S3 request signing | `KyMessages-Native:internal/blobs/s3.go @ 9202576` (ky-primitives/s3) | AWS SigV4 (HMAC-SHA-256), HTTPS-only endpoint (`config.go:832-834`) | Operator S3 credentials | symmetric, PQ-safe at 256-bit | SigV4 is inferred from ky-primitives/s3 (unverified here). TLS is the Go default (hybrid). |
| KyMessages-Native | Backup attachment mirror | `KyMessages-Native:internal/backup/attachments.go:524-528 @ 9202576` | AES-256-GCM via `blobs.Sealer` | `data/attachments.key` (`docs/PRODUCT.md:156`) | symmetric, PQ-safe at 256-bit | — |
| KyMessages-Native | Backup capsule to KyRecovery | `KyMessages-Native:internal/backup/payload.go:62-67 @ 9202576`; ky-primitives `recoverykey/recoverykey.go:42 @ b55ca6d` | `kycap/3`: HPKE X-Wing (`hpke.MLKEM768X25519()`), HKDF-SHA256, AES-256-GCM | Custodians (k-of-n). The pinned suite public key is in the app | PQ-hybrid already | The capsule carries the deployment key (`payload.go:67`), so its PQ status covers all at-rest keys above. ky-primitives `v0.10.2-0.20261124003741-b55ca6d3313c` (`go.mod`). |
| KyMessages-Native | Suite pair / directory webhook / presence auth | `KyMessages-Native:internal/api/suite.go`, `sso_handlers.go`, `presence_handlers.go`, `meeting_handlers.go` (ky-primitives/syncauth) | HMAC-SHA-256 (syncauth) | KyIdentity-issued pair secrets | symmetric, PQ-safe at 256-bit | — |
| KyMessages-Native | SCIM bearer token | `KyMessages-Native:internal/scim/handler.go` (`subtle.ConstantTimeCompare`) | Static bearer token | Operator / IdP | n/a | — |
| KyMessages-Native | Device pairing secret | `KyMessages-Native:internal/devices/devices.go:42 @ 9202576` | 192-bit random secret | Pairing devices | n/a | E3 plans to reuse this as the QR transport. |
| KyMessages-Native | Image release provenance | `KyMessages-Native:.github/workflows/release-image.yml:25-26,160-178 @ 9202576` | GitHub `actions/attest-build-provenance` v4.2.2 (Sigstore keyless), `gh attestation verify` before `:stable` moves | Sigstore Fulcio / GitHub OIDC | forgery-only (signatures) | Sigstore's key algorithm (ECDSA P-256) is unverified for this action. There is no cosign or GPG. |
| KyMessage-Server | Element Web E2EE (Olm/Megolm) | `KyMessage-Server:docker-compose.matrix.yml:222 @ 439babc` (Element Web v1.12.30) | Element `apps/web/package.json:84` @ v1.12.30 pins matrix-js-sdk 43.0.0, then crypto-wasm 18.7.0 (per the prior report's lockfile read), then matrix-sdk-crypto 0.18.0 (git f333a324), then vodozemac 0.10.0 (git cfc4eee) ([crypto-wasm v18.7.0 Cargo.lock](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/blob/v18.7.0/Cargo.lock)). Olm Curve25519 3DH and ratchet, Megolm AES-256-CBC/HMAC-SHA-256 | Users' browsers | HNDL (confidentiality) | Synapse sets `encryption_enabled_by_default_for_room_type: all` (`internal/matrixinit/templates/homeserver.yaml.tmpl:38`). Element is a stock upstream image. |
| KyMessage-Server | Cross-signing (master, self-signing and user-signing keys) | Element (upstream). Agent probe: `KyMessage-Server:scripts/agent-probe/xsign.py:1-15 @ 439babc`; notes bot `notes/src/main.mjs:134-136 @ 439babc` | Ed25519 ([spec](https://spec.matrix.org/latest/client-server-api/#cross-signing)) | User's devices and SSSS | forgery-only (signatures) | — |
| KyMessage-Server | Server-side key backup | Element / matrix-sdk-crypto (upstream) | `m.megolm_backup.v1.curve25519-aes-sha2`: ephemeral Curve25519 ECDH to the backup public key, HKDF-SHA-256, AES-256-CBC, HMAC-SHA-256 ([spec](https://spec.matrix.org/latest/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2)) | Backup private key in SSSS | HNDL (confidentiality) | Backup ciphertext sits on Synapse and goes into backup capsules (Synapse DB dump). Recording that dump exposes room keys to a future Curve25519 break. |
| KyMessage-Server | Secret storage (SSSS) and recovery key | Element (upstream); console help URLs `internal/matrixinit/templates/element.json.tmpl:21-22 @ 439babc` | `m.secret_storage.v1.aes-hmac-sha2` (HKDF-SHA-256, AES-256-CTR, HMAC-SHA-256). Recovery key is 256-bit, base58 with `0x8B 0x01` prefix and parity byte. Optional passphrase via `m.pbkdf2` ([spec](https://spec.matrix.org/latest/client-server-api/#secret-storage)) | User | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | Device verification | Element (upstream) | SAS `m.sas.v1`: key agreement `curve25519-hkdf-sha256`, MAC `hkdf-hmac-sha256.v2`, SHA-256 commitment. QR `m.qr_code.scan.v1` ([spec](https://spec.matrix.org/latest/client-server-api/#short-authentication-string-sas-verification)) | The two devices (ephemeral) | forgery-only (signatures) | Real-time authentication only: a recorded SAS gives no content. A quantum active MITM would be needed. |
| KyMessage-Server | Element device store at rest | Element (upstream) | IndexedDB crypto store (pickle-key encryption details unverified for v1.12.30) | Browser | symmetric, PQ-safe at 256-bit | Unverified. There is no desktop or mobile app with a Keychain or Keystore. |
| KyMessage-Server | Synapse federation server signing key | `KyMessage-Server:internal/matrixinit/matrixinit.go:350,584-591 @ 439babc`; `templates/homeserver.yaml.tmpl:29,31 @ 439babc` | Ed25519 (`ed25519 a_<id> <seed>`), signs federation requests (X-Matrix) and events. `trusted_key_servers: []` | Synapse (`./matrix/synapse/signing.key`) | forgery-only (signatures) | Federation is closed by default (`federation_domain_whitelist: []`). PR history: `docs/superpowers/plans/2026-10-11-federation-opt-in.md`. |
| KyMessage-Server | Synapse federation and outbound HTTPS | `KyMessage-Server:internal/matrixinit/templates/homeserver.yaml.tmpl:9 @ 439babc` (no `federation_client_minimum_tls_version`) | Twisted/pyOpenSSL (OpenSSL 3.5.x in the image per the prior report). Minimum TLS 1.0 by Synapse default | Synapse | HNDL (confidentiality) | Whether OpenSSL 3.5's default groups negotiate X25519MLKEM768 in Synapse's context is unverified, so this is marked HNDL conservatively. |
| KyMessage-Server | Synapse macaroon and form secrets | `KyMessage-Server:internal/matrixinit/matrixinit.go:274-275,594-599 @ 439babc`; `templates/homeserver.yaml.tmpl:27-28 @ 439babc` | HMAC keys, 32 random bytes hex. A kept key under 32 bytes is refused | Synapse | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | MAS signing keys (OIDC tokens issued to Element) | `KyMessage-Server:internal/matrixinit/matrixinit.go:278-279,611-655 @ 439babc`; `templates/mas.yaml.tmpl:30-34 @ 439babc` | RSA-2048 (PKCS#1) and ECDSA P-256. A kept RSA key under 2048 bits is refused | MAS | forgery-only (signatures) | — |
| KyMessage-Server | MAS encryption key | `KyMessage-Server:internal/matrixinit/matrixinit.go:277,601-607 @ 439babc` | 32-byte key (comment: "MAS's AES-256 key"; MAS's actual AEAD unverified) | MAS | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | MAS upstream OIDC to KyIdentity | `KyMessage-Server:internal/matrixinit/templates/mas.yaml.tmpl:55-64 @ 439babc` | RS256 ID tokens. `client_secret_basic` | KyIdentity / MAS | forgery-only (signatures) | MAS applies no RSA floor (`docs/STRONG-CRYPTO.md:134-135`). |
| KyMessage-Server | Matrix access and refresh tokens | MAS / Synapse (upstream). MAS to Synapse shared secret `matrixinit.go:276 @ 439babc` | Opaque bearer tokens (MAS); 32-byte hex shared secret | MAS / Synapse | n/a | Token storage format is unverified (upstream). |
| KyMessage-Server | Console SSO ID-token verification | `KyMessage-Server:internal/sso/oauth.go:59,80,98 @ 439babc`; `internal/sso/jwks_strength.go:16,23,64 @ 439babc` | go-oidc v3.21.0 (algorithm from provider; RS256). JWKS RSA keys under 2048 bits are refused, and JWKS redirects are refused. PKCE S256 and nonce | KyIdentity | forgery-only (signatures) | PR #97 |
| KyMessage-Server | Console sessions, CSRF, guest and agent tokens | `KyMessage-Server:internal/auth/session.go:55-56,162 @ 439babc`; `internal/api/guest_handlers.go:66-81 @ 439babc` | 256-bit random tokens stored as SHA-256. CSRF = HMAC-SHA-256(`KY_SESSION_SECRET`, "ky-csrf:"+session) | Server | symmetric, PQ-safe at 256-bit | `KY_SESSION_SECRET` floor: `MinSessionSecretBytes` (`internal/config/config.go:215`; 16 bytes per `docs/STRONG-CRYPTO.md:29`). |
| KyMessage-Server | Proof-of-work challenge | `KyMessage-Server:internal/auth/pow.go:70 @ 439babc` | HMAC-SHA-256 under `KY_SESSION_SECRET` | Server | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | Deployment key / KyRecovery token seal | `KyMessage-Server:internal/config/config.go:219-224 @ 439babc`; `internal/backup/settings.go:12,36-37 @ 439babc` | AES-256-GCM (ky-primitives `NewAESGCMSealer`), 32-byte key | `KY_ENCRYPTION_KEY` / `data/encryption.key` | symmetric, PQ-safe at 256-bit | `internal/crypto.EncryptAESGCM` has no non-test caller on master. Local TOTP is removed (`docs/ASSURANCE-CASE.md:110`). |
| KyMessage-Server | Synapse media store | `KyMessage-Server:internal/matrixinit/templates/homeserver.yaml.tmpl:25 @ 439babc` | Plaintext on disk (`/media`). Media in E2EE rooms is client-encrypted (Matrix attachments: AES-256-CTR and SHA-256, [spec](https://spec.matrix.org/latest/client-server-api/#sending-encrypted-attachments)) | Clients (for E2EE media) | symmetric, PQ-safe at 256-bit | The per-file key travels in a Megolm event, so it is HNDL via Olm. Unencrypted-room media has no at-rest encryption. |
| KyMessage-Server | Media backup mirror | `KyMessage-Server:internal/backup/media/media.go:3-4,305-322 @ 439babc`; key `internal/backup/matrix.go:20-25 @ 439babc`, `internal/backup/payload.go:98 @ 439babc` | AES-256-GCM, AAD = relative path | `data/media.key` (32 bytes), carried inside the capsule | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | Backup capsule to KyRecovery (Synapse/MAS pg_dump, `./matrix` secrets, signing key, media key) | `KyMessage-Server:internal/backup/matrix.go:15,40-42 @ 439babc`; ky-primitives `recoverykey/recoverykey.go:42 @ 875f57b` | `kycap/3` HPKE X-Wing (ML-KEM-768 + X25519), HKDF-SHA256, AES-256-GCM | Custodians (k-of-n) | PQ-hybrid already | ky-primitives `v0.10.2-0.20261116015712-875f57b13976` (`go.mod`). The capsule contents include key-backup ciphertext that is itself classical (see the key-backup row). |
| KyMessage-Server | Suite HMAC (KyCalendar/KyPost pairs, directory webhook) | `KyMessage-Server:internal/config/config.go:316,343 @ 439babc`; ky-primitives/syncauth in `internal/kycalendar/kycalendar.go`, `internal/api/suite_pair.go` | HMAC-SHA-256 | KyIdentity-issued 32-byte secrets | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | LiveKit grants (MatrixRTC SFU JWTs) | `KyMessage-Server:internal/matrixrtc/matrixrtc.go:40-48 @ 439babc`; `internal/api/rtc_handlers.go:203 @ 439babc`; `templates/livekit.yaml.tmpl:11-12 @ 439babc` | HS256 JWT (HMAC-SHA-256). Secret is 32 random bytes hex, and the app accepts 32–256 bytes (`config.go:439`) | Console and LiveKit | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | OpenID token check for remote callers | `KyMessage-Server:internal/api/federation_calls.go:48-53,100-123 @ 439babc` | Go 1.27.4 default TLS (no `tls.Config`, verified chain, https-only, public IPs) | Ephemeral | PQ-hybrid already | Hybrid only when the remote homeserver offers it. The certificate chain is classical: forgery-only. |
| KyMessage-Server | Console outbound HTTPS (KyIdentity, KyRecovery, Postgres TLS) | no `tls.Config` in non-test Go except `matrixinit` cert parsing | Go 1.27.4 defaults. The optional profile `docker-compose.strong-crypto.yml:6` sets `GODEBUG=fips140=on` | Ephemeral | PQ-hybrid already | Under `fips140=on`, Go 1.27.4 still allows X25519MLKEM768 ([defaults_fips140.go:35-42](https://github.com/golang/go/blob/go1.27.4/src/crypto/tls/defaults_fips140.go)). There is no `tlsmlkem=0` anywhere. |
| KyMessage-Server | TURN/TLS listener certificate | `KyMessage-Server:internal/matrixinit/matrixinit.go:629-640,706-743 @ 439babc`; `templates/livekit.yaml.tmpl:18-26 @ 439babc` | Operator certificate. Every chain cert must be RSA-2048+, ECDSA or Ed25519. LiveKit TLS listener `MinVersion` 1.2 (upstream, per the prior report) | Operator / LiveKit | forgery-only (signatures) | The key exchange on that listener is LiveKit's Go default (likely X25519MLKEM768 if the client offers it; unverified at the pinned image). |
| KyMessage-Server | TURN credentials | LiveKit upstream (`livekit/livekit-server:v1.13.7`, `docker-compose.matrix.yml:243`) | Credential derived from the API secret. STUN MESSAGE-INTEGRITY is HMAC-SHA1 under an MD5 long-term key (per the prior report, pion/turn) | LiveKit | symmetric, 128-bit: Grover → ~64-bit, review | Authentication only (128-bit MD5-derived key). Interoperability is fixed by RFC 5389/8489. |
| KyMessage-Server | WebRTC DTLS (LiveKit SFU and Element Call) | LiveKit v1.13.7 upstream | Pion DTLS (livekit/dtls v3.1.5-warp.1): ECDHE X25519/P-256/P-384, local ECDSA P-256 cert, DTLS 1.2. Accepts RSA-1024 peer certificates (prior report probe) | Ephemeral per peer connection | HNDL (confidentiality) | The DTLS version is from Pion's capability (DTLS 1.2), unverified at the pinned fork. |
| KyMessage-Server | SRTP media | LiveKit v1.13.7 upstream | SRTP AES-128-GCM / AES-256-GCM / AES-128-CM-HMAC-SHA1-80 (Pion profiles, per the prior report) | Derived from DTLS | symmetric, 128-bit: Grover → ~64-bit, review | Which profile is negotiated depends on the browser. |
| KyMessage-Server | MatrixRTC frame E2EE (Element Call / LiveKit E2EE) | `KyMessage-Server:notes/src/meeting.mjs:54-65,87-89 @ 439babc`; `notes/src/rules.mjs:34-36 @ 439babc` | Per-participant 16-byte random media keys sent over Matrix E2EE (Olm/Megolm). HKDF with livekit-client salt, then AES-GCM frames (`EncryptionType.GCM`) | Each participant | symmetric, 128-bit: Grover → ~64-bit, review | Key transport is HNDL through Olm. The frame AES key length (128 bits from a 16-byte key) is inferred. The notes bot refuses keys under 16 bytes. |
| KyMessage-Server | Meeting-notes bot E2EE | `KyMessage-Server:notes/src/main.mjs:4,27,50 @ 439babc`; `notes/package-lock.json:763-765,1197-1199,740-741 @ 439babc` | matrix-js-sdk 44.0.0, then crypto-wasm 18.9.2, then matrix-sdk-crypto 0.19.1, then vodozemac 0.11.2 ([crypto-wasm v18.9.2 Cargo.lock](https://github.com/matrix-org/matrix-rust-sdk-crypto-wasm/blob/v18.9.2/Cargo.lock)). Olm/Megolm | The bot | HNDL (confidentiality) | `initRustCrypto({cryptoDatabasePrefix})` passes no storage key or passphrase. The store is fake-indexeddb, `v8.serialize`'d to `crypto.v8` with file mode 0600 (`notes/src/store.mjs:22`). It is apparently not encrypted at rest (inferred). |
| KyMessage-Server | Notes bot snapshot attachments | `KyMessage-Server:notes/src/attach.mjs:3,11,25 @ 439babc` | AES-256-CTR with a fresh 32-byte key, SHA-256 (Matrix encrypted-attachment format) | The bot, then room members via Megolm | symmetric, PQ-safe at 256-bit | — |
| KyMessage-Server | Notes bot to console auth | `KyMessage-Server:internal/api/notes_handlers.go:206 @ 439babc`; `internal/matrixinit/matrixinit.go:284 @ 439babc` | Static 32-byte bearer, constant-time compare | Console and bot | n/a | — |
| KyMessage-Server | Push notifications | `KyMessage-Server:internal/matrixinit/templates/homeserver.yaml.tmpl:39-41 @ 439babc` | Synapse HTTP pusher to the client's push gateway (Element's Sygnal or self-hosted ntfy / UnifiedPush). `include_content: false`. No payload encryption; transport is Synapse's TLS | Gateway operators; FCM/APNs keys are held by the gateway, not Ky | HNDL (confidentiality) | Only event and room IDs leave. There is no Sygnal, FCM, APNs or VAPID config in the repo. |
| KyMessage-Server | Password hashing | `KyMessage-Server:internal/api/auth_handlers.go`, `password_handlers.go` (ky-primitives/password) | Argon2id (`docs/STRONG-CRYPTO.md:40`) | Server DB | n/a | — |
| KyMessage-Server | Image release provenance (server and notes images) | `KyMessage-Server:.github/workflows/release-image.yml:40-41,176-193 @ 439babc`; `docs/VERIFYING-RELEASES.md:21-45 @ 439babc` | Sigstore keyless SLSA provenance (`actions/attest-build-provenance` v4.2.2) | GitHub OIDC / Fulcio | forgery-only (signatures) | — |
| kymessages-desktop | none (empty repo) | `kymessages-desktop:README.md:2 @ 0c3de83` | — | — | n/a | It has only LICENSE and README ("Electron: encrypted chat, calls and screen sharing"). There is no code, workflow, branch or PR. |
| kydrive-server | Blob and cache encryption at rest (KYB2) | kydrive-server:internal/drive/sealed.go:19-23,123,212 @ 9d5a468 | age v1 (filippo.io/age v1.3.2) STREAM: ChaCha20-Poly1305, 64 KiB chunks, random per-file 128-bit file key (age), header HMAC | Per-file key is random; it is wrapped by the deployment key (next row) | symmetric, PQ-safe at 256-bit | age file key is 16 bytes (age v1 spec). The payload key is HKDF-SHA256 of it with a nonce, giving a 256-bit ChaCha20 key (age spec, https://age-encryption.org/v1). Grover against a 128-bit file key: unverified whether this needs a review note. |
| kydrive-server | Wrapping the per-file key in a custom `kydrive` age stanza | kydrive-server:internal/drive/sealed.go:68-94 @ 9d5a468 | AES-256-GCM under HKDF-SHA256(deployment key, 16-byte random salt, binding `kydrive:kyb2:blob:<id>` or `cache:<id>`), all-zero nonce (the key is fresh per salt) | Server: 32-byte deployment key | symmetric, PQ-safe at 256-bit | No asymmetric recipient. The age X25519 recipient is not used. |
| kydrive-server | Legacy KYB1 blob read (until migrated) | kydrive-server:internal/drive/sealed.go:24-27,261-265 @ 9d5a468 | AES-256-GCM chunks under HKDF-SHA256(deployment key, 32-byte salt, `kydrive:blob`) | Server deployment key | symmetric, PQ-safe at 256-bit | Read only. Nothing new is written as KYB1. |
| kydrive-server | Deployment key (the root of every at-rest key) | kydrive-server:internal/config/config.go:280-293 @ 9d5a468 | 32 random bytes from `KY_ENCRYPTION_KEY` or `<data>/encryption.key` (ky-primitives keyfile). Required external in multi mode (config.go:285). | Operator/server. It also travels inside every recovery capsule (see the capsule row). | symmetric, PQ-safe at 256-bit | Multi mode refuses to mint it (D13). |
| kydrive-server | File and folder name encryption, plus name_hmac | kydrive-server:internal/drive/names.go:22-30,68,73 @ 9d5a468 | AES-256-GCM (AAD `table:id`) under HKDF `kydrive:name`. HMAC-SHA256 under HKDF `kydrive:name-hmac`. Key check under `kydrive:key-check` (names.go:40). | Server deployment key | symmetric, PQ-safe at 256-bit | |
| kydrive-server | Content-search index | kydrive-server:internal/search/index.go:61-73,129,135 @ 9d5a468; vocab.go:180 | HMAC-SHA256 term and doc tokens. Vocabulary sealed with AES-256-GCM. HKDF labels `kydrive:search-token/-doc/-check/-vocab`. | Server deployment key | symmetric, PQ-safe at 256-bit | |
| kydrive-server (step K, unpushed) | Per-org data keys (multi-tenant only, D14) | local branch `feat/per-org-keys`: internal/drive/orgkeys.go:79-99,113-145 @ ac85499; sealed.go diff (stanza `kydrive-org`) | Org key: 32 random bytes. Wrapped with AES-256-GCM under KEK = HKDF-SHA256(deployment key, no salt, `kydrive:org-kek`), random 12-byte nonce, AAD `kydrive:org-key:<kek>:<org_id>`. File keys wrapped under HKDF(org key, salt, `kydrive:kyb2:org:<org>:`+binding). Names are per org too. | Server. The deployment key is the KEK (owner decision: no KMS, no KyIdentity-held key, no BYOK). The cache keeps unwrapped keys for 1 minute and up to 4096 entries. | symmetric, PQ-safe at 256-bit | Not on origin and no PR. Purge deletes the row (crypto-shredding). Search keys are not yet per org. |
| kydrive-server | Restic bulk backup repository password | kydrive-server:internal/backup/bulk.go:59-60,81-87 @ 9d5a468 | Password = hex(HKDF-SHA256(deployment key, `kydrive:restic`)). Restic does its own crypto: scrypt KDF, then AES-256-CTR plus Poly1305-AES (https://restic.readthedocs.io/en/stable/100_references.html, not re-read for this report, so unverified here). | Server deployment key | symmetric, PQ-safe at 256-bit | Restic comes from Alpine's apk (Dockerfile:28). The repo is reached over `s3:https://` or `rest:https://` with Restic's own TLS (docs/STRONG-CRYPTO.md "Out of scope"). |
| kydrive-server | Recovery capsule (config, DB snapshot, keys) | kydrive-server:internal/api/backup_handlers.go:181; cmd/server/main.go:725 @ 9d5a468 → ky-primitives:capsule/hpke.go:5-17 @ b5f5853 | HPKE base mode: KEM X-Wing (ML-KEM-768 + X25519), HKDF-SHA256, AES-256-GCM, manifest as AAD (kycap/3) | Recipient: the suite recovery key, split by Shamir into custodian cards (KyRecovery ceremony). The sender holds only the pinned public key. | PQ-hybrid already | The capsule carries the deployment key and the Ed25519 identity seed (docs/STRONG-CRYPTO.md table), so this one KEM protects every other at-rest key. A PG snapshot goes in as a SQLite file (internal/store/snapshot.go:36-41). Capsules are not signed (see Gaps). |
| kydrive-server | Stored KyRecovery bearer token | ky-primitives:recoveryclient/sealer.go:24-34 @ b5f5853 (via internal/backup NewSealer, api/backup_handlers.go:263) | AES-256-GCM under HKDF-SHA256(deployment key, label) | Server deployment key | symmetric, PQ-safe at 256-bit | |
| kydrive-server | Recovery-key pin | ky-primitives:recoveryclient/pin.go:47-64 @ b5f5853 | Key ID (SHA-256 of the X-Wing public key) stored in settings | Server settings | n/a | It pins the public key; there is no signature. |
| kydrive-server | TLS pin rollover statement (linked devices) | kydrive-server:internal/api/tls_pin.go:31-60,107 @ 9d5a468; identity key config.go:181-206 | Ed25519 signature over `kydrive-tls-pin/1\nhost\npin\nissued_at`. The pin is SHA-256 of the leaf SPKI. | Server: 32-byte Ed25519 seed, `<data>/identity.key` or `KYDRIVE_IDENTITY_KEY_FILE`. Never rotated (linked apps hold the public half). | forgery-only (signatures) | A CRQC could forge a rollover and get a device to re-pin to a MITM leaf. |
| kydrive-server | TLS pin probe (outbound handshake to own KY_APP_URL) | kydrive-server:internal/api/tls_pin.go:170 @ 9d5a468 | `tls.Config{MinVersion: TLS1.2}`, no CurvePreferences | n/a | PQ-hybrid already | Go default key shares. Go 1.27 enables X25519MLKEM768 by default (local GOROOT go1.27.3 crypto/tls/defaults.go:21-42). Whether it is negotiated depends on the edge. |
| kydrive-server | Inbound HTTPS | docs/STRONG-CRYPTO.md "Configure the independent HTTPS edge" @ 9d5a468; tls_pin.go:73 comment | KyDrive serves plain HTTP behind a proxy and never terminates TLS. The documented edge is TLS 1.2/1.3, `DEFAULT@SECLEVEL=2`, RSA-2048+ or P-256+ certificates. | Operator's proxy, ingress (deploy/render.py:53) or cert-manager | HNDL (confidentiality) | The PQ key exchange depends on the proxy's TLS library (unverified). The docs set no hybrid group. Certificates are classical: forgery-only. |
| kydrive-server | Outbound TLS clients (OIDC, Euro-Office, KyRecovery, S3) | docs/STRONG-CRYPTO.md profile; internal/objects/s3.go:55 @ 9d5a468 | Go stdlib defaults; no `tls.Config` overrides anywhere except tls_pin.go:170. Optional `GODEBUG=fips140=on` (docker-compose.strong-crypto.yml:6). | n/a | PQ-hybrid already | fips140=on keeps X25519MLKEM768 allowed (go1.27.3 crypto/tls/defaults_fips140.go:35-43). Go toolchain is 1.27.3 (go.mod), the image is golang:1.27.4 (Dockerfile:12). No `tlsmlkem=0` anywhere. Hybrid only when the peer supports it. |
| kydrive-server | Object storage (multi mode) | kydrive-server:internal/objects/s3.go:32,55-66 @ 9d5a468 | AWS SDK v2 S3 (service/s3 v1.116.0): HTTPS (plain HTTP only to loopback), SigV4 HMAC-SHA256 | Access/secret key: operator | PQ-hybrid already | No SSE requested in code (no ServerSideEncryption). Objects are KYB2 ciphertext before upload. TLS is the Go default, as in the outbound row. |
| kydrive-server | OIDC ID token and back-channel logout verification | kydrive-server:internal/sso/oauth.go:62,117-132; jwks_strength.go:60 @ 9d5a468 | coreos/go-oidc v3.21.0 with go-jose v4.1.9; KyIdentity/KySignOn signs RS256. Every RSA JWK must be at least 2048 bits. | IdP (KyIdentity) | forgery-only (signatures) | PKCE S256 (internal/crypto/crypto.go:118-128). |
| kydrive-server | KySignOn directory webhooks | ky-primitives:syncauth/syncauth.go:7-15 @ b5f5853; kydrive internal/api/server.go:256 | HMAC-SHA256 (ky-sync-v1); `KY_KYSIGNON_HMAC_SECRET` at least 16 bytes | Shared secret (KySignOn and KyDrive) | symmetric, 128-bit: Grover → ~64-bit, review | The floor is 16 bytes (128-bit). At the recommended 32 bytes it is 256-bit. HMAC is not materially weakened by Grover, so this is a cautious flag. |
| kydrive-server | Euro-Office editor JWT | kydrive-server:internal/editor/client.go:50,56,66 @ 9d5a468 | HS256 (go-jose v4), secret at least 32 bytes | Shared secret with Document Server | symmetric, PQ-safe at 256-bit | |
| kydrive-server | Device request signatures (desktop and Android) | kydrive-server:internal/api/devicesig.go:57-89; internal/drive/devices.go:133-135 @ 9d5a468 | ECDSA P-256 / SHA-256 (`kydrive-request-v1`) over method, URI, date, nonce, header and body digests | Device: private key. Server: SPKI. | forgery-only (signatures) | |
| kydrive-server | Device link redeem | kydrive-server:internal/drive/devices.go:110-120,328-336 @ 9d5a468 | PKCE-style S256 verifier; 256-bit device token, stored as SHA-256 | Device and server | n/a | |
| kydrive-server | Share links, guest links, view copies, KyPost tickets, sessions | kydrive-server:internal/drive/links.go:41-43; guest.go:75-80; viewcopies.go:80-82; peer.go:131-133; auth/session.go:59-60 @ 9d5a468 | 256-bit random bearer tokens, stored as SHA-256. Optional guest secret uses Argon2id. Not HMAC-signed URLs. | Server DB (hash). The holder has the token. | n/a | Random bearer tokens, not signatures. |
| kydrive-server | WebDAV auth (app passwords, agent tokens) | kydrive-server:internal/api/dav.go:32,80; internal/drive/apppasswords.go:55-58,136 @ 9d5a468 | HTTP Basic over TLS; 160-bit random secret stored as SHA-256 | Server DB (hash) | n/a | |
| kydrive-server | WebDAV lock tokens | kydrive-server:internal/dav/locks.go:54-57,227 @ 9d5a468 | HMAC-SHA256 under HKDF(deployment key, `kydrive webdav lock …`). Lock details sealed with AES-256-GCM. | Server deployment key | symmetric, PQ-safe at 256-bit | |
| kydrive-server | CSRF and proof-of-work tokens | kydrive-server:internal/auth/session.go:169-176; internal/auth/pow.go:71,101 @ 9d5a468 | HMAC-SHA256 under `KY_SESSION_SECRET` (at least 16 bytes) | Server | symmetric, 128-bit: Grover → ~64-bit, review | Same floor caveat as the webhook row. |
| kydrive-server | Replica-config fingerprints | kydrive-server:internal/config/replica.go:18,75 @ 9d5a468 | HMAC-SHA256 under deployment key | Server | symmetric, PQ-safe at 256-bit | |
| kydrive-server | KyPost pairing MAC | kydrive-server:internal/api/kypost.go:222-223 @ 9d5a468 | HMAC-SHA256 | Shared pairing secret | symmetric, PQ-safe at 256-bit | The secret's size was not checked (unverified). |
| kydrive-server | Local passwords (admin, step-up, guest) | ky-primitives:password/password.go:1,50-53 @ b5f5853 | Argon2id m=64 MiB, t=3, p=4 (x/crypto v0.59.0) | Server DB | n/a | |
| kydrive-server | SCIM bearer token | internal/scim/handler.go (crypto/subtle compare) @ 9d5a468 | Constant-time compare of a static token (`KY_SCIM_TOKEN`) | Operator | n/a | |
| kydrive-server | Release image signing | kydrive-server:.github/workflows/release-image.yml:178-193; ci.yml:191 @ 9d5a468 | GitHub attest-build-provenance v4.2.2 (Sigstore keyless; Fulcio cert, ECDSA P-256 per Sigstore, unverified) | GitHub/Sigstore OIDC identity | forgery-only (signatures) | docs/VERIFYING-RELEASES.md. The SBOM is unsigned. |
| kydrive-server (planned) | End-to-end vaults (D15) | kydrive-server:docs/superpowers/specs/2026-11-22-e2e-vault-design.md:3,47-63 @ 9d5a468 | Planned: age files, every recipient age `mlkem768x25519` hybrid. Signatures Ed25519 + ML-DSA-65, both required. | User keys in the OS keystore, recovery key offline, escrow key (single-tenant only) | PQ-hybrid already | Draft only; nothing built. age v1.3.2 has `mlkem768x25519` (module cache pq.go:18,82). |
| KyDrive-for-Android | Session (token) at rest | KyDrive-for-Android:app/src/main/java/org/kysecurity/drive/Session.kt:32,107-136 @ 60e755b | AES-256-GCM, non-exportable AndroidKeyStore key (StrongBox when available) | Device Keystore | symmetric, PQ-safe at 256-bit | |
| KyDrive-for-Android | Device request signing key | KyDrive-for-Android:app/src/main/java/org/kysecurity/drive/DeviceSigningKey.kt:24,37-40; core/Signing.kt:13-40 @ 60e755b | ECDSA P-256 SHA256withECDSA, AndroidKeyStore (TEE, not StrongBox) | Device Keystore | forgery-only (signatures) | |
| KyDrive-for-Android | TLS pinning and rollover verification | KyDrive-for-Android:app/src/main/java/org/kysecurity/drive/core/TlsPin.kt:57-95; core/Tls.kt:28-29,79-98 @ 60e755b | SPKI SHA-256 pin. Ed25519 rollover check (BouncyCastle bcprov 1.87). Chain floor RSA 2048, EC 256. | Server identity key (public half on device) | forgery-only (signatures) | network_security_config: system CAs only, no cleartext. |
| KyDrive-for-Android | HTTPS transport | KyDrive-for-Android:app/src/main/java/org/kysecurity/drive/core/Api.kt:146; core/Tls.kt:85-89 @ 60e755b | HttpsURLConnection with platform SSLContext("TLS") (Conscrypt). No group or cipher override. minSdk 31, targetSdk 36. | n/a | HNDL (confidentiality) | Whether Android's Conscrypt offers X25519MLKEM768, and on which API level, is unverified. |
| KyDrive-for-Android | App-lock PIN verifier | KyDrive-for-Android:app/src/main/java/org/kysecurity/drive/lock/AppLock.kt:245-262; lock/Device.kt:77-89 @ 60e755b | PBKDF2-HMAC-SHA256, 150,000 iterations, 256-bit, plus a pepper (HMAC-SHA256 under a Keystore key) | Device Keystore | n/a | |
| KyDrive-for-Android | Biometric unlock gate | KyDrive-for-Android:app/src/main/java/org/kysecurity/drive/lock/Device.kt:105-133 @ 60e755b | AES-GCM Keystore key that needs BIOMETRIC_STRONG and is invalidated on enrolment change | Device Keystore | symmetric, PQ-safe at 256-bit | No key size is set (Keystore default; unverified whether it is 256). |
| KyDrive-for-Android | Release signing | KyDrive-for-Android:.github/workflows/ci.yml:97 @ 60e755b | None: CI builds are unsigned ("nothing here is published") | n/a | n/a | No Play or app signing config in the repo. |
| KyDrive-for-Android | Client-side file encryption | n/a | None. Files go to the server in plaintext over TLS, and the server seals them. | n/a | n/a | |
| kydrive-desktop | Token, device key and pin storage | kydrive-desktop:core/cmd/kydrive-sync/credential.go:36,61,75; daemon.go:28 @ 9596d67 | OS keyring via zalando/go-keyring v0.2.8 (libsecret over D-Bus, macOS Keychain, Windows Credential Manager via wincred v1.2.3) | OS keyring | n/a | The device key is a software P-256 key stored as PKCS#8 in the keyring, not a platform key (core/AGENTS.md:29). |
| kydrive-desktop | Device request signing | kydrive-desktop:core/link/link.go:53; core/api/sign.go:24-38 @ 9596d67 | ECDSA P-256 / SHA-256 (`kydrive-request-v1`) | Desktop (keyring) | forgery-only (signatures) | |
| kydrive-desktop | TLS pinning and rollover | kydrive-desktop:core/api/tlspin.go:83-116,156-200 @ 9596d67 | SPKI SHA-256 pin through VerifyConnection. Ed25519 rollover verify (stdlib). | Server identity key | forgery-only (signatures) | |
| kydrive-desktop | HTTPS transport | kydrive-desktop:core/cmd/kydrive-sync/daemon.go:80-81; core/go.mod:3-5 @ 9596d67 | Go stdlib default http.Transport; `godebug fips140=on` in go.mod; no CurvePreferences | n/a | PQ-hybrid already | go 1.26.11 enables X25519MLKEM768 by default (Go 1.24+). The build toolchain is not pinned in go.mod (no toolchain line). The server edge must support the hybrid. |
| kydrive-desktop | Browser link PKCE | kydrive-desktop:core/link/link.go:38,63 @ 9596d67 | S256 (SHA-256) and crypto/rand | n/a | n/a | |
| kydrive-desktop | Release signing | kydrive-desktop:.github/workflows/ci.yml:229-276,368-372,441-485 @ 9596d67 | macOS: Developer ID codesign and notarization, only when secrets are set. Windows MSIX unsigned. SHA256SUMS plus attest-build-provenance v4.2.2 (Sigstore keyless) on every release. | Apple Developer ID cert (secret), GitHub OIDC | forgery-only (signatures) | |
| kydrive-desktop | Client-side file encryption | n/a | None | n/a | n/a | |
| KyNotes-server (web client) | Note, comment, attachment and container-meta encryption (E2EE) | KyNotes-server:web/src/crypto.ts:97-107,136-164 @ 88c85c8; Go port internal/notecrypto/notecrypto.go:1-9,61-65 | AES-256-GCM under HKDF-SHA256(container key, salt=containerID, `kynotes/content/v2`); AAD binds container, ID and kind | Browser or MCP client. The 32-byte container key never reaches the server in plaintext. | symmetric, PQ-safe at 256-bit | The server stores ciphertext only. |
| KyNotes-server (web client) | Team container-key envelopes (key distribution) | KyNotes-server:web/src/teamKeys.ts:10-16,26-27,65-93 @ 88c85c8; Go reference internal/teamkeys/envelope.go:18,36 | RFC 9180 HPKE mode_auth: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. Libraries: @hpke/core 1.10.1, @hpke/dhkem-x25519 1.8.1, @noble/curves 2.4.0. Go side: cloudflare/circl v1.6.5. Legacy v2 (read only): custom ephemeral+static X25519 → HKDF → ChaCha20-Poly1305 (teamKeys.ts:129; envelope_legacy.go). | Recipients: each member's long-term X25519 identity. Sender auth: the sender's static X25519 key. | HNDL (confidentiality) | Highest-priority item in this part. A recorded envelope (stored on the server) plus a CRQC gives the container key and so every note. Sender authentication in auth mode is classical too, so forgery applies as well. No PQ plan in the repo. |
| KyNotes-server (web client) | Identity private key, password copy | KyNotes-server:web/src/teamKeys.ts:18,139-142; crypto.ts:72-80 @ 88c85c8; internal/teamkeys/identity.go:15-29 | AES-256-GCM under userKEK = HKDF(PBKDF2-HMAC-SHA256(password, 600,000 iterations), `kynotes/user-kek/v1`) | User's password. The server stores the wrapped copy. | symmetric, PQ-safe at 256-bit | Offline guessing against the password is the real bound. |
| KyNotes-server (web client) | Identity recovery-code copy | KyNotes-server:web/src/recovery.ts:11-12,81,98 @ 88c85c8; crypto.ts:61-69 | 128-bit random code → PBKDF2-SHA256, 600,000 iterations → AES-256-GCM | User (offline code) | symmetric, 128-bit: Grover → ~64-bit, review | The secret has 128 bits of entropy. The wrap key is 256 bits. |
| KyNotes-server (web client) | Device linking (moves the identity private key to a new browser) | KyNotes-server:web/src/linking.ts:1-71 @ 88c85c8 | HPKE mode_auth X25519 (same suite) between one-time X25519 keys. 6-digit SAS check code. | One-time keys in memory | HNDL (confidentiality) | A recorded link bundle plus a CRQC exposes the identity private key. It travels over TLS too. |
| KyNotes-server (web client) | Login secret (server never sees the password) | KyNotes-server:web/src/crypto.ts:72-86; internal/auth/derive.go:7-21 → ky-primitives derive @ b55ca6d | PBKDF2-HMAC-SHA256 600,000 iterations (100,000 legacy floor) → HKDF `kynotes/auth/v1` | Client. The server stores Argon2id of it. | n/a | |
| KyNotes-server | Login-secret and recovery-code verifiers | KyNotes-server:internal/auth/hash.go:21-30 @ 88c85c8 | Argon2id (ky-primitives password, m=64 MiB, t=3, p=4) | Server DB | n/a | Legacy scrypt verifiers are refused. |
| KyNotes-server (web client) | Public share links | KyNotes-server:web/src/crypto.ts:263-271; internal/httpapi/share_link_routes.go:56-61 @ 88c85c8 | Random 256-bit AES-256-GCM key in the URL fragment. Server token is 32 random bytes, stored as SHA-256. | Link holder (fragment) | symmetric, PQ-safe at 256-bit | |
| KyNotes-server | Session, CSRF, pairing and setup tokens | KyNotes-server:internal/auth/session.go:49-55; csrf.go:19-42; pairing.go:34-62; internal/httpapi/setup_token.go:44 @ 88c85c8 | Random tokens stored as SHA-256. HMAC-SHA256 CSRF and pairing tokens. Pairing and server-salt secrets are 32 bytes (config.go:193-203). | Server | symmetric, PQ-safe at 256-bit | |
| KyNotes-server | SSO ID token and logout token | KyNotes-server:internal/sso/sso.go:346; internal/auth/sso_logout.go:18 @ 88c85c8 | ky-primitives oidcverify, RS256 pinned | KySignOn / KyIdentity | forgery-only (signatures) | |
| KyNotes-server | Directory webhooks | KyNotes-server:internal/httpapi/sso_directory.go:69-71 @ 88c85c8 | syncauth HMAC-SHA256 | Shared secret | symmetric, PQ-safe at 256-bit | The floor depends on configuration (unverified for KyNotes). |
| KyNotes-server | Web Push reminders (VAPID) | KyNotes-server:internal/webpush/webpush.go:1-2,65-76,108-112 @ 88c85c8; replica copy internal/app/replica_config.go:94 | VAPID ES256 (ECDSA P-256) JWT. Pushes are content-free, so there is no RFC 8291 payload encryption. | Server: `<data>/secrets/vapid.key` | forgery-only (signatures) | |
| KyNotes-server | Multi-mode PostgreSQL archive | KyNotes-server:internal/backup/pg_archive.go:19-22,64-72; cmd/kynotes-server/postgres_backup.go:98-106 @ 88c85c8 | 1 MiB AES-256-GCM frames under HKDF-SHA256(backup key, per-archive salt, `kynotes pg archive v1`), random nonces (NewGCMWithRandomNonce) | Operator: 32-byte key in `KYNOTES_PG_BACKUP_KEY_FILE` | symmetric, PQ-safe at 256-bit | This is the native PG backup. It is not pg_dump and not age. |
| KyNotes-server | Recovery capsule backups | KyNotes-server:internal/backup/service.go:92,225; internal/backup/payload.go:313 @ 88c85c8 | ky-primitives capsule: HPKE X-Wing / HKDF-SHA256 / AES-256-GCM | Suite recovery key (custodians) | PQ-hybrid already | |
| KyNotes-server | Offline capsule restore from custodian shares | KyNotes-server:cmd/kynotes-server/backup.go:180-188 @ 88c85c8 | Shamir combine (ky-primitives shamir) → recoverykey.Combine → X-Wing private key | Custodians (cards) | n/a | Shamir is information-theoretic. |
| KyNotes-server | Offsite mirror: SFTP | ky-primitives:offsite/sftp.go:55-80 @ offsite/v0.3.0 (KyNotes go.mod pins v0.3.0) | x/crypto/ssh v0.59.0 with SupportedAlgorithms; KEX prefers mlkem768x25519-sha256 (x/crypto ssh/common.go:61-62,86-87) | SSH host and user keys (operator) | PQ-hybrid already | Applies when the server offers mlkem768x25519. Host and user key signatures (Ed25519, ECDSA, RSA-2048+) are forgery-only. |
| KyNotes-server | Offsite mirror: SMB | KyNotes-server:internal/config/blob_target.go:48-52 @ 88c85c8; offsite/smb.go:89 @ offsite/v0.3.0 | NTLMv2 (MD4, HMAC-MD5, RC4 in go-smb2). Refused under fips140=on. | Operator password | n/a | Legacy and classical-broken regardless of quantum. |
| KyNotes-server | Object storage (S3) | KyNotes-server:internal/blobstore/objects.go:22-40; internal/config/blob_target.go:54 @ 88c85c8 | HTTPS-only S3, SigV4; Go default TLS | Operator | PQ-hybrid already | Ciphertext only. Applies when the peer supports the hybrid. |
| KyNotes-server | MCP bridge client (E2EE client in Go) | KyNotes-server:cmd/kynotes-mcp/client.go:103-115; trust.go:180-202 @ 88c85c8 | X25519 identity (crypto/ecdh), OpenIdentity (AES-256-GCM), OpenEnvelope (HPKE auth X25519 via circl) | User's machine (password) | HNDL (confidentiality) | Same envelope exposure as the web client. |
| KyNotes-server | Release image signing | KyNotes-server:.github/workflows/release-image.yml:160; ci.yml:329 @ 88c85c8 | attest-build-provenance v4.2.2 (Sigstore keyless) | GitHub OIDC | forgery-only (signatures) | |
| kynotes-desktop | (all) | gh api repos/Busnes-app/kynotes-desktop git tree @ b357111 | No code: the repo holds only README.md and LICENSE ("offline, end-to-end encrypted notes") | n/a | n/a | One commit; no branches or PRs. |
| KyRecovery-server | Suite recovery keypair generation and split (ceremony) | KyRecovery-server:cmd/ceremony-wasm/main.go:3-6,21-25 @ 45dfe28 → ky-primitives:recoverykey/recoverykey.go:5-27 | X-Wing (ML-KEM-768 + X25519) keypair from a 32-byte seed, through crypto/hpke. The seed is Shamir-split k-of-n (2 ≤ k ≤ n ≤ 255). | Runs in the operator's browser tab (WASM). Custodians hold the shares. The server never holds the private key. | PQ-hybrid already | |
| KyRecovery-server | Recovery public-key import and rotation | KyRecovery-server:internal/server/recoverykey.go:17-57 @ 45dfe28 | Parses and stores the X-Wing public key and topology. The body has no field for shares. | Server stores the public key only | n/a | Products pin its key ID at pairing. |
| KyRecovery-server | Capsule deposit (blind store) | KyRecovery-server:internal/server/deposit.go:68-115; verify.go:51 @ 45dfe28 | `capsule.ReadUnverifiedManifest`, then SHA-256 of the container. No decryption. | Products seal to the recovery key. KyRecovery holds only ciphertext. | PQ-hybrid already | The manifest is unsigned and only readable unverified at the server (see Gaps). |
| KyRecovery-server | Stored credentials (S3/SFTP/SMB secrets, etc.) | KyRecovery-server:internal/secrets/secrets.go:1-6,66-113; internal/crypto/envelope.go:14-60 @ 45dfe28 | AES-256-GCM under HKDF-SHA256(server key, `kyrecovery/db-secrets/v1`) (x/crypto/hkdf) | Server: 32-byte `KYRECOVERY_SECRET_KEY` or 0600 key file | symmetric, PQ-safe at 256-bit | |
| KyRecovery-server | Audit ledger chain | KyRecovery-server:internal/audit/chain.go:32,76; secrets.go:76-77 @ 45dfe28 | ky-primitives auditchain, keyed hash chain (HMAC-SHA256 under `kyrecovery/audit-ledger/v1`; the HMAC is unverified in auditchain source) | Server key | symmetric, PQ-safe at 256-bit | |
| KyRecovery-server | Pairing codes and bearer tokens | KyRecovery-server:internal/db/db.go:493-506 @ 45dfe28 | Pairing code HMAC-SHA256 (`kyrecovery/pairing-code/v1`). Bearer tokens stored as SHA-256. | Server | symmetric, PQ-safe at 256-bit | |
| KyRecovery-server | Admin login | KyRecovery-server:internal/auth/auth.go:224-231,388-461,583 @ 45dfe28 | Argon2id (ky-primitives password). OIDC via go-oidc v3.21.0 / go-jose v4.1.9 with PKCE S256. RSA JWKS 2048+ (docs/STRONG-CRYPTO.md:30-31). | IdP and server DB | forgery-only (signatures) | |
| KyRecovery-server | Managed signed directory | KyRecovery-server:internal/server/installer_directory.go (syncauth) @ 45dfe28 | syncauth HMAC-SHA256, at least 16 bytes (docs/STRONG-CRYPTO.md:85) | Shared secret | symmetric, 128-bit: Grover → ~64-bit, review | Floor only. |
| KyRecovery-server | Replication to S3 / R2 / MinIO | KyRecovery-server:internal/replication/s3.go:29-49 @ 45dfe28 | HTTPS with SigV4 (aws-sdk-go-v2 v1.48.0 signer); Go default TLS | Operator access keys | PQ-hybrid already | Applies when the peer supports the hybrid. Payload is already X-Wing-sealed capsules. |
| KyRecovery-server | Replication over SFTP (two clients) | KyRecovery-server:internal/replication/sftp.go:89-91,222-243 @ 45dfe28; offsite v0.3.0 sftp.go:55-80 | x/crypto/ssh v0.59.0 SupportedAlgorithms (mlkem768x25519-sha256 first). Host and user keys RSA-2048+, ECDSA P-256/384/521, or Ed25519. | Operator SSH keys and pinned host fingerprint | PQ-hybrid already | Applies when the server offers mlkem768x25519. Key signatures are forgery-only. |
| KyRecovery-server | Replication over SMB | KyRecovery-server:internal/replication/smb.go:67; offsite.go:188-192 @ 45dfe28 | NTLMv2 (cloudsoda/go-smb2). Refused under fips140=on. | Operator password | n/a | Legacy. |
| KyRecovery-server | Restic rest-server (bulk repos of products) | KyRecovery-server:docker-compose.restic.yml (rest-server 0.14.0, `--tls --append-only --private-repos`); cmd/kyrecovery/app/app.go:83 @ 45dfe28 | rest-server TLS (its own Go build) plus htpasswd. KyRecovery only mounts the data read-only for status. | Repo passwords are the products' (KyDrive: HKDF of its deployment key) | HNDL (confidentiality) | rest-server's Go version and TLS groups are unverified, which is why HNDL is assumed. Restic repo data itself is symmetric. |
| KyRecovery-server | Inbound HTTPS | KyRecovery-server:docs/STRONG-CRYPTO.md:91,101-105 @ 45dfe28 | Serves internal HTTP behind a TLS proxy (TLS 1.2/1.3, RSA-2048+ or P-256+) | Operator proxy | HNDL (confidentiality) | Depends on the proxy (unverified). |
| KyRecovery-server | Release image signing | KyRecovery-server:.github/workflows/release-image.yml:164; ci.yml:279 @ 45dfe28 | attest-build-provenance v4.2.2 (Sigstore keyless) | GitHub OIDC | forgery-only (signatures) | |
| kyguard-server | Secret-envelope DEK wrap (to broker, user and recovery recipients) | kyguard-server:internal/pqcrypto/seal.go:45 @ 37b302b (Seal), :68 (Open) | HPKE base mode, X-Wing KEM (`hpke.MLKEM768X25519` via ky-primitives `recoverykey`, ky-primitives:recoverykey/recoverykey.go:42 @ 9f4bc5875e04), HKDF-SHA256, AES-256-GCM, info `kyguard/1/dek-wrap` | Recipient X-Wing private keys: broker key file, user CLI key file, KyRecovery custodians (Shamir) | PQ-hybrid already | Matches spec §3.1 and DEK-wrap rule (docs/SPEC.md:55, :81 @ 37b302b). enc is 1120 bytes |
| kyguard-server | Secret payload encryption | kyguard-server:internal/pqcrypto/sealenv.go @ 37b302b (uses seal.go AES-GCM) | AES-256-GCM, random 32-byte DEK, 12-byte nonce, framed AAD | DEK exists only wrapped per recipient | symmetric, PQ-safe at 256-bit | Spec §3.1 line 56 |
| kyguard-server | Signed objects (manifests, tx, envelopes, receipts, PoP) | kyguard-server:internal/pqcrypto/sig.go:64-70 (verify), :88-128 (keygen/sign) @ 37b302b | Hybrid ML-DSA-65 (stdlib `crypto/mldsa`, empty context) plus pure Ed25519 over SHA-256 domain digest. Both must verify | Custodians (offline Argon2id-wrapped key files), brokers, users, per-tx `cnf` keys | PQ-hybrid already | `alg: "mldsa65+ed25519"`, spec lines 68-70 |
| kyguard-server | Custodian/user key-file wrap (kyguard-cli) | kyguard-server:internal/cli/keyfile.go:85 (Argon2id 32-byte KEK), :143-147 (AES-GCM) @ 37b302b | Argon2id (ky-primitives `password.DefaultParams`, cmd/cli/main.go:30) and AES-256-GCM | Human passphrase | symmetric, PQ-safe at 256-bit | Spec line 59 and line 123 (hardware tokens wait for ML-DSA support) |
| kyguard-server | Broker key file (TLS, hybrid signing and X-Wing seeds) | kyguard-server:internal/broker/keys.go:46-80 @ 37b302b | Four raw seeds in a 0600 hex file (ky-primitives `keyfile`), not encrypted | Broker host | n/a | At-rest protection is file permission only, per spec §4.1 (line 261) |
| kyguard-server | Internal broker CA (X.509) | kyguard-server:internal/brokerproto/ca.go:69-84 @ 37b302b (CA, 20-year life, ca.go:39) | Ed25519 self-signed CA | Control Plane `data/broker-ca.key` (also carried in backup capsules) | forgery-only (signatures) | The spec names an internal CA (line 119, 263) but no algorithm |
| kyguard-server | Broker listener leaf certificate and broker client certificates from CSR | kyguard-server:internal/brokerproto/ca.go:167-216 @ 37b302b | Ed25519 leaf (1 year, ca.go:41). Broker client certificate is Ed25519 from the CSR with broker_id bound (10 years, ca.go:40) | CP (leaf), broker (client key = TLS seed) | forgery-only (signatures) | |
| kyguard-server | Broker listener TLS / mTLS (`/broker/v1/*`) | kyguard-server:internal/brokerproto/tls.go:13, :21-25 (server), :42-44 (client) @ 37b302b; cmd/server/guard.go:152 | TLS 1.3 only, `CurvePreferences: [X25519MLKEM768, X25519]`, `VerifyClientCertIfGiven`. Client pins the CA by SHA-256 and checks the hostname | Ephemeral | PQ-hybrid already | Explicit override, matching spec line 263. A peer without ML-KEM falls back to X25519. Under `GODEBUG=fips140=on` the effect on X25519 is unverified |
| kyguard-server | Broker pairing token | kyguard-server:internal/brokerproto/listener.go:66, :86 @ 37b302b; internal/api/broker_handlers.go:90 | 32-byte random secret, stored as SHA-256. Token also carries the CA SHA-256 pin | CP DB (hash only) | n/a | Spec lines 265-269. Sent over the PQ-hybrid listener |
| kyguard-server | SSH connector to Linux targets (branch only, PR #14) | kyguard-server:internal/connectors/sshpasswd/sshpasswd.go:50-80 @ d6b7781 (branch `kyguard/connector-ssh`) | `x/crypto/ssh` v0.59.0 `ClientConfig` with no `KeyExchanges` or `HostKeyAlgorithms`, so library defaults apply. The default KEX list starts with `mlkem768x25519-sha256` (golang.org/x/crypto@v0.59.0 ssh/common.go:98-106). Host key is pinned by SHA-256 of the wire key | Ephemeral KEX. Target host key is pinned | PQ-hybrid already | Against OpenSSH ≥9.9/10.0 the result should be mlkem768x25519-sha256 (OpenSSH 10.0 made it the default: https://www.openssh.com/txt/release-10.0). Older targets fall back to curve25519/ECDH/DH14-SHA1. The default list includes `diffie-hellman-group14-sha1`. Not on main |
| kyguard-server | SSH target host-key authentication (branch) | same file :50-58 @ d6b7781 | Whatever host-key alg is negotiated (Ed25519/ECDSA/RSA), pinned by fingerprint | Target | forgery-only (signatures) | The pin limits this to live-MITM forgery of the pinned key |
| kyguard-server | AD LDAPS connector TLS (branch only, PR #13) | kyguard-server:internal/connectors/adldaps/adldaps.go:61 @ f8b4fd1 (branch `kyguard/connector-ad`) | TLS ≥1.2, `RootCAs` = descriptor `tls_ca_pem`, default curves | Ephemeral; AD DC cert | PQ-hybrid already (only if the DC negotiates it), otherwise HNDL (confidentiality) | Windows DCs are unlikely to offer X25519MLKEM768 (unverified). Carries `P_old`/`P_new` |
| kyguard-server | Audit hash chain | kyguard-server:internal/store/auditchain.go:55-194 @ 37b302b; key: internal/config/config.go:81 | HMAC-SHA256 chain (ky-primitives:auditchain/auditchain.go:281 @ 9f4bc5875e04). Key = HKDF-SHA256(encryption.key, "kyguard:auditchain", 32) | CP `data/encryption.key` | symmetric, PQ-safe at 256-bit | Spec line 455. No external anchor (line 463, D.8 line 644) |
| kyguard-server | Operation-intent outcome MAC | kyguard-server:internal/store/intents.go:39-43 @ 37b302b | HMAC-SHA256, HKDF key "kyguard:intent-outcome" | CP | symmetric, PQ-safe at 256-bit | |
| kyguard-server | Deployment encryption key (TOTP factors, recovery token, replica fingerprint) | kyguard-server:internal/config/config.go:204-209; internal/auth/totp.go:36; internal/backup/settings.go:79; internal/config/replica.go:67 @ 37b302b | 32-byte key. AES-256-GCM via `recoveryclient.NewAESGCMSealer`. HMAC-SHA256 replica fingerprints | CP `data/encryption.key` or `KY_ENCRYPTION_KEY` | symmetric, PQ-safe at 256-bit | |
| kyguard-server | Generic AES-GCM / HMAC helpers | kyguard-server:internal/crypto/crypto.go:27-90 @ 37b302b | AES-256-GCM (exactly 32-byte key), HMAC-SHA256 DeriveKey, HMAC floor 16 bytes (crypto.go:22) | CP | symmetric, PQ-safe at 256-bit | |
| kyguard-server | Session tokens and CLI login | kyguard-server:internal/auth/session.go:99, :150; internal/api/cli_login.go:70 @ 37b302b | Random token stored as SHA-256. CLI login uses PKCE S256 | DB hash | n/a | |
| kyguard-server | Password hashing (break-glass) | kyguard-server:cmd/server/breakglass.go:69; internal/api/auth_handlers.go:119 @ 37b302b | Argon2id (ky-primitives `password`) | DB | n/a | |
| kyguard-server | TOTP (break-glass and step-up) | kyguard-server:internal/auth/totp.go:46, :91 @ 37b302b | RFC 6238 HMAC-SHA1 (ky-primitives:totp/totp.go:117) | Sealed in `mfa_factors` | symmetric, PQ-safe at 256-bit | The key is a 160-bit-class secret. HMAC is not a quantum concern |
| kyguard-server | OIDC ID-token verification (SSO) | kyguard-server:internal/sso/jwks_strength.go:56-61; internal/sso/oauth.go:38-54 @ 37b302b | go-oidc v3.21.0 / go-jose v4.1.9. IdP JWKS RSA must be ≥2048 bits. HTTPS required under fips140 | External IdP (KyIdentity) | forgery-only (signatures) | RS256/ES256 per IdP |
| kyguard-server | Backup capsule | kyguard-server:cmd/server/main.go:458; internal/api/backup_handlers.go:210 @ 37b302b | ky-primitives `recoveryclient.Seal`: X-Wing HPKE plus AES-256-GCM | KyRecovery custodians (Shamir) | PQ-hybrid already | Includes `encryption.key`, `recovery.pub`, and the broker CA key/cert per spec line 469 (the CA-key inclusion was not separately verified) |
| kyguard-server | Release provenance | kyguard-server:.github/workflows/ci.yml:429 @ 37b302b | GitHub `attest-build-provenance` (Sigstore) | GitHub/Fulcio | forgery-only (signatures) | ECDSA P-256 Fulcio certs (unverified) |
| KyDNS-server | DNSSEC validation (resolver-side, no signing) | KyDNS-server:internal/dnssec/validator.go:671-675 @ cdaae83 | Accepts alg 8 RSASHA256, 10 RSASHA512, 13 ECDSAP256SHA256, 14 ECDSAP384SHA384, 15 ED25519, 16 ED448. Refuses RSA/SHA-1 (5/7) | Zone owners and root (IANA anchors, internal/dnssec/anchors.go) | forgery-only (signatures) | Verifies via miekg/dns v1.1.73 plus circl v1.6.5 Ed448 (internal/dnssec/ed448.go:25) |
| KyDNS-server | DS digest selection | KyDNS-server:internal/dnssec/validator.go:680-705 @ cdaae83 | SHA-256 / SHA-384. SHA-1 counts only when no stronger DS exists | n/a | n/a | |
| KyDNS-server | NSEC3 hashing | KyDNS-server:internal/dnssec/denial.go:208 @ cdaae83 | SHA-1 (protocol-fixed), iteration cap | n/a | n/a | |
| KyDNS-server | DoT upstream client | KyDNS-server:internal/upstream/dot.go:28, :94-101 @ cdaae83 | TLS ≥1.2, system roots, default curves | Ephemeral; upstream resolver cert | PQ-hybrid already (only if the upstream negotiates it), otherwise HNDL (confidentiality) | Public resolvers' ML-KEM support is unverified |
| KyDNS-server | DoH upstream client | KyDNS-server:internal/upstream/doh.go:30-36 @ cdaae83 | Same `tlsConfig` as DoT | Same | PQ-hybrid already (if upstream supports it), otherwise HNDL (confidentiality) | |
| KyDNS-server | Replica node identity | KyDNS-server:internal/replica/identity.go:24-39 @ cdaae83 | Ed25519 seed in a raw keyfile. Fingerprint = SHA-256(pub) | Each node's data dir | forgery-only (signatures) | |
| KyDNS-server | Replica TLS (mutual, pinned) | KyDNS-server:internal/replica/transport.go:35-49 (self-signed Ed25519, 100-year), :59-74 (config) @ cdaae83 | TLS 1.3, `RequireAnyClientCert`, Ed25519 fingerprint pin, no CurvePreferences (Go default) | Ephemeral | PQ-hybrid already | Zone/config replication over this channel |
| KyDNS-server | Replica pairing code | KyDNS-server:internal/replica/pairing.go:20-25, :74; pairing_exchange.go:58-73 @ cdaae83 | 80-bit random code sent only after the operator confirms the fingerprint, over the pinned TLS 1.3 | In memory | n/a | No PAKE (docs/superpowers/specs/2026-08-13-kydns-pake-selection.md @ cdaae83) |
| KyDNS-server | Health-probe HTTPS | KyDNS-server:internal/health/checker.go:235 @ cdaae83 | `InsecureSkipVerify: true` transport for probes, default curves | n/a | n/a | Reachability only, no secrets |
| KyDNS-server | Recovery-token sealing at rest | KyDNS-server:internal/backup/backup.go:47-51 @ cdaae83 | AES-256-GCM, 32-byte `keyfile` | Node data dir | symmetric, PQ-safe at 256-bit | |
| KyDNS-server | Backup capsule | KyDNS-server:internal/backup/backup.go:281 @ cdaae83 | `recoveryclient.Seal` (X-Wing HPKE, AES-256-GCM), ky-primitives v0.10.1 | KyRecovery custodians | PQ-hybrid already | |
| KyDNS-server | Admin password and session/CSRF | KyDNS-server:internal/auth/password.go:21; internal/auth/session.go:134 @ cdaae83 | Argon2id. 32-byte random session and CSRF IDs | DB | n/a | |
| KyDNS-server | OIDC SSO | KyDNS-server:internal/auth/sso.go:142; internal/auth/jwks_strength.go @ cdaae83 | PKCE S256, go-oidc / go-jose JWT verify, JWKS RSA floor | External IdP | forgery-only (signatures) | |
| KyDNS-server | MCP/agent API tokens | KyDNS-server:internal/registry/registry.go:455-465 @ cdaae83 | 32-byte random, stored as SHA-256 | DB hash | n/a | |
| KyDNS-server | Release signing | KyDNS-server:.github/workflows/release.yml:185, :281 @ cdaae83; docs/VERIFYING-RELEASES.md:14-30 | Sigstore SLSA provenance plus SHA256SUMS | GitHub/Fulcio | forgery-only (signatures) | `ProtonMail/go-crypto` v1.5.2 is an indirect dep (go.mod:31), probably from packaging tooling. Not seen imported by product code |
| KyDNS-server | TSIG / zone transfer | none found @ cdaae83 | not implemented | n/a | n/a | No TSIG, AXFR or IXFR serving in code. AXFR is mentioned only in the validation spec (docs/superpowers/specs/2026-11-15-dnssec-validation-design.md:80) |
| KyCalendar | Content-encryption key library (not wired) | KyCalendar:internal/contentkey/suite.go:21-23, :94-123 @ 7bce306; docs/CONTENT-ENCRYPTION-FORMAT.md:15-29 | HPKE X-Wing (`MLKEM768X25519`, KEM 0x647a), HKDF-SHA256, AES-256-GCM. Account, calendar, worker and previous-key wraps | Planned: user account seeds via unlock slots | PQ-hybrid already | "Nothing in the server uses these formats until build step CE2" (CONTENT-ENCRYPTION-FORMAT.md:8). No importer of `internal/contentkey` on main |
| KyCalendar | Unlock-slot passphrase KDF (not wired) | KyCalendar:internal/contentkey/slots.go:76 @ 7bce306 | Argon2id → 32 bytes, then AES-256-GCM | User passphrase | symmetric, PQ-safe at 256-bit | x/crypto v0.59.0 (go.mod:39) |
| KyCalendar | At-rest sealing of subscription feed URLs and video guest URLs | KyCalendar:internal/feed/feed.go:128-133; internal/api/video_meetings.go:245, :279 @ 7bce306 | AES-256-GCM under HMAC-SHA256-derived subkeys of the 32-byte encryption key (config.go:382-396) | Server `encryption.key` / `KY_ENCRYPTION_KEY` | symmetric, PQ-safe at 256-bit | |
| KyCalendar | Recovery-token sealing | KyCalendar:internal/backup/settings.go:113 @ 7bce306 | AES-256-GCM (`NewAESGCMSealer`) | Server | symmetric, PQ-safe at 256-bit | |
| KyCalendar | CalDAV / MCP auth with app passwords | KyCalendar:internal/apppass/apppass.go:18-49; internal/api/dav_auth.go:206-220; internal/api/mcp.go:81 @ 7bce306 | HTTP Basic carrying a 256-bit random secret, stored as SHA-256, constant-time compare | DB hash | n/a | Transport is the operator proxy's TLS |
| KyCalendar | Booking confirmation tokens | KyCalendar:internal/api/booking.go:598, :678 @ 7bce306 | Random token, SHA-256 stored, constant-time compare | DB hash | n/a | No "iCal share token" feature found on main (grep for share/public ics) |
| KyCalendar | Session CSRF, PoW challenge, SSO nonce cookie | KyCalendar:internal/auth/session.go:131-135; internal/auth/pow.go:127; internal/api/sso_handlers.go:45, :268 @ 7bce306 | HMAC-SHA256, session secret ≥16 bytes (config.go:374) | Server session secret | symmetric, PQ-safe at 256-bit | 16-byte floor means imported secrets may be 128-bit (Grover ~64-bit applies to a key search, but HMAC forgery is not Grover-limited this way). Review |
| KyCalendar | Inbound KySignOn directory webhook | KyCalendar:internal/api/sso_handlers.go:447-478; internal/sso/kysignon.go:39-53 @ 7bce306 | HMAC-SHA256 `X-Signature-SHA256` plus timestamp, secret ≥16 bytes (config.go:378) | Shared with KyIdentity | symmetric, PQ-safe at 256-bit | Still live here. kyguard-server's docs say the same secret is ignored there |
| KyCalendar | KyIdentity SCIM/directory and KyPost iTIP events | KyCalendar:internal/api/installer_directory.go:36; internal/api/tenant_directory.go:62; internal/kypost/kypost.go:202 @ 7bce306 | ky-primitives `syncauth` HMAC-SHA256 (ky-primitives:syncauth/syncauth.go:115 @ b5f5853be771) plus replay guard | Shared secret | symmetric, PQ-safe at 256-bit | |
| KyCalendar | Replica config fingerprint | KyCalendar:internal/config/replica.go:145 @ 7bce306 | HMAC-SHA256 | Server | symmetric, PQ-safe at 256-bit | |
| KyCalendar | OIDC discovery and token TLS | KyCalendar:internal/sso/discovery.go:68 @ 7bce306 | TLS ≥1.2, optional private CA, default curves | Ephemeral; IdP cert | PQ-hybrid already (if the IdP supports it), otherwise HNDL (confidentiality) | |
| KyCalendar | OIDC ID-token verification | KyCalendar:internal/sso/jwks_strength.go; internal/sso/oauth.go @ 7bce306 | go-oidc v3.21.0 / go-jose v4.1.9 | IdP | forgery-only (signatures) | |
| KyCalendar | Password hashing | KyCalendar:cmd/server/bootstrap.go:48; internal/api/password_handlers.go:55-60 @ 7bce306 | Argon2id (ky-primitives v0.10.2-0.20261124022836-b5f5853be771) | DB | n/a | |
| KyCalendar | Backup capsule | KyCalendar:cmd/server/main.go:652; internal/api/backup_handlers.go:239 @ 7bce306 | `recoveryclient.Seal` X-Wing HPKE | KyRecovery custodians | PQ-hybrid already | |
| KyCalendar | Release/image provenance | KyCalendar:.github/workflows/ci.yml:468; release-image.yml:204 @ 7bce306 | Sigstore attest-build-provenance | GitHub/Fulcio | forgery-only (signatures) | |
| go-webdav (fork, branch kycalendar) | CalDAV/WebDAV protocol library | go-webdav @ 7f1337b (no `crypto/` imports in non-test Go files) | none | n/a | n/a | Auth lives in KyCalendar `dav_auth.go`. KyCalendar vendors the fork at third_party/go-webdav, commit 7f9258bf, an ancestor of 7f1337b (third_party/go-webdav.commit @ 7bce306) |
| KyPulse-server | Outbound HTTPS (health polls, TLS-expiry checks, notifications, KyYard, KyPost) | KyPulse-server:internal/egress/egress.go:81 @ 7a45d37; internal/poller/cert.go:25-54 | TLS ≥1.2, default curves | Ephemeral | PQ-hybrid already (peer-dependent), otherwise HNDL (confidentiality) | Notification tokens (ntfy/Gotify) travel in headers over this channel (internal/notify/notify.go:121) |
| KyPulse-server | Outbound alert webhooks | KyPulse-server:internal/notify/notify.go:110-124; internal/monitor/webhook.go:32-62 @ 7a45d37 | No payload signature. Optional Bearer token. Config sealed with AES-256-GCM | Admin config, sealed with the deployment key | symmetric, PQ-safe at 256-bit (at rest) | No HMAC webhook signing exists |
| KyPulse-server | KyPost send (signed) | KyPulse-server:internal/kypost/kypost.go:59-65 @ 7a45d37 | `syncauth` HMAC-SHA256 | Shared secret | symmetric, PQ-safe at 256-bit | |
| KyPulse-server | Inbound KySignOn webhook and directory | KyPulse-server:internal/sso/kysignon.go:85; internal/api/installer_directory.go:36 @ 7a45d37 | HMAC-SHA256 (≥16-byte secret, config.go:193); syncauth | Shared | symmetric, PQ-safe at 256-bit | |
| KyPulse-server | Sealed settings (webhook, mail, KyYard pairing, recovery token) | KyPulse-server:internal/monitor/webhook.go:32; internal/monitor/mail.go:65; internal/kyyard/pairing.go:46; internal/backup/settings.go:37 @ 7a45d37 | AES-256-GCM, 32-byte key (config.go:207-212) | Server `encryption.key` | symmetric, PQ-safe at 256-bit | |
| KyPulse-server | Audit hash chain | KyPulse-server:internal/store/audit.go:157-249; key config.go:59-62 @ 7a45d37 | HMAC-SHA256 (ky-primitives auditchain), separate 32-byte audit key | Server audit keyfile / `KYPULSE_AUDIT_KEY` | symmetric, PQ-safe at 256-bit | |
| KyPulse-server | Log-source pairing and ingest tokens | KyPulse-server:internal/api/sources.go:21, :82, :182-189; internal/sender/sender.go:125 @ 7a45d37 | 6-digit code and 32-byte token, both stored as SHA-256 | DB hash / sender state file | n/a | |
| KyPulse-server | Session/PoW/step-up MACs | KyPulse-server:internal/auth/pow.go:70; internal/api/sso_handlers.go:157, :182 @ 7a45d37 | HMAC-SHA256, 32-byte session.key (config.go:197) | Server | symmetric, PQ-safe at 256-bit | |
| KyPulse-server | Password hashing, OIDC, backup | KyPulse-server:internal/api/auth_handlers.go:99; internal/sso/oauth.go; cmd/server/main.go:539 @ 7a45d37 | Argon2id; go-oidc / go-jose; `recoveryclient.Seal` X-Wing | DB / IdP / custodians | n/a / forgery-only (signatures) / PQ-hybrid already | Three uses grouped into one row |
| KyPulse-server | Release provenance | KyPulse-server:.github/workflows/ci.yml:431; release-image.yml:166 @ 7a45d37 | Sigstore | GitHub | forgery-only (signatures) | |
| KyYard-server | Agent ↔ server transport TLS | KyYard-server:cmd/agent/main.go:203 @ 8148a97 | TLS ≥1.2, optional private CA, default curves | Ephemeral | PQ-hybrid already (Go↔Go both default to X25519MLKEM768), otherwise HNDL (confidentiality) | Agent commands and container logs. HNDL applies only if an intermediary proxy terminates TLS without ML-KEM (unverified) |
| KyYard-server | Server instance identity, challenge signing | KyYard-server:internal/agent/protocol/messages.go:132-144; internal/api/agent_connect.go:349; config.go:273 @ 8148a97 | Ed25519 (32-byte `instance.key` seed). Agent pins the fingerprint | Server data dir | forgery-only (signatures) | |
| KyYard-server | Agent identity: enroll, auth, key rotation | KyYard-server:internal/agent/client/enroll.go:50; connect.go:295, :694; internal/agent/protocol/sign.go:48-59 @ 8148a97 | Ed25519 signatures over domain-separated preimages | Agent host 0600 file (identity.go:214) | forgery-only (signatures) | |
| KyYard-server | Built-in local Docker agent key | KyYard-server:internal/api/local_docker.go:42-44 @ 8148a97 | Ed25519 from HMAC-SHA256(instance key, label) | Server | forgery-only (signatures) | |
| KyYard-server | Application env secrets, registry credentials, SSO provider configs, TOTP secrets at rest | KyYard-server:internal/store/application_secrets.go:53-66; internal/store/registries.go:45, :125; internal/api/provider_handlers.go:44, :122; internal/api/account_handlers.go:67, :116 @ 8148a97 | AES-256-GCM under the 32-byte encryption key or HMAC-derived subkeys | Server `encryption.key` | symmetric, PQ-safe at 256-bit | |
| KyYard-server | Container registry client TLS | KyYard-server:internal/registry/client.go:116 @ 8148a97 | TLS ≥1.2, default curves | Ephemeral | PQ-hybrid already (peer-dependent), otherwise HNDL (confidentiality) | Carries registry credentials |
| KyYard-server | Kubernetes API client | client-go v0.37.2 (go.mod) @ 8148a97 | kubeconfig TLS / mTLS, Go default curves | Cluster CA | PQ-hybrid already (if the apiserver's Go version is ≥1.24), otherwise HNDL (confidentiality) | Unverified per cluster |
| KyYard-server | Service tokens, pairing codes, recovery codes | KyYard-server:internal/store/agent_tokens.go:68-82; service_tokens.go:32-86; internal/auth/recovery.go:15 @ 8148a97 | Random, stored as SHA-256 | DB hash | n/a | |
| KyYard-server | Webhooks (KySignOn, directory) and session MACs | KyYard-server:internal/sso/kysignon.go:78; internal/api/installer_directory.go:40; internal/api/server.go:303-318; internal/auth/pow.go:70 @ 8148a97 | HMAC-SHA256 | Shared / server | symmetric, PQ-safe at 256-bit | |
| KyYard-server | Password hashing, TOTP, OIDC, backup | KyYard-server:cmd/server/main.go:410, :619; internal/auth/totp.go:10-20; internal/sso/oauth.go @ 8148a97 | Argon2id; RFC 6238; go-oidc; `recoveryclient.Seal` X-Wing | — | n/a / symmetric, PQ-safe at 256-bit / forgery-only (signatures) / PQ-hybrid already | Four uses grouped into one row |
| KyYard-server | Release provenance | KyYard-server:.github/workflows/ci.yml:493; release-image.yml:167 @ 8148a97 | Sigstore | GitHub | forgery-only (signatures) | |
| KQS | Installer/runner SSH key exchange (Go client) | KQS:internal/remote/ssh.go:79-86 @ 950c3f8; x/crypto v0.59.0 (KQS:go.mod) | `ssh.SupportedAlgorithms().KeyExchanges`: x/crypto v0.59.0 lists `mlkem768x25519-sha256` first, then curve25519-sha256, ECDH P-256/384/521, DH14/16-SHA256, DH-GEX-SHA256 (x/crypto ssh/common.go:86-95). | ephemeral, per connection | PQ-hybrid already (when the target sshd offers mlkem768x25519-sha256, OpenSSH 9.9+). HNDL (confidentiality) when it falls back to the classical KEX. | x/crypto has no sntrup761, so an OpenSSH 9.0–9.8 server negotiates classical curve25519. Under `GODEBUG=fips140=on` (the runner image sets it, KQS:Dockerfile:27) x/crypto registers only mlkem768x25519 and ECDH NIST, not curve25519 or DH (x/crypto ssh/kex.go:405-420). The installer overrides only the list and never removes ML-KEM. |
| KQS | SSH ciphers/MACs | KQS:internal/remote/ssh.go:81 @ 950c3f8 | `SupportedAlgorithms()` ciphers: AES-128/256-GCM, ChaCha20-Poly1305, AES-128/192/256-CTR; SHA-2 MACs | ephemeral session keys | symmetric, 128-bit: Grover → ~64-bit, review (AES-128-GCM is first in x/crypto's preference); AES-256 / ChaCha20 are symmetric, PQ-safe at 256-bit | Which cipher is negotiated depends on the server's order. |
| KQS | SSH host-key verification (pinning) | KQS:internal/remote/ssh.go:178-260; ssh_strength.go:13-44 @ 950c3f8 | Accepts Ed25519, ECDSA ≥224-bit, RSA ≥2048 (RSA-SHA2 only); certificate CA keys checked to the same floor. Prefers Ed25519 on first contact. | target sshd host key (target owner) | forgery-only (signatures) | TOFU pin plus an operator fingerprint check. No ML-DSA host keys (x/crypto adds ML-DSA only under go1.27 build tags, ssh/mldsa.go:5, while KQS builds with Go 1.26.11). |
| KQS | SSH user auth (operator key file or agent) | KQS:internal/remote/ssh.go:97-136; ssh_strength.go:47-76 @ 950c3f8 | Ed25519 / ECDSA / RSA ≥2048 with SHA-2 | operator (file or ssh-agent) | forgery-only (signatures) | |
| KQS | Runner SSH login key generation | KQS:internal/runner/state.go:166-196 @ 950c3f8 | Ed25519 from `crypto/rand` (`ed25519.GenerateKey(rand.Reader)`) | runner state volume `/state/ssh/id_ed25519` | forgery-only (signatures) | Installed on targets as `restrict ssh-ed25519 … kyquickstart-runner <uuid>` (KQS:internal/cli/handoff.go:205-218; internal/dockerhost/authkeys.go:15). |
| KQS | CNPG database TLS: installer-made CA and server certificate | KQS:internal/kube/dbcluster.go:146-191, 44-45 @ 950c3f8 | ECDSA P-256 CA and leaf, `crypto/rand`, 127-bit serial, 10-year life, CA private key discarded after issuance | server key in a k8s Secret; the CA key is not kept | forgery-only (signatures) | Clients use `sslmode=verify-full&sslrootcert=…` (dbcluster.go:76-85). Nothing renews the certificate (dbcluster.go:44). |
| KQS | CNPG database TLS: key exchange | KQS:internal/kube/dbcluster.go:82 @ 950c3f8; cluster image `ghcr.io/cloudnative-pg/postgresql:17.12-minimal-trixie` (KQS:internal/catalog/apps/kyidentity/manifest.yaml:21) | PostgreSQL 17 `ssl_ecdh_curve` defaults to `prime256v1` (https://www.postgresql.org/docs/17/runtime-config-connection.html). No override in KQS. | ephemeral | HNDL (confidentiality) | The Postgres server limits the group to P-256, so a Go client cannot get X25519MLKEM768. PostgreSQL 18's `ssl_groups` default is `X25519:prime256v1` (https://www.postgresql.org/docs/18/runtime-config-connection.html), so open PR #217 (PG18 for CNPG) would still be classical unless `ssl_groups` is set. Whether CNPG overrides it is unverified. |
| KQS | Single-pod Postgres link | KQS:internal/kube/replicas.go:280-292 @ 950c3f8 | `sslmode=disable` (plaintext inside the namespace, NetworkPolicy-bound) | n/a | n/a | No TLS by design (comment at replicas.go:280). |
| KQS | Edge-pod TLS probe (Go client) | KQS:internal/kube/tlscert.go:46-59 @ 950c3f8 | `tls.Config{MinVersion: TLS12, RootCAs: exact leaf}`, no CurvePreferences, so Go 1.26 defaults apply: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256/384/521 (go1.26.10 src/crypto/tls/defaults.go:21-35) | ephemeral | PQ-hybrid already (if the nginx pod offers it, see the nginx row) | Probes only, no data sent. |
| KQS | All other installer Go TLS (client-go Kubernetes API, NPM/KyDNS/route HTTPS clients) | KQS:docs/STRONG-CRYPTO.md; no `CurvePreferences` anywhere in KQS (git grep) @ 950c3f8 | Go 1.26 defaults. Under `fips140=on`, go1.26.10 allows X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, P-256/384/521 and drops plain X25519 (go1.26.10 src/crypto/tls/defaults_fips140.go:33-40) | ephemeral | PQ-hybrid already (client side; depends on the peer) | The kube-apiserver Go version and its TLS config belong to the cluster owner and are unverified. |
| KQS | Restic backup repository encryption | KQS:internal/dockerhost/backup.go:20-36, 88 @ 950c3f8; restic 0.19.1 pinned by digest | AES-256-CTR + Poly1305-AES; master key wrapped under a scrypt-derived key (restic design.rst, per OPENSSF_CRYPTO_PROTOCOL_SCOPE.md) | repo password: 32 random bytes in `secrets/restic_password` on the target (KQS:AGENTS.md:462-466) | symmetric, PQ-safe at 256-bit | Password generated on the target from /dev/urandom (see the generated-secrets row). |
| KQS | Restic → rest-server transport | KQS:internal/dockerhost/backup.go:88; internal/stack/stack.go:82-131 @ 950c3f8 | TLS via restic's Go runtime with `GODEBUG=fips140=on`. restic v0.19.1 go.mod says `toolchain go1.25.10`; Go 1.25 FIPS mode allows X25519MLKEM768 (go1.25.0 defaults_fips140.go:33-38) | ephemeral; rest-server user password in a file | PQ-hybrid already (likely; Go version of the release image is unverified, built by `restic/builder:latest`) | Rest-server PQ support depends on the operator's server build. Optional private CA via `ca_file`. |
| KQS | Generated app secrets (session, SCIM, JWT, secure_link, NPM admin, restic) | KQS:internal/dockerhost/secrets.go:14, 65-105; internal/kube/generate.go:18-31 @ 950c3f8 | 32 bytes from the target's `/dev/urandom` (Docker) or from a pinned BusyBox 1.37.0 pod (k8s), unpadded base64url | target files at mode 0600 / k8s Secrets | symmetric, PQ-safe at 256-bit | The products use these as HMAC/session/JWT keys. |
| KQS | Run-lock holder token | KQS:internal/dockerhost/lock.go:43; internal/kube/lock.go:39 @ 950c3f8 | `crypto/rand` nonce | n/a | n/a | Lock identity, not a key. |
| KQS | nginx edge (k8s) TLS termination | KQS:internal/edge/nginxconf.go:63-67 @ 950c3f8; image `nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116e…` (KQS:internal/catalog/apps/nginx/manifest.yaml:7) | `ssl_protocols TLSv1.2 TLSv1.3`; TLS 1.2 ciphers ECDHE/DHE-AEAD only; no `ssl_ecdh_curve`, so nginx uses `auto` = OpenSSL's built-in list (https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_ecdh_curve) | leaf key in the cert-manager Secret | PQ-hybrid already (if the image's OpenSSL is ≥3.5, which is unverified for this digest) | OpenSSL 3.5.0: "default TLS supported groups list ... include and prefer hybrid PQC KEM groups" and keyshares X25519MLKEM768 + X25519 (https://github.com/openssl/openssl/blob/openssl-3.5/NEWS.md). Alpine v3.23 ships openssl 3.5.9-r1 (pkgs.alpinelinux.org). Current upstream stable/alpine-slim is 1.30.8 on alpine:3.24. Nothing in KQS drops X25519MLKEM768. |
| KQS | nginx edge certificates via cert-manager (ACME) | KQS:internal/edge/nginx.go:336-373; internal/kube/nginxedge.go:295-314 @ 950c3f8 | Let's Encrypt ACME v2, DNS-01 (Cloudflare). The Certificate spec sets no `privateKey`, so the cert-manager default applies: RSA-2048 (cert-manager API docs: "default to 2048"; that RSA is the algorithm when none is set is unverified). ACME account key in Secret `kyq-<name>-account` (algorithm unverified) | cert-manager (installed by the cluster owner, never by KQS) | forgery-only (signatures) | rotationPolicy defaults to `Always` in cert-manager ≥1.18 (cert-manager API docs). |
| KQS | Nginx Proxy Manager edge TLS | KQS:internal/catalog/apps/npm/manifest.yaml:8 @ 950c3f8 (`jc21/nginx-proxy-manager:2.17.1@sha256:04a9d0…`) | NPM v2.17.1 `ssl-ciphers.conf`: TLSv1.2/1.3, no `ssl_ecdh_curve` (upstream file at tag v2.17.1). The OpenResty base `nginx-full` builds on debian:trixie-slim against `libssl-dev` (trixie openssl 3.5.9-1~deb13u1) | NPM `/etc/letsencrypt` volume | PQ-hybrid already (likely; OpenSSL version inside the pinned digest is unverified) | |
| KQS | NPM certificates (certbot ACME) | KQS:internal/edge/certs.go:213-226 @ 950c3f8 | No `key_type` in meta, so NPM passes no `--key-type` (NPM backend/internal/certificate.js:1076-1078 @ v2.17.1) and certbot's default applies: ECDSA P-256 since certbot 2.0.0 (certbot CHANGELOG.md) | NPM container | forgery-only (signatures) | Certbot version in the image and the account-key algorithm are unverified. |
| KQS | Public TLS chain copy and pin source (KyDrive/KyPost) | KQS:internal/cli/tlscert.go:39-120; internal/dockerhost/tlschain.go @ 950c3f8 | Parses X.509 and pins the leaf by SHA-256; private-key blocks dropped | n/a (public) | n/a | The pins are consumed by the products (see their parts). |
| KQS | frp connector (frpc → operator frps) | KQS:internal/edge/connector.go:26, 52-68 @ 950c3f8; `ghcr.io/fatedier/frpc:v0.71.0` | TLS on, `trustedCaFile` and serverName verified, token auth. frp sets no CurvePreferences (fatedier/frp pkg/transport/tls.go @ v0.71.0, `&tls.Config{}`); frp go.mod `go 1.25.0` | token file (operator) | PQ-hybrid already (likely: Go ≥1.24 defaults; frpc build Go and frps side unverified) | frp auto-generates RSA-2048 self-signed certificates only when no certificate is configured (tls.go:38,158); the operator's frps setup is out of scope. |
| KQS | cloudflared connector | KQS:internal/edge/connector.go:27, 71-88 @ 950c3f8; `cloudflare/cloudflared:2026.10.0` | Cloudflare docs: "By default, Cloudflare Tunnel connections over quic are encrypted using post-quantum cryptography", with fallback to non-PQ; "not supported when using http2" (developers.cloudflare.com, cloudflared run parameters) | `TunnelSecret` credentials file (operator) | PQ-hybrid already (QUIC default, with silent non-PQ fallback) | `--post-quantum` / `TUNNEL_POST_QUANTUM` is not set, so a fallback to classical is possible. The exact group is unverified. Origin hop cloudflared → NPM is HTTPS; cloudflare-direct uses plain HTTP on the host bridge (connector.go:72-75). |
| KQS | Release signing: runner image and binaries | KQS:.github/workflows/release-image.yml:185-215, 276-324 @ 950c3f8; docs/VERIFYING-RELEASES.md:23-62 | GitHub artifact attestations (Sigstore, Fulcio short-lived certificate, keyless). SLSA provenance plus SBOM. Key type: Sigstore ephemeral ECDSA P-256 (unverified for actions/attest-build-provenance v4.2.2) | GitHub/Sigstore (ephemeral) | forgery-only (signatures) | Consumers run `gh attestation verify --cert-identity …release-image.yml@refs/tags/v<tag>`. |
| KQS | Third-party image integrity | e.g. KQS:internal/dockerhost/backup.go:23; internal/kube/generate.go:21; internal/catalog/catalog.go:500 @ 950c3f8 | SHA-256 digest pins | n/a | n/a | restic is described as having "only ... an unsigned BuildKit SLSA attestation" (backup.go:20-22). |
| KQS | Recovery pairing for catalog KyPost | KQS:internal/cli/recoverypair.go:18-162 @ 950c3f8 | Installer relays a 6-digit pairing code over stdin. Sealing (ky-primitives `capsule`, X-Wing HPKE) runs inside KyPost/KyRecovery | KyRecovery / owner | n/a (installer does no crypto here) | The only ky-primitives package KQS imports is `keyfile` (KQS:internal/remote/ssh.go:15; internal/runner/state.go:18). The crypto is in the products' parts. |
| KQA | Managed SSH login key | KQA:kyqs-ai:67-75 @ 3a7b8ef | `ssh-keygen -q -t ed25519` (OpenSSH arc4random seed, per the research doc) | operator workstation (`$SSHD/id_ed25519`, passphrase optional) | forgery-only (signatures) | Target accepts only `ssh-ed25519` (KQA:bin/prepare-host.sh:17-23). |
| KQA | SSH transport policy for launcher, `bin/on`, `bin/handover` | KQA:bin/ssh-policy:7-27 @ 3a7b8ef | OpenSSH client: `RequiredRSASize 2048`, `KexAlgorithms=-*sha1*`, `Ciphers=-*cbc*,arcfour*`, `MACs=-*sha1*,*md5*,*-96*,umac-64*`, `HostKeyAlgorithms`/`PubkeyAcceptedAlgorithms=-ssh-rsa*,ssh-dss*`, `CASignatureAlgorithms=-ssh-rsa,ssh-dss`, `ControlPath=none` | ephemeral | PQ-hybrid already (keeps OpenSSH defaults: mlkem768x25519-sha256 on ≥9.9 and sntrup761x25519 on ≥9.0) | Subtractive (`-`) lists, so the defaults' PQ KEX is **not** overridden. `test/unit.sh:258-264` fails if any `mlkem*`/`sntrup*` default is removed. HNDL only against servers that lack both. |
| KQA | Target host-key pinning | KQA:kyqs-ai:250-270; bin/prepare-host.sh:52-55 @ 3a7b8ef | `ssh-keyscan -t ed25519` plus an out-of-band fingerprint compare; changed key refused | target sshd | forgery-only (signatures) | KQA does not change sshd_config on targets (prepare-host.sh only adds a user and authorized_keys). |
| KQA | Kubernetes ServiceAccount token for the agent | KQA:kyqs-ai:296-310 @ 3a7b8ef | `kubernetes.io/service-account-token` Secret, signed by the cluster's SA issuer key (algorithm is the cluster's, typically RS256/ES256, unverified) | cluster control plane | forgery-only (signatures) | |
| KQA | Strong Kubernetes TLS profile (kubectl) | KQA:bin/kubectl-policy:33-57 @ 3a7b8ef | Child `GODEBUG=fips140=on`; accepts kubectl built with Go ≥1.24 (line 54) | ephemeral | PQ-hybrid already with Go ≥1.25 kubectl. **HNDL (confidentiality) with a Go 1.24 kubectl**: go1.24.0 FIPS curves are only P-256 and P-384 (go1.24.0 src/crypto/tls/defaults.go:103-105), so X25519MLKEM768 is dropped | Go 1.25 added X25519MLKEM768 to the FIPS list (go1.25.0 defaults_fips140.go:33-38). The documented matrix (Go 1.25.5 / 1.26.6) is fine. Raising the floor to Go 1.25 would close this. |
| KQA | Update channel: `gh` downloads and attestation | KQA:kyqs-ai:684-690, 755-772; docs/STRONG-UPDATES.md @ 3a7b8ef | `gh` with `GODEBUG=fips140=on`; SHA-256 digest check plus `gh attestation verify` (Sigstore) pinned to the tag workflow identity | GitHub/Sigstore | forgery-only (signatures); TLS PQ-hybrid if gh is built with Go ≥1.25, HNDL with Go 1.24 (same FIPS-curve issue) | The Go version of the gh build is unverified. |
| KQA | Target secrets (agent instruction) | KQA:PROMPT.md:20 @ 3a7b8ef | `head -c 32 /dev/urandom` → base64url on the target | target files | symmetric, PQ-safe at 256-bit | Prompted recipe, not enforced. |
| KyPost-Server | Inbound HTTPS (optional direct TLS) | KyPost-Server:backend/internal/api/tls.go:179-190 @ 928ba0be; ListenAndServeTLS backend/internal/api/server.go:1163 | TLS 1.2 minimum, Go default cipher suites and curves (X25519MLKEM768 first in TLS 1.3); operator certificate, RSA under 2048 refused (backend/internal/cryptutil/certkey.go:11-15) | Operator (`TLS_CERT_FILE`/`TLS_KEY_FILE`, hot-reloaded) | PQ-hybrid already | Hybrid only with TLS 1.3 clients that offer it; TLS 1.2 clients get classical ECDHE (HNDL). Certificate authentication is classical (forgery-only). Usually sits behind a reverse proxy whose TLS is outside this repo. |
| KyPost-Server | `GODEBUG=fips140=on` "strong-crypto" overlay | KyPost-Server:docker-compose.strong-crypto.yml:6 @ 928ba0be; docs/STRONG-CRYPTO.md:60-75 | Go FIPS 140-3 mode | Operator opt-in | n/a | Unverified: whether Go 1.27 FIPS mode still offers X25519MLKEM768. X25519 is not FIPS-approved, so this overlay may drop the hybrid group, or swap it for SecP256r1MLKEM768. Needs a check against Go's crypto/tls FIPS defaults before anyone recommends the overlay. |
| KyPost-Server | Inbound SMTP on port 25 (Maddy, generated config) | KyPost-Server:backend/internal/app/receiving_config.go:175-176 @ 928ba0be; `require_tls` ibid. ~:196 | `protocols tls1.2 tls1.3`; operator certificate (RSA under 2048 refused) | Operator; Maddy is an external binary (v0.9.5 assessed in docs/RECEIVING_GATEWAY_ASSESSMENT.md:14) | HNDL (confidentiality) | Maddy is Go. Its curve defaults depend on the Go version of the Maddy release build (unverified). Sending MTAs mostly offer classical ECDHE only. No MTA-STS/TLS-RPT/DANE (docs/guides/NATIVE_MAIL.md:167). |
| KyPost-Server | Outbound SMTP submission to relay (STARTTLS required, or implicit TLS) | KyPost-Server:backend/internal/mailmsg/smtp_send.go:203 and :408 @ 928ba0be; mandatory-STARTTLS rule :159-163 | TLS 1.2 minimum, Go defaults | Relay provider (server certificate); SMTP AUTH credentials sealed at rest | HNDL (confidentiality) | Go offers X25519MLKEM768, but the relay peer decides; most SMTP relays are classical today (unverified per provider). `ALLOW_INSECURE_SMTP` opt-out exists. |
| KyPost-Server | Direct MX delivery (verified STARTTLS) | KyPost-Server:backend/internal/mailmsg/direct_mx.go:149-152 @ 928ba0be | TLS 1.2 minimum, `RootCAs: directRoots`, hostname verified | Recipient MX | HNDL (confidentiality) | Hybrid only if the recipient MX offers it. No MTA-STS/DANE: "DNS selection is not authenticated by DNSSEC, DANE or MTA-STS" (docs/DIRECT_DELIVERY.md:55). |
| KyPost-Server | IMAP import client (implicit TLS or STARTTLS) | KyPost-Server:backend/internal/adapters/imap/import_source.go:125-133 @ 928ba0be | TLS 1.2 minimum, verified | Remote IMAP provider | HNDL (confidentiality) | Imported credentials are sealed with `imap-import.key` (AES-256-GCM). Captured IMAP sessions expose the user's whole mailbox, so this is a high-value HNDL target. |
| KyPost-Server | Hosted receiving transport (MX host to replica, mutual TLS) | KyPost-Server:backend/internal/app/receiving_tls.go:319-322 (server), :438-442 (client), keygen :170/:205, self-signed cert :144-157 @ 928ba0be | TLS 1.3 only, mutual, Ed25519 keys, SPKI-SHA256 pins both ways (`InsecureSkipVerify` replaced by pin check) | KyPost operator (`SECRET_DIR/receiving-tls.key`; gateway keys from `receiving gateway keygen`) | PQ-hybrid already | Both ends are Go 1.27 with default curves, so the key exchange is X25519MLKEM768. Peer authentication is Ed25519 (forgery-only). Multi-tenant installs only. |
| KyPost-Server | Pairing-link certificate pin probe | KyPost-Server:backend/internal/api/pairing_pin.go:259-262 @ 928ba0be | TLS 1.2 minimum dial; publishes SHA-256 of the leaf SPKI | n/a (hash of the server's own certificate) | n/a | Hash only. |
| KyPost-Server | Relay identity (signed TLS pin rollover for native devices) | KyPost-Server:backend/internal/api/relay_identity.go:31-45 @ 928ba0be | Ed25519 over `kypost-tls-pin/1\nhost\npin\nissuedAt` | Server (`relay-identity.key`, 32-byte seed) | forgery-only (signatures) | A CRQC could forge a pin rollover and MITM native devices. Verified on Android (push/NativeRegistration.kt:74) and on the other clients. |
| KyPost-Server | Direct-delivery DKIM signing | KyPost-Server:backend/internal/mailmsg/dkim.go:78-80 (keygen), :104-107 (exactly 2048 bits), :260-262 (sign), :123 (`k=rsa` record) @ 928ba0be | RSA-2048, rsa-sha256, relaxed/relaxed; no ed25519-sha256 | Server, sealed in `native-relay.json` with the domain-relay master key (AES-256-GCM) | forgery-only (signatures) | Rotation is admin-driven only (Rotate/Confirm/RotateNow; old key kept 7 days; `Tick` hourly cleanup, backend/internal/app/dkim_rotation.go:14-35). 180-day rotation is recommended (docs/STRONG-CRYPTO.md:46). Relay mode never signs. There is no import path. |
| KyPost-Server | DKIM verification (send-as probe, Autocrypt date, KyCalendar REPLY provenance) | KyPost-Server:backend/internal/adapters/imap/dkim_verify.go:69-71 @ 928ba0be | emersion/go-msgauth v0.7.0 `dkim.VerifyWithOptions`, max 3 signatures | Remote senders' DNS keys | forgery-only (signatures) | I did not check which algorithms go-msgauth accepts (rsa-sha1? ed25519?) (unverified). |
| KyPost-Server | DKIM/SPF/DMARC on received mail (Rspamd) | KyPost-Server:backend/internal/app/receiving_spam.go:118-127 @ 928ba0be; scripts/rspamd/rspamd.conf:10-13 | Rspamd dkim/spf/dmarc modules; only `R_SPF_ALLOW` / `R_DKIM_ALLOW` are trusted | Remote senders | forgery-only (signatures) | No ARC verification or ARC sealing anywhere in KyPost-Server. |
| KyPost-Server | VAPID identity (browser Web Push and UnifiedPush) | KyPost-Server:backend/internal/config/config.go:886-905 (keygen), :847-867 (load) @ 928ba0be | ECDSA P-256 (ES256 VAPID JWT) via SherClockHolmes/webpush-go v1.4.0 | Server (`notifications-vapid-private.pem`, CONFIG_DIR/SECRET_DIR) | forgery-only (signatures) | Shared by daemon, API and replicas. |
| KyPost-Server | Web Push / UnifiedPush payload encryption | KyPost-Server:backend/internal/processor/native_sender.go:418-427, push_dispatch.go:68 @ 928ba0be; subscriber key check processor/webpush_keys.go:51 | RFC 8291: ECDH P-256 + HKDF, content AES-128-GCM (aes128gcm, RFC 8188) | Device (UA key + auth secret) | HNDL (confidentiality) | Payloads cross public brokers (ntfy.sh etc.) and browser push services. The AES-128 content key also falls under "symmetric, 128-bit: Grover to ~64-bit, review". UnifiedPush MFA approvals are sent only if keys are present (backend/internal/api/push_mfa_handlers.go:42-53, :236-237). |
| KyPost-Server (worker/) | FCM relay: Google OAuth service-account assertion | KyPost-Server:worker/src/fcm.ts:4, :43-56 @ 928ba0be; push-relay-shared/AGENTS.md:13 | RS256, RSA modulus at least 2048 measured | Maintainer (wrangler secret `FCM_*` on Cloudflare) | forgery-only (signatures) | One Firebase project for all self-hosted servers. Notification title/body pass through the relay to FCM under TLS only. |
| KyPost-Server (worker-apns/) | APNs provider token | KyPost-Server:worker-apns/src/apns.ts:50-84 @ 928ba0be | ES256 (P-256 .p8), WebCrypto | Maintainer (wrangler secret `APNS_*`) | forgery-only (signatures) | |
| KyPost-Server | Push relay per-server API keys | KyPost-Server:push-relay-shared/push-relay-common.ts:286 @ 928ba0be; worker/README.md:105, :326 | 256-bit random bearer, stored as SHA-256 | Each KyPost server (key file) and relay (hash) | n/a | Sent as a bearer over HTTPS only (backend/internal/processor/native_sender.go:90-123). |
| KyPost-Server | OIDC ID-token verification (browser SSO, step-up, native sign-on) | KyPost-Server:backend/internal/sso/sso.go:158-162, :640-642 @ 928ba0be; JWKS RSA under 2048 refused backend/internal/sso/jwks_strength.go:51 | coreos/go-oidc v3.21.0 (go-jose v4.1.9); RS/PS 256-512, ES256-512, no HMAC | External IdP (KyIdentity, Authentik, Keycloak) | forgery-only (signatures) | |
| KyPost-Server | OIDC back-channel logout | KyPost-Server:backend/internal/sso/lifecycle.go:175 @ 928ba0be (via ky-primitives/oidcverify) | RS256 only | IdP | forgery-only (signatures) | oidcverify is covered by the ky-primitives worker. |
| KyPost-Server | Native sign-on proof of possession (device approval) | KyPost-Server:backend/internal/api/native_signon.go:195-225 @ 928ba0be | ECDSA P-256/SHA-256 over `kypost-signon-pop/1`, key bound by `cnf` SPKI-S256 thumb | Device (ephemeral app key) | forgery-only (signatures) | |
| KyPost-Server (frontend) | Device key delivery (browser seals the OpenPGP key or ring to a device) | KyPost-Server:frontend/src/lib/deviceEnrollment.ts:26, :65-71, :380-393 @ 928ba0be | RFC 9180 HPKE Base, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (@hpke/core 1.10.1, frontend/package-lock.json:235-236); v2/v3 custom ECDH envelopes retired | Device enrollment key (Android Keystore / Secure Enclave / OpenSSL) | HNDL (confidentiality) | Wraps the user's OpenPGP private key, and the ciphertext transits the server. The earlier OpenSSF review (snapshot 3a4c11b) said v2/v3 were still live; at 928ba0be they are retired ("never sealed here"). Prime candidate for an X-Wing/ML-KEM HPKE suite. |
| KyPost-Server | Session and CSRF tokens | KyPost-Server:backend/internal/api/server_auth_session.go:587, :605-610 @ 928ba0be; storage hash backend/internal/api/shared_state.go:206-209 | 192-bit random (`randomToken(24)`), stored as SHA-256 | Server / browser cookie (`kypost_session` HttpOnly) | n/a | Opaque tokens, not JWTs. |
| KyPost-Server | Pairing, QR and pickup tokens; synthetic login salt | KyPost-Server:backend/internal/api/server_notifications.go:1131, :1162; login_params.go:100 @ 928ba0be | HMAC-SHA256 with `PAIRING_SECRET` (32 bytes) | Server (`pairing.key`) | symmetric, PQ-safe at 256-bit | |
| KyPost-Server | Proof-of-work CAPTCHA | KyPost-Server:backend/internal/captcha/pow.go:152 @ 928ba0be | HMAC-SHA256, `POW_SECRET` at least 16 bytes (32 generated) | Server (`pow.key`) | symmetric, PQ-safe at 256-bit | |
| KyPost-Server | HMAC-keyed digests (recovery codes, replica config, tenancy purge) | KyPost-Server:backend/internal/mfa/mfa.go:479-484; replica/config.go:129-134; tenancy/purge.go:298 @ 928ba0be | HKDF-SHA256 subkey, then HMAC-SHA256 | Server master keys | symmetric, PQ-safe at 256-bit | |
| KyPost-Server | At-rest sealing (IMAP config, TOTP secrets, scheduled send, outbox, domain relay + DKIM, pickup store, documents, vol table, SSO migration) | KyPost-Server:backend/internal/cryptutil/cryptutil.go:49-58 (32-byte key), :155-173 (seal) @ 928ba0be; callers e.g. mailmsg/domain_relay.go:242, mailbox/outbox.go:96/:171, vol/table.go:290, mfa/mfa.go:494, app/documents.go:224 | AES-256-GCM, random 96-bit nonce; HKDF-SHA256 subkeys for bindings | Server (`SECRET_DIR/*.key`, 32 random bytes each) | symmetric, PQ-safe at 256-bit | Keys sit on the same volume as the data, so this protects against volume/backup leaks, not against host compromise. |
| KyPost-Server | Sealed backup capsules (to KyRecovery) | KyPost-Server:backend/internal/backup/backup.go:267 @ 928ba0be; KEM ky-primitives:recoverykey/recoverykey.go:42 @ 9deb288 (the go.mod pin), KDF/AEAD capsule/hpke.go:15-16 | HPKE MLKEM768X25519 (X-Wing), HKDF-SHA256, AES-256-GCM | KyRecovery custodian key (pinned) | PQ-hybrid already | Matches docs/STRONG-CRYPTO.md:37. |
| KyPost-Server | Replica anchor encryption | KyPost-Server:backend/internal/backup/replica.go:166-207 @ 928ba0be | HKDF-SHA256 from master, AES-256-GCM | Server | symmetric, PQ-safe at 256-bit | |
| KyPost-Server | Bulk mail backup (restic) | KyPost-Server:backend/internal/backup/bulk.go:31-40, :206 @ 928ba0be | restic repository password = hex of `bulk-backup.key` (32 bytes). restic uses AES-256-CTR + Poly1305-AES with a scrypt-derived master key (https://restic.readthedocs.io/en/stable/100_references.html#design) | Server; key also collected into the capsule | symmetric, PQ-safe at 256-bit | `rest:https://` transport TLS is restic's own (Go). |
| KyPost-Server | Cloudflare continuous receiving wire | KyPost-Server:backend/internal/cfreceiving/wire.go:58-59, :81-88 @ 928ba0be | Ed25519-signed routing documents with context string; 256-bit pickup bearer | Server per epoch (seed), Worker verifies | forgery-only (signatures) | The bearer is a 256-bit random secret (n/a for quantum). |
| KyPost-Server | Password hashing / login | KyPost-Server:backend/internal/users/authsecret_derive.go:30, :77-83 @ 928ba0be; Argon2id params ky-primitives:password/password.go:51-53 @ 871828c | Client: PBKDF2-SHA256 600,000 iterations, then HKDF. Server: Argon2id m=64 MiB, t=3, p=4 (x/crypto v0.59.0). Legacy scrypt hashes never verify (users.go:2276) | Server (hash) | n/a | Listed briefly as the brief asks. |
| KyPost-Server | TOTP | KyPost-Server:backend/internal/api/mfa_handlers.go:92, :179 @ 928ba0be; ky-primitives:totp/totp.go:23, :40 @ 9deb288 | HMAC-SHA1, 160-bit secret, RFC 6238; sealed at rest | Server + user authenticator | n/a | Key is 160-bit; Grover gives roughly 80-bit, which is acceptable for a short-lived OTP. |
| KyPost-Server | SHA-1 non-secret uses (CardDAV path key) | KyPost-Server:backend/internal/api/carddav_client.go:5 @ 928ba0be | SHA-1 as an identifier | n/a | n/a | WKD SHA-1 is OpenPGP (another worker). |
| KyPost-for-Android | HTTPS to KyPost server and relay (pinned) | KyPost-for-Android:app/src/main/java/org/kysecurity/mail/PairingAuthHeaders.kt:58-81 @ 01f304bb; floor security/StrongTls.kt:18-42 | OkHttp 5.4.0 `ConnectionSpec.RESTRICTED_TLS`; TOFU leaf SPKI pin (`sha256/`); RSA 2048 or more / EC 256 or more, SHA-256+ PKCS#1/ECDSA only | Server certificate; pin in Keystore-backed prefs | HNDL (confidentiality) | Unverified: whether Conscrypt on the target Android versions offers X25519MLKEM768. Pin rollover is verified with the server's Ed25519 relay identity (forgery-only). |
| KyPost-for-Android | Device enrollment key (receives HPKE envelope) | KyPost-for-Android:app/src/main/java/org/kysecurity/mail/pgp/EnrollmentKeyStore.kt:28-30; pgp/DeviceEnvelope.kt:14, :26-30 @ 01f304bb | P-256 ECDH in AndroidKeyStore (StrongBox when available); HPKE-Base-P256-SHA256-A256GCM; v4/v5 only | Device hardware keystore | HNDL (confidentiality) | Since the OpenSSF snapshot 7de9e10, Android is HPKE-only (v2/v3 dropped). The HPKE open is app code (BouncyCastle 1.87 point decode + Keystore KeyAgreement). |
| KyPost-for-Android | Local secret storage (pairing proof, DB key, push state) | KyPost-for-Android:app/src/main/AGENTS.md:16, :1212 @ 01f304bb; gradle/libs.versions.toml:44 | androidx security-crypto 1.1.0 EncryptedSharedPreferences: AES-256-GCM values / AES-256-SIV keys, Keystore master key (library default, unverified for 1.1.0) | Device Keystore | symmetric, PQ-safe at 256-bit | |
| KyPost-for-Android | Push: FCM and UnifiedPush (WebPush keys) | KyPost-for-Android:app/src/main/AndroidManifest.xml:190-193; push/PushRepository.kt:452 @ 01f304bb; firebaseBom 35.2.0, unifiedPush 3.3.5 (libs.versions.toml:39, :89) | UnifiedPush: RFC 8291 P-256 ECDH + aes128gcm; FCM: Google transport | Device | HNDL (confidentiality) | Same exposure as the server-side RFC 8291 row. |
| KyPost-for-Linux | HTTPS client (pinned) | KyPost-for-Linux:core/net/HttpClient.cpp:125-172 @ ae383bf | Qt6 QSslSocket (OpenSSL) with SPKI-SHA256 pin; KDE runtime 6.11 (packaging/flatpak/com.kysecurity.mail.yaml:2-3) | Server certificate | HNDL (confidentiality) | The app sets no explicit curves. If the runtime's OpenSSL is 3.5 or newer, its default groups include X25519MLKEM768, but I have not checked which OpenSSL KDE 6.11 ships (unverified). |
| KyPost-for-Linux | Device enrollment HPKE | KyPost-for-Linux:core/pgp/DeviceEnrollmentCrypto.cpp:170, :200 @ ae383bf | OpenSSL 3.2+ OSSL_HPKE P-256/HKDF-SHA256/AES-256-GCM, v4/v5 only | Device | HNDL (confidentiality) | v2/v3 retired since OpenSSF snapshot 8fec1b4. |
| KyPost-for-Linux | Credential seal + keychain | KyPost-for-Linux:core/security/CredentialCipher.cpp:95, :192 @ ae383bf; Argon2id core/CMakeLists.txt:227-239; app/platform/SecureStoreKeychain.cpp:9 | AES-256-GCM, Argon2id (libargon2, 64 MiB); QtKeychain (Secret Service) | User session keyring | symmetric, PQ-safe at 256-bit | |
| KyPost-for-Linux | Push | KyPost-for-Linux:app/CMakeLists.txt:175-181 @ ae383bf | KUnifiedPush (RFC 8291 per server) | Device | HNDL (confidentiality) | |
| KyPost-for-Mac (macOS + iOS) | HTTPS client (pinned) | KyPost-for-Mac:KyPost/Data/Networking/PinnedSessionDelegate.swift:81-130 @ 165148e | URLSession + SecTrustEvaluateWithError + leaf pin; RSA 2048 or more / EC 256 or more; deployment target 26.0 (KyPost.xcodeproj/project.pbxproj:332, :335) | Server certificate | HNDL (confidentiality) | Apple says iOS/macOS 26 URLSession negotiates X25519MLKEM768 by default (WWDC25 session 314, https://developer.apple.com/videos/play/wwdc2025/314/). I have not confirmed this, so I am not counting it as PQ. |
| KyPost-for-Mac | Device enrollment HPKE | KyPost-for-Mac:KyPost/Domain/Security/DeviceEnvelope.swift:31, :43; DeviceAgreementKey.swift:22, :39-62 @ 165148e | CryptoKit HPKE P256_SHA256_AES_GCM_256; Secure Enclave P-256 when available; v4/v5 only | Secure Enclave / Keychain (`WhenUnlockedThisDeviceOnly`) | HNDL (confidentiality) | CryptoKit on 26.0 also has `HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256` (Apple docs, unverified), which makes migration cheap here. |
| KyPost-for-Mac | Token storage, APNs | KyPost-for-Mac:KyPost/Data/Storage/KeychainStorage.swift:48; GatedCredentialStore.swift:38; App/AppDelegate.swift:251, :520 @ 165148e | Keychain (`AfterFirstUnlockThisDeviceOnly` / `WhenUnlockedThisDeviceOnly`); APNs via relay | Device | n/a | |
| Busnes.app-site | Static site | Busnes.app-site:HOSTING.md:6-11; CNAME @ 23e10f6 | GitHub Pages (legacy build) for `busnes.app`, meta CSP `default-src 'self'` (index/about/404 .html:10) | GitHub | n/a | No crypto in repo. TLS is GitHub Pages' (outside repo). |
| All container repos (see Part B) | Image/binary provenance | e.g. KyPost-Server:.github/workflows/release-image.yml:235 @ 928ba0be | Sigstore (GitHub artifact attestations, actions/attest-build-provenance v4.2.2), ephemeral-key signing (ECDSA P-256 per Sigstore, unverified) | GitHub OIDC identity of the workflow (keyless) | forgery-only (signatures) | Details in Part B. |
| KyPost-for-Linux, KyAuth-Linux | Flatpak OSTree repo + bundle signing | KyPost-for-Linux:.github/workflows/flatpak.yml:481-611 @ ae383bf; key spec packaging/flatpak/gen-signing-key.sh:52-57 | GPG RSA-4096, no expiry | Maintainer; GitHub secret `FLATPAK_GPG_PRIVATE_KEY` | forgery-only (signatures) | Part B. |
| KyAuth-android, KyPost-for-Android | APK/AAB signing | KyPost-for-Android:.github/workflows/release.yml:138-151, :213-235 @ 01f304bb | apksigner (keystore alg not visible; CI throwaway is RSA-4096, ci.yml:169-170) | Maintainer; GitHub `release` environment secrets | forgery-only (signatures) | Part B. |
| KyPost-for-Mac, KyAuth-iOS, kydrive-desktop | Apple codesign / notarization / App Store upload | KyPost-for-Mac:.github/workflows/release.yml:114-120, :328-348 @ 165148e | Apple Developer ID / Development certificates (alg unverified, typically RSA-2048), ASC API key ES256 | Maintainer; GitHub secrets | forgery-only (signatures) | Part B. |
| KyQuickStart | Runner SSH key to Docker targets | KyQuickStart:internal/cli/handoff.go:209-218; internal/remote/ssh.go:80-84 @ 950c3f8 | ssh-ed25519 (`restrict` authorized_keys), x/crypto v0.59.0 `ssh.SupportedAlgorithms()` KEX list | Runner state volume | forgery-only (signatures) | For the KEX, I assume the x/crypto v0.59 supported list includes mlkem768x25519-sha256, but I have not checked (unverified). The KyQuickStart worker owns the details. |

## 2. Per-repo notes

### Part 1: ky-primitives, ky-server-base, the private dashboard repo, ky-ui, org `.github`

#### Snapshot, toolchain and libraries

Snapshots, read-only through `git show` and `git grep` on origin branches (no fetch): ky-primitives master `871828c`, ky-server-base master `eceb24e`, the private dashboard repo main `6b2659c`, ky-ui main `1b0e466`. The org `.github` repo was read with `gh api` at main `b2ee038`.

Toolchains: ky-primitives `go 1.26.6`, no toolchain line, x/crypto v0.59.0 (`ky-primitives:go.mod:3,5 @ 871828c`). ky-server-base `go 1.26.9`, `toolchain go1.27.4`; it builds with `golang:1.27.4-alpine` (`ky-server-base:go.mod:3,5`, `Dockerfile:13 @ eceb24e`). the private dashboard repo has the same go/toolchain lines (`the private dashboard repo:go.mod:3,5 @ 6b2659c`).

#### Per-repo notes

#### ky-primitives package inventory (every package at 871828c)

| package | does crypto? | what |
|---|---|---|
| (root `kyprimitives`) | test-only | `crypto_profile_test.go` (fips140 TLS profile test), `nodeps_test.go` |
| applysetup | no | Local installer setup over a unix socket (`applysetup/local.go:157`, Proxy nil). No crypto imports |
| auditchain | yes | HMAC-SHA256 chain, 32-byte key floor |
| capsule | yes | HPKE X-Wing / HKDF-SHA256 / AES-256-GCM, kycap/3. SHA-256 payload and file digests |
| cmd/kyauditverify | yes (via auditchain) | Offline HMAC chain verifier |
| derive | yes | PBKDF2-SHA256 → HKDF-SHA256; HMAC-SHA256 synthetic salt |
| health | no | |
| keyfile | yes (RNG/storage) | crypto/rand generation, 0600 file policy, 16-byte floor |
| logging | no | |
| netallow | no | IP allowlist matcher |
| offsite (separate module) | yes | SFTP (x/crypto/ssh), SMB NTLM (go-smb2), S3 SigV4 (aws-sdk-go-v2), local file |
| oidcverify | yes | RS256 JWT/JWKS verifier, plus bearer middleware (`oidcverify.go:487-507`) |
| password | yes | Argon2id PHC |
| recoveryclient | yes | AES-256-GCM sealer, capsule sealing, key pin, HTTPS client |
| recoveryclient/guardtest | no | AST checker that a server never calls decrypt (test helper) |
| recoverycode | yes (RNG) | 60-bit codes, constant-time match |
| recoverykey | yes | X-Wing keypair, seed split |
| s3 | yes | SigV4 HMAC-SHA256 |
| scim | no | SCIM client, Bearer token (`scim/client.go:224`) |
| shamir | yes | GF(2^8) 0x11b SSS |
| suitedir | no | Suite directory client |
| syncauth | yes | HMAC-SHA256 webhook signatures |
| totp | yes | RFC 6238 HMAC-SHA1 |

There are no keyring, envelope/DEK-wrapping, JWT-signing, session or TLS-config helpers in ky-primitives. JWT handling is verify-only (RS256). Libraries: Go stdlib (`crypto/hpke`, `crypto/mlkem` via hpke, `crypto/hkdf`, `crypto/pbkdf2`, aes/cipher/hmac/sha1/sha256/rsa) and golang.org/x/crypto v0.59.0 (argon2, ssh). Nothing from CIRCL, filippo.io, Tink or libsodium.

#### Import map

The table covers every repo in shas.txt with a go.mod at origin/<branch>, root and subdirs. "test-only" lists packages imported only from `_test.go` files.

| repo | ky-primitives version | packages imported (prod; +test-only) | ky-server-base version |
|---|---|---|---|
| KyMessage-Server (`go.mod`) | v0.10.2-0.20261116015712-875f57b13976 | applysetup capsule health keyfile logging netallow password recoveryclient recoverykey suitedir syncauth; +recoveryclient/guardtest | none required. The module itself is named `github.com/Busnes-app/ky_server_base` (scaffold fork, not a dependency) |
| KyPulse-server | v0.10.2-0.20261114135120-7f9c247b0fbd | applysetup auditchain capsule health keyfile logging password recoveryclient suitedir syncauth; +guardtest recoverykey totp | none |
| KyIdentity-server | v0.10.2-0.20261113220457-9f4bc5875e04 | capsule health keyfile logging netallow recoveryclient recoverykey scim syncauth totp; +guardtest | none |
| ky-server-base | v0.10.2-0.20261113220457-9f4bc5875e04 | capsule keyfile netallow password recoveryclient; +guardtest recoverykey | (self) |
| kyguard-server | v0.10.2-0.20261113220457-9f4bc5875e04 | auditchain capsule keyfile logging netallow password recoveryclient recoverykey totp; +guardtest | none |
| KyYard-server (`go.mod`; `scripts/spikes/websocket-proxy/go.mod` has none) | v0.10.2-0.20261026050236-bae5c14dba4c | applysetup capsule health keyfile logging password recoveryclient recoverycode syncauth totp; +guardtest recoverykey | none |
| KyQuickStart | v0.10.1 | keyfile; +recoverykey | none |
| KyPost-Server (`backend/go.mod`; `tools/`, `third_party/go-imap` have none) | v0.10.2-0.20261120212828-9deb28884264 | capsule health logging netallow oidcverify password recoveryclient recoverycode recoverykey suitedir syncauth totp; +guardtest | none |
| KyMessages-Native (`go.mod`) | v0.10.2-0.20261124003741-b55ca6d3313c | applysetup capsule keyfile password recoveryclient recoverycode s3 suitedir syncauth totp; +guardtest recoverykey | none required. Module is also named `ky_server_base` (fork) |
| KyNotes-server (`go.mod`; `tools/` none) | v0.10.2-0.20261124003741-b55ca6d3313c, plus `offsite` v0.3.0 | capsule derive health keyfile logging netallow offsite oidcverify password recoveryclient recoverycode recoverykey s3 shamir suitedir syncauth; +guardtest | none |
| kydrive-server | v0.10.2-0.20261124022836-b5f5853be771 | applysetup capsule keyfile netallow password recoveryclient suitedir syncauth; +guardtest recoverykey | none |
| KyCalendar (`go.mod`; `e2e/suite`, `third_party/go-webdav` none) | v0.10.2-0.20261124022836-b5f5853be771 | applysetup capsule health keyfile logging netallow oidcverify password recoveryclient s3 suitedir syncauth; +guardtest recoverykey | none |
| KyDNS-server | v0.10.1 | applysetup capsule health keyfile logging password recoveryclient syncauth; +guardtest recoverykey | none |
| KyRecovery-server | v0.10.1, plus `offsite` v0.3.0 | applysetup auditchain capsule health keyfile logging offsite password recoverykey syncauth; +shamir | none |
| ky-primitives (`go.mod`, `offsite/go.mod`) | (self) | (self) | none |
| kydrive-desktop (`core/go.mod`), go-webdav, the private demo repo (`test/acceptance`), KyAuth-android and KyAuth-iOS (`scripts/tls-fixtures`) | none | none | none |

Sources: `git show origin/<br>:<go.mod>` and `git grep '"github.com/Busnes-app/ky-primitives…"'` on `*.go` at the SHAs in shas.txt (third_party excluded). No repo requires `github.com/Busnes-app/ky_server_base` as a dependency. It is a copy-and-fork scaffold.

All seven pinned pseudo-version commits and v0.10.1 use `hpke.MLKEM768X25519()` + HKDFSHA256 + AES256GCM, kycap/3, checked with `git show <c>:recoverykey/recoverykey.go` and `capsule/hpke.go` in ky-primitives. Every product therefore seals backups with X-Wing today. v0.10.1 (KyQuickStart, KyDNS-server, KyRecovery-server) predates the TOTP/SFTP key-floor commit 1c0be6a. The seven pseudo-versions include it.

#### ky-server-base

- TLS: none in-process. There is no `tls.Config`, `CurvePreferences` or `MinVersion` anywhere (grep on non-test .go). The server is plain HTTP behind an operator proxy. The strong profile is `GODEBUG=fips140=on` via `docker-compose.strong-crypto.yml:6`.
- Uses go-oidc/go-jose, not ky-primitives `oidcverify`. the private dashboard repo does the same. The accepted algorithm set comes from IdP discovery, so it is wider than RS256 (it can include EdDSA/ES*). It will accept whatever classical algorithm the IdP advertises. A future ML-DSA JWS would need go-jose/go-oidc support. That is unverified.
- `KY_KYSIGNON_HMAC_SECRET` is accepted and ignored with a warning (`internal/config/config.go:167-169 @ eceb24e`).
- Open PRs: only #127 (dependabot, modernc sqlite). Merged #67 "Enforce signing-key floors and support a strong TLS profile" (2026-10-26). No PQ-specific PRs found (gh pr list search on mlkem, post-quantum, pqc, x-wing, hpke, fips).

#### ky-primitives

- No open PRs (`gh pr list -R Busnes-app/ky-primitives --state open`: empty). Remote branches have no PQ work: feat/suitedir-*, feat/s3-*, feat/installer-setup, ci/*, chore/go-bump-standard, dependabot.
- Planned crypto: docs mention X-Wing only as already done (`docs/CAPSULE.md:120-122`, `docs/ASSURANCE-CASE.md:79`). No ML-DSA/PQ-signature plans found in `*.md`.

#### OpenSSF review cross-check

Checked `OPENSSF_SERVER_CRYPTO_REVIEW.md`, snapshots ky-primitives `1539c0c`, ky-server-base `e400622`, dated 2026-10-26. These claims are now stale:

1. "TOTP hotp accepts any nonempty decoded key" is stale. `totp.go:42,111-112` now enforces 16 bytes.
2. "syncauth signing keys are caller-supplied" with no floor is stale. `MinKeyBytes = 16` (`syncauth.go:48`).
3. "keyfile length is a caller parameter" is partly stale. A 16-byte floor exists (`keyfile.go:38`). The size is still caller-declared.
4. "offsite SFTP leaves SSH algorithms at x/crypto v0.58.0 defaults (group14-sha1, ssh-rsa, DSA, hmac-sha1-96)" is stale. It now uses `ssh.SupportedAlgorithms()` (`sftp.go:68-75`) with x/crypto v0.59.0, size floors (`:115-145`), and RSA client signing restricted to rsa-sha2-512/256 (`:46-53`). The "crypto_weaknesses: Unmet" basis is gone. Re-verifying the handshake was not done.
5. "No documented supported strong profile" is stale. `ky-primitives:docs/STRONG-CRYPTO.md` and `ky-server-base:docs/STRONG-CRYPTO.md` plus `docker-compose.strong-crypto.yml` now exist.
6. "Current product consumers use root v0.10.0", and "KyNotes and KyRecovery use offsite v0.2.2", are stale. See the import map: v0.10.1 or v0.10.2 pseudo-versions, offsite v0.3.0.
7. ky-server-base "Consumes ky-primitives v0.10.0" is stale. It is now `v0.10.2-0.20261113220457-9f4bc5875e04`.
8. ky-server-base "requires only a nonempty KY_SESSION_SECRET" is stale. A 16-byte floor exists (`config.go:161-162`), and the KySignOn HMAC secret is now ignored.
9. ky-server-base "randomly generated TOTP secrets" is stale or misleading. The base no longer does local MFA (docs/STRONG-CRYPTO.md, "This server has no local multi-factor sign-in"). the private dashboard repo still does.
10. Still accurate: capsule suite X-Wing/HKDF-SHA256/AES-256-GCM via crypto/hpke; oidcverify RS256 with ≥2048 bits; no recipient PFS for capsules; SMB/NTLM still present (`offsite/smb.go:88-89`), now documented as excluded from the strong profile.

### KyIdentity-server crypto inventory (master @ 6e7df38)

#### Snapshot, toolchain and libraries

Repo: Busnes-app/KyIdentity-server, default branch `master`, short SHA `6e7df38` (the merge commit of PR #296).
All code citations are `KyIdentity-server:path:line @ 6e7df38` unless they say otherwise. The ky-primitives citations use the commit KyIdentity pins in go.mod, `9f4bc5875e04` (`ky-primitives:path:line @ 9f4bc58`).

Libraries (go.mod @ 6e7df38): Go `go 1.26.9`, `toolchain go1.27.3`. The Dockerfile builder is `golang:1.27.4-alpine` (Dockerfile:12). Go modules:
- Go stdlib `crypto/*`, including `crypto/hpke`, `crypto/ecdh`, `crypto/hkdf` and `crypto/tls`.
- `golang.org/x/crypto v0.59.0`, used for `argon2`.
- `github.com/golang-jwt/jwt/v5 v5.3.1`.
- `github.com/go-webauthn/webauthn v0.18.2`, with indirect `go-webauthn/x v0.3.1` and `google/go-tpm v0.9.8`.
- `github.com/SherClockHolmes/webpush-go v1.4.0`.
- `github.com/go-ldap/ldap/v3 v3.4.15`.
- `github.com/jackc/pgx/v5 v5.13.0`.
- `github.com/Busnes-app/ky-primitives v0.10.2-0.20261113220457-9f4bc5875e04`, which supplies `capsule`, `recoverykey`, `recoveryclient`, `syncauth`, `totp` and `scim`.
- `github.com/fxamacker/cbor/v2 v2.10.0`.

The browser side uses WebCrypto (`crypto.subtle`) only, with no JS crypto library. The Cloudflare Workers (`workers/apns`, `workers/fcn`) use WebCrypto in workerd.

#### Per-repo notes

#### PR states (verified with `gh pr view` on 2026-11-25)
- **#295** "keyring: add zero-knowledge suite keyring v1". Branch `feat/zk-keyring`, **MERGED** 2026-11-25T22:17:33Z, merge commit `4538c549`, an ancestor of origin/master.
- **#296** "keyring: cross-origin OIDC key handoff" (branch `feat/zk-keyring-handoff`). **MERGED** 2026-11-26T00:41:15Z, merge commit `6e7df38` = current origin/master head.
- All keyring code cited above is on master.

#### Zero-knowledge keyring summary (docs/KEYRING.md @ 6e7df38)
- **Curve:** P-256, ephemeral, WebCrypto ECDH. Points are 65-byte uncompressed SEC1. The server checks them with `ecdh.P256().NewPublicKey` (internal/api/keyring.go:137-140).
- **KDF:** HKDF-SHA-256 with info = UTF-8 compact JSON AAD. The salt depends on the use:
  - 32 zero bytes for wrappers, app keys and the handoff.
  - The 256-bit approval secret for device transfer.
- **AEAD:** AES-256-GCM with a 12-byte random nonce. The same JSON is the AAD.
- **Transfer request authentication:** HMAC-SHA-256 of the transcript prefix, keyed by the approval secret.
- **Wrapped subkeys:** each app subkey (32 random bytes) is wrapped with AES-256-GCM under HKDF(SRK, info=`["ky-keyring/1","app",issuer,org_id,user_id,keyring_version,client_id,key_version]`). This is AEAD wrapping, not RFC 3394 AES-KW.
- **Recovery path:** the `KYR1-` key holds 32 random bytes and is printed as 8×8 hex. It feeds HKDF to wrap the SRK as the single `recovery` wrapper. It is separate from MFA recovery codes and KyRecovery custodian cards. Rotation replaces only that wrapper.
- **Client-held keys:** the SRK, the device secrets (non-extractable in IndexedDB), the device capability, the recovery key, the PRF output, transfer ephemerals and the approval secret, and the app-side ephemeral `keyring_pk` private key.
- **Server-held data:** envelopes, SHA-256 of the device capability, PRF credential IDs, public transfer points and MACs. It holds no plaintext key material.
- **Threat model gap:** the threat model itself says an operator who changes the served JS can steal keys (docs/KEYRING.md).
- **PQ status:** all keyring public-key steps are classical P-256 ECDH: device transfer and the OIDC handoff. Everything at rest is symmetric 256-bit. Device transfer has a secret 256-bit HKDF salt carried out of band. The handoff has none (zero salt) but keeps its ciphertext in the URL fragment.
- **PQ candidate:** WebCrypto has no ML-KEM in browsers today (unverified per browser). A hybrid would need a JS/WASM ML-KEM.

#### "Workstation login HPKE queue for Himmelblau/XCreds"
- **No HPKE is used for Himmelblau or XCreds.**
  - Himmelblau uses the RFC 8628 device grant as a public client with no secret. Tokens are RS256 JWTs and opaque SHA-256-hashed refresh tokens.
  - XCreds uses authorization code + PKCE S256.
  - Sources: docs/WORKSTATION-LOGIN.md, docs/superpowers/specs/2026-11-19-workstation-login-design.md:17-28, :59, :83-84, and docs/superpowers/specs/2026-11-19-workstation-macos-design.md:15, :44.
  - Himmelblau seals the refresh token to a TPM-backed Hello key on the desktop side. That is outside this repo.
- **The only HPKE queue in the repo is the Active Directory password queue** (internal/adpass, cmd/kyidentity-dc-agent; docs/ACTIVE-DIRECTORY.md:88-89, :143-144; docs/superpowers/specs/2026-11-19-active-directory-design.md:65-69).
  - RFC 9180 IDs: KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0002 AES-256-GCM, mode base, single-shot `hpke.Seal`.
  - The IDs come from RFC 9180 §7 (https://www.rfc-editor.org/rfc/rfc9180#section-7). The constructors are in adpass.go:25 and :58.
  - Implementation: Go stdlib `crypto/hpke`.
  - Each entry is signed with Ed25519 by a key derived from encryption.key.
  - This is the clearest HNDL item in the repo: it carries plaintext AD passwords to a static X25519 key. ky-primitives already uses `hpke.MLKEM768X25519()` for capsules, so a drop-in hybrid is available in the same stdlib.

#### OIDC/JWT
- **Signing:** RS256 only, RSA-2048 generated on first start. The key is a PEM file at `data/jwt_rs256.key`, mode 0600 and not encrypted.
- **Rotation:** none. One key appears in JWKS. Replacing it invalidates every issued token. The docs say never to replace it (STRONG-CRYPTO.md).
- **Token formats:**
  - id_token and access_token are RS256 JWTs carrying `token_use`.
  - logout tokens use `typ=logout+jwt`.
  - Refresh tokens, codes and device codes are opaque random values.
- **Grants:** authorization_code, refresh_token, the RFC 7523 jwt-bearer grant (KyAuth device ES256 assertion) and device_code.
- **Client auth:** client_secret_post, client_secret_basic and none. client_secret_jwt and private_key_jwt are not supported.
- **Federation:** no upstream IdP federation and no SAML in the code. A grep for saml, federat and upstream IdP found nothing in Go code. The server verifies no external JWKS.

#### TLS
- **No `CurvePreferences` anywhere** (grep over all non-test Go at 6e7df38). Every `tls.Config` sets only `MinVersion: TLS12`, plus `RootCAs`/`ServerName` where noted. Go's default key-exchange list therefore applies, with X25519MLKEM768 first since Go 1.24 (https://go.dev/doc/go1.24#crypto-tls).
- The server terminates no TLS itself.
- **FIPS caveat:** STRONG-CRYPTO.md recommends `GODEBUG=fips140=on`. Whether Go's FIPS 140-3 mode keeps X25519MLKEM768 in the client's default curves at Go 1.27 is **unverified**. Check `crypto/tls` defaults in the FIPS profile before relying on it.

#### Push
- Push payloads use RFC 8291, which mandates P-256 ECDH and AES-128-GCM. Changing that needs a protocol change, not a config change.
- FCM and APNs credentials live only in the Cloudflare Worker secrets. KyIdentity authenticates to the relays with a bearer relay key.

#### Cells / multi-tenant docs
- docs/superpowers/specs/2026-11-19-tenancy-design.md mentions crypto only in two places:
  - "Tokens are RS256" (line 67), with `org_id` from the DB.
  - Argon2 timing equalisation (line 74).
- No doc in the repo mentions post-quantum, ML-KEM, ML-DSA or hybrids. The one "hybrid" hit is config.go:155, about Android v3.2 APK signers, which is unrelated.
- "cells" in the docs refers to UI table cells, not deployment cells.

#### Cross-check against OPENSSF_SERVER_CRYPTO_REVIEW.md ("Busnes-app/KyIdentity-server")
- **Stale snapshot:** the review is pinned at `5c7f65d` (2026-10-25). That commit is an ancestor of master but about a month older.
- **Dependency drift:** the review says "Consumes ky-primitives v0.10.0", which was true at 5c7f65d. go.mod now pins `v0.10.2-0.20261113220457-9f4bc5875e04`.
  - docs/STRONG-CRYPTO.md says the pin is `bae5c14dba4c`. **That doc is stale against go.mod** (`9f4bc5875e04`).
- **Still accurate:** RSA-2048 floor (crypto.go:270), ES256 device assertions, Argon2id, AES-256-GCM per-purpose row sealing, RFC 8291 push, mail MinVersion TLS 1.2 (mail.go:142), netguard using Go default transports.
- **crypto_pfs Unmet:** the review's backup point still holds. Capsules are sealed to a static recipient. The KEM is now X-Wing/ML-KEM-768+X25519 (recoverykey.go:42 @ 9f4bc58). The review cites recoverykey at a different ky-primitives commit (`1539c0c`) and does not say "PQ hybrid".
- **Not in the review (new since or omitted):**
  - The keyring with P-256 ECDH and HKDF/AES-256-GCM (PRs #295/#296).
  - The AD HPKE X25519 queue and Ed25519 entry signing.
  - VAPID ES256.
  - KyAuth push ECDSA P-256 response signatures.
  - The pairing-proof HMAC.
- **"Required fix: document supported strong-crypto configuration":** docs/STRONG-CRYPTO.md now exists (last touched by 929b69c) and documents the key floors and the `GODEBUG=fips140=on` profile. It explicitly leaves the external proxy and the Worker TLS unverified.

### Part 3: KyAuth (Android, iOS, Linux) and KyVault (backend, web): crypto inventory

#### Snapshot, toolchain and libraries

Snapshots (read via `git show origin/<branch>`): KyAuth-android `main` @ 559e687, KyAuth-iOS `master` @ f31cc76,
KyAuth-Linux `master` @ c2efea6, KyVault-backend `main` @ c0a86c2a (plus open PR #1 head 891fe945),
KyVault-web `main` @ 1344eb7. Read-only; nothing built or run.

#### Per-repo notes

**KyAuth-android (559e687).** Every pairing has two asymmetric keys: the Keystore P-256 signing key (approvals, refresh, revoke, ES256 sign-on) and the RFC 8291 P-256 receive key, generated by the app for FCM or by the UnifiedPush connector. Pairing itself has no key exchange. It is HMAC-SHA256 over a QR token (PairingProof v1), then the device's public key is registered over TLS. The vault is AES-256-GCM. Its key is wrapped two ways: by an auth-bound Keystore RSA-2048-OAEP KEK, and by PBKDF2(PIN)+Keystore-pepper AES-GCM. The RSA KEK is the only classical public-key *encryption* at rest, and it is local-only. A PQ swap there would mean an auth-bound Keystore AES key instead, which needs a prompt to wrap. TLS key exchange is whatever Conscrypt negotiates. The app adds a cert-key floor (commit 3843024, docs/native-tls-evidence.md). Specs touching crypto are docs/superpowers/specs/2026-10-07-push-mfa-binding-design.md, 2026-09-30-device-signon-attestation-design.md and 2026-09-02-signon-passkey-secure-element-design.md (passkey later removed; RemovedPasskey.kt). None mentions PQ (not exhaustively read). No open PRs.

**KyAuth-iOS (f31cc76).** Same protocol as Android. The device key is SE P-256 and the push key is a CryptoKit P-256 Keychain item shared with the KyAuthPush extension. App Attest is optional at pairing. Vault: AES-256-GCM with a 256-bit Keychain key under `.userPresence`. The PIN is a second factor (PBKDF2 310k). TLS is URLSession+ATS plus an all-chain key floor (docs/native-tls-evidence.md). No open PRs.

**KyAuth-Linux (c2efea6).** Everything is in software with OpenSSL 3: P-256 device key, P-256 push key, scrypt+AES-256-GCM vault. TLS is the most explicit of the three (SECLEVEL=2, filtered anchors, per-cert floor), but it sets no groups, so PQ status follows the Flatpak / Ubuntu Touch OpenSSL version. No open PRs.

**KyVault-backend (c0a86c2a).** This is upstream Vaultwarden. Fork-specific commits on `main`: only #2 (CI pin). The `key_id` column (migrations/*/2026-09-02-120000_add_key_id, upstream #7693) is upstream's user-key-id. The server is zero-knowledge for vault data. Its own crypto is RS256 JWTs (RSA-2048), PBKDF2 verifier, TOTP/WebAuthn/Duo 2FA, and rustls(ring) outbound TLS. **Open PR #1** (`feat/multi-tenant`, head 891fe945) adds hosted multi-tenancy, a Go worker on ky-primitives (suitedir/syncauth/oidcverify), and a "Personal Recovery Kit" stored as an opaque client-wrapped user key. It also disables org admin escrow (reset-password), Send, and by default emergency access in hosted mode. That removes several RSA-wrapped paths, but org-key sharing to members (RSA-OAEP) remains.

**KyVault-web (1344eb7).** This is a fork of the Bitwarden clients monorepo via vaultwarden/vw_web_builds@2470758. Fork commits are rebrand/theme/CI plus removal of `@bitwarden/commercial-sdk-internal`. All vault crypto is client-side in `@bitwarden/sdk-internal` 0.2.0-main.1126 (WASM). The TS layer only dispatches. Algorithm details that live in the SDK (RSA-OAEP-SHA1 for type 4, V2 Ed25519 signing, COSE XChaCha20-Poly1305) were not read here; their source is https://github.com/bitwarden/sdk-internal (unverified). As built, the KyVault-backend image does not ship KyVault-web (docker/Dockerfile.debian:30 pulls upstream `vaultwarden/web-vault:v2026.10.1`).

**Cross-check against OPENSSF_NATIVE_CRYPTO_REVIEW.md** (snapshots Android 0fce5c2, iOS d05f42c, Linux 62f76f2; all three are ancestors of current heads):
- **Stale (all three):** "the default TOTP validator accepts any non-empty decoded secret, including one byte". Current code refuses fewer than 10 bytes (80-bit) at generation/enrolment: Android TotpGenerator.kt:37-40,70 (commits cfe5d0f, then 35949da relaxed 128 to 80 bit), iOS TotpEntry.swift:103 (27dcb75), Linux totp.cpp:63,96 / totp.h:12. The `crypto_keylength` verdict is still Unmet if the review's own ≥112-bit floor applies, because 80 < 112. The stated reason is wrong.
- **Stale (all three):** "TLS certificate ... strength is delegated to platform defaults". Each app now enforces an app-level cert-key floor: Android ServerTls.kt:30-34 (3843024), iOS HTTPClient.swift:91-115, Linux crypto.cpp:232-248 + controller.cpp:64-73,789-806. Each has a native-tls-evidence doc (Android and iOS `docs/native-tls-evidence.md`). Linux EC floor is 224, not 256.
- **Incomplete:** for Android the review lists "AES256-GCM and a standard password KDF" but omits the RSA-2048-OAEP Keystore KEK (VaultKek.kt) and the ECDSA P-256 device-signing key on all three platforms. The review notes the Linux scrypt params (N=2^17, r=8, p=1), and they still match crypto.h:35-39.
- **Still accurate:** RFC 8291 P-256 push, HKDF-SHA256, AES-128-GCM content encryption, no recipient forward secrecy, HMAC-SHA1 TOTP.
- **OPENSSF_CRYPTO_PROTOCOL_SCOPE.md, "KyAuth iOS native transport evidence":** says sources "do not establish actual KyAuth URLSession acceptance or refusal" and that a native simulator run is needed. That is now stale: KyAuth-iOS docs/native-tls-evidence.md records simulator runs (e.g. run 40414013888 showing RSA-2047 accepted before the floor) and the floor in HTTPClient.swift. It points at `OPENSSF_IOS_TLS_POLICY_RESEARCH.md`, which is not in  (not checked elsewhere).

### Part 4: KyMessages (KyMessages-Native, KyMessage-Server, kymessages-desktop): crypto inventory

#### Snapshot, toolchain and libraries

These are read-only snapshots: KyMessages-Native `main` @ 9202576 (the merge of PR #56), KyMessage-Server `master` @ 439babc, and kymessages-desktop `main` @ 0c3de83 (read through the GitHub API).

**How the three repos relate.** All three are Ky's chat product.
- **KyMessages-Native** is the newer product. It has its own Go server and web client, with its own end-to-end encryption: vodozemac Olm and Megolm, built into an in-repo WebAssembly module. It has no Matrix, matrix-rust-sdk or Element. Its E2EE design says it "replaces the end-to-end encryption KyMessages lost when Element was retired" (`KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md:5-7 @ 9202576`).
- **KyMessage-Server** is the Matrix stack. A Go console and `matrix-init` run beside stock Synapse, MAS (Matrix Authentication Service), Element Web and LiveKit images, plus an optional Node meeting-notes bot.
- Both Go modules are still named `github.com/Busnes-app/ky_server_base` (see each `go.mod:1`).
- **kymessages-desktop** is an empty placeholder (see the per-repo notes).

#### Per-repo notes

#### KyMessages-Native (main @ 9202576)

**Libraries.**
- Rust: vodozemac 0.11.2 (exact pin) with wasm-bindgen 0.2.130 on Rust 1.99.0. The committed wasm is `web/src/crypto/pkg/kycrypto_bg.wasm`, reproduced in CI (PR #26).
- Go: stdlib only. `golang.org/x/crypto` v0.59.0 is only indirect. ky-primitives `b55ca6d3313c`, go-oidc v3.21.0, go-jose v4.1.9 (indirect).
- Web: WebCrypto, and livekit-client 2.25.0.
- There is no matrix-rust-sdk and no `@matrix-org/*` npm package. The spec rejects both `matrix-sdk-crypto-wasm` and libolm (`docs/superpowers/specs/2026-11-22-e2ee-design.md:11-14`).

**E2EE spec and PR state.**

| PR | State | What it specifies or builds |
|---|---|---|
| #25 | Merged 2026-11-23, `126a190` | The E2EE design (docs only): Olm/Megolm via vodozemac, a recovery key, bots as devices, on-device search, frame-encrypted calls. Guests get the call key encrypted to an ephemeral X25519 key with a 4-word code. |
| #26 | Merged, `d472438` | E1: the wasm core and key server. Migration 31 adds `e2ee_devices`, `e2ee_one_time_keys` (claim-once `DELETE … RETURNING`), fallback keys and the to-device mailbox. Uploads carry Ed25519 self-signatures. |
| #30 | Merged | Webhooks removed. |
| #31 | Merged | Server search removed. |
| #32 | Merged, `3665cba` | E2: encrypted rooms. Server refuses `plain_v1` from members (`kybot_` bots excepted). CSP adds `'wasm-unsafe-eval'`. |
| #43 | Closed unmerged | Mail rows would have carried sender device keys (migration 34). |
| #56 | Merged, `9202576` | Persistent storage request for the key store. |
| #21, #29 | Merged | Tenancy specs. These add the S3 seal key, `KY_CELLS` (no crypto: cell-scoped object paths, `KY_REGION` refused, `2026-11-22-tenancy-design.md:471-476`) and shared secrets across replicas (`2026-11-23-tenancy-design.md:149-151,313`). |
| #52 | Merged | `kye2e` build tag: a multi-tenant e2e test gate, not crypto. |

There are no open PRs.

**Not built yet.** These are E3–E6: the master key and recovery-key backup, bot devices, attachment encryption and call E2EE. The release gate forbids publishing an encryption release until E1–E5 have merged (spec §10, `:184-189`). No spec in this repo mentions PQ, ML-KEM, PQXDH or hybrid key exchange.

**PQ migration points.**
- Olm session setup is the only HNDL path for room content. A PQXDH-style Olm would need upstream vodozemac work (see below), or an in-repo hybrid KEM layered into `web/crypto`.
- Web Push RFC 8291 is fixed by the standard (P-256 only).

#### KyMessage-Server (master @ 439babc)

**Libraries.**
- Go: stdlib, with `crypto/rsa`, `ecdsa`, `ed25519`, `x509` and `tls` used only in `matrixinit` for key generation and checks. ky-primitives `875f57b13976`, go-oidc v3.21.0, go-jose v4.1.9.
- Images (`docker-compose.matrix.yml`):
  - Synapse v1.162.0 (`:158`)
  - MAS 1.26.0 (`:201`)
  - Element Web v1.12.30 (`:222`)
  - LiveKit v1.13.7 (`:243`)
  - Postgres 17.12 / 18.7
- Notes bot (`notes/package-lock.json`): matrix-js-sdk 44.0.0, crypto-wasm 18.9.2, @livekit/rtc-node 1.2.2.

**PRs.** There are no open PRs. There is no Server spec PR about E2EE or PQ.
- #97 (merged 2026-10-27) added the strong-key profile (`docs/STRONG-CRYPTO.md`, `docker-compose.strong-crypto.yml`) and key floors.
- #145 creates an encrypted room per suite group. That is Matrix room encryption: Element/Megolm, not new crypto.

**Other points.**
- There is no `KY_REGION`, `KY_CELLS` or per-org key in this repo. It runs one Matrix stack per deployment.
- There are no mobile apps in these repos, so there is no Keychain or Keystore anywhere. Every E2EE client here is a browser or the Node bot.

#### vodozemac / matrix-rust-sdk PQ status (external, primary sources)

- **vodozemac 0.11.2** (tag commit `fb4a9980a103`, used by Native and the notes bot) has no PQ support. Its `Cargo.toml` features are `wasm_js`, `libolm-compat`, `precomputed-tables`, `insecure-pk-encryption`, `experimental-session-config` and `low-level-api`, with no KEM dependency ([Cargo.toml@0.11.2](https://github.com/matrix-org/vodozemac/blob/0.11.2/Cargo.toml)). Its CHANGELOG has no match for kyber, ml-kem, pqxdh or quantum ([CHANGELOG@0.11.2](https://github.com/matrix-org/vodozemac/blob/0.11.2/CHANGELOG.md)). The `main` CHANGELOG has no match either.
- **Unreleased experiment.** The upstream branch `poljar/pq` has its last commit `cb67385ef53c` on 2024-01-30 ("Implement Serialize/Deserialize and Debug for the KyberPublicKey type"). It is not in any release ([branch](https://github.com/matrix-org/vodozemac/tree/poljar/pq)). There is also an `interolm` branch.
- **matrix-sdk-crypto 0.19.1** (in crypto-wasm 18.9.2): the CHANGELOG at tag `matrix-sdk-crypto-0.19.1` has no match for kyber, ml-kem, pqxdh, quantum or hpke ([CHANGELOG](https://github.com/matrix-org/matrix-rust-sdk/blob/matrix-sdk-crypto-0.19.1/crates/matrix-sdk-crypto/CHANGELOG.md)).
- **Element's chain** (vodozemac git `cfc4eee`, 0.10.0) predates 0.11.2, and 0.11.2 has none, so it has no PQ.

#### Stale claims in the earlier reports (checked against current code)

**`OPENSSF_KYMESSAGES_CRYPTO_BOUNDARIES.md`** (snapshot `feb4f95`, 2026-10-26):
- *"matrix-init TURN loader validates … but not algorithm/bit strength"*: **stale.** `strongPublicKey` now checks every chain certificate (`KyMessage-Server:internal/matrixinit/matrixinit.go:629-640,724-731 @ 439babc`).
- *"MAS keystore … without a MAS-specific bit floor"*: still true of MAS itself. However, `matrix-init` now refuses a kept RSA key under 2048 bits before rendering (`:611-627`).
- *"Preflight retained key/secret files …"* (safe next action 1): **done.** See `hmacKey`, `masEncryptionKey` and `rsaSigningKey` (`:594-627`), and the console JWKS floor (`internal/sso/jwks_strength.go:16,64`).
- *Notes bot uses `@livekit/rtc-node` 1.1.0*: **stale.** The pin is now 1.2.2 (`notes/package.json:14`). The code comment at `notes/src/meeting.mjs:13` still refers to 1.1.0.
- **Still accurate:**
  - the image pins;
  - Element v1.12.30 pinning matrix-js-sdk 43.0.0 (I re-checked this);
  - crypto-wasm 18.7.0 resolving matrix-sdk-crypto f333a324 and vodozemac cfc4eee (I re-checked this);
  - Synapse's federation minimum TLS left at its default (no override in `homeserver.yaml.tmpl`);
  - the LiveKit DTLS RSA-1024 peer gap (`docs/STRONG-CRYPTO.md:137-139` says the same).

**`OPENSSF_SERVER_CRYPTO_REVIEW.md`, KyMessage-Server section** (snapshot `7217e0f`):
- *"randomly generated TOTP secrets"* and *"RFC6238 TOTP"*: **stale.** Local TOTP has been removed (`docs/ASSURANCE-CASE.md:110`; `docs/STRONG-CRYPTO.md:42-43`), and no non-test Go code imports `ky-primitives/totp`.
- *"Consumes ky-primitives v0.10.0"*: **stale.** The pin is now `v0.10.2-0.20261116015712-875f57b13976`.
- *"requires only a nonempty KY_SESSION_SECRET in production"*: **stale.** There is now a `MinSessionSecretBytes` floor (`internal/config/config.go:215`).
- *"KY_KYSIGNON_HMAC_SECRET"*: **renamed** to `KY_KYIDENTITY_HMAC_SECRET` (`config.go:316`).
- *"Publish a concise supported strong-crypto profile"*: **done** in PR #97 (`docs/STRONG-CRYPTO.md`).
- *"suite recovery fixed to X-Wing/AES256-GCM"*: still accurate (ky-primitives `recoverykey.go:42 @ 875f57b`).

**Inside the repos:**
- `KyMessage-Server:docs/STRONG-CRYPTO.md:20-21` says ky-primitives is pinned to `bae5c14dba4c`. That is **stale**: `go.mod` pins `875f57b13976`.
- `KyMessages-Native:docs/superpowers/specs/2026-11-23-tenancy-design.md:149` cites `internal/config/config.go:259-267` for the encryption key. That is **stale**: the code is now at `:352-366`.
- The OpenSSF reports cover only KyMessage-Server (the Matrix stack). **KyMessages-Native has no equivalent review**, and its Olm/Megolm, Web Push, VAPID, S3 seal and LiveKit paths are not in either report.

### Part 5: KyDrive (server, Android, desktop), KyNotes (server, desktop), KyRecovery-server

#### Snapshot, toolchain and libraries

Read-only inventory. Code read only through `git grep` and `git show` on `origin/<branch>` (and, for one unpushed local branch, its ref; see Per-repo notes). Nothing was fetched, built or run.

Snapshots: kydrive-server `master` @ 9d5a468, KyDrive-for-Android `main` @ 60e755b, kydrive-desktop `main` @ 9596d67, KyNotes-server `master` @ 88c85c8, KyRecovery-server `main` @ 45dfe28, kynotes-desktop `main` @ b357111 (gh api). ky-primitives as pinned by kydrive-server: b5f5853 (`v0.10.2-0.20261124022836-b5f5853be771`).

#### Per-repo notes

#### kydrive-server

- **Libraries (go.mod @ 9d5a468):**
  - Go 1.26.9, toolchain go1.27.3. The Docker builder is golang:1.27.4.
  - filippo.io/age v1.3.2, filippo.io/hpke v0.4.0 (indirect), golang.org/x/crypto v0.59.0 (indirect).
  - coreos/go-oidc/v3 v3.21.0, go-jose/v4 v4.1.9, aws-sdk-go-v2 v1.48.0 with service/s3 v1.116.0.
  - ky-primitives b5f5853: capsule, recoveryclient, password, syncauth, keyfile, applysetup, suitedir, netallow.
  - No CIRCL, no libsodium.
- **Key hierarchy today:** one 32-byte deployment key, with HKDF-SHA256 subkeys per purpose.
  - Labels: `kydrive:kyb2:*` per file stanza, `kydrive:name`, `kydrive:name-hmac`, `kydrive:key-check`, `kydrive:search-*`, `kydrive:restic`, the WebDAV lock labels, and recoveryclient's sealer labels.
  - Per-file random age file keys sit under the deployment-key-derived wrap.
  - No asymmetric encryption is used at rest anywhere.
  - The only asymmetric secrecy is the capsule, which is X-Wing (PQ-hybrid).
- **Signatures:** Ed25519 (TLS pin rollover, server-side), ECDSA P-256 (device requests, verified server-side), RS256 (IdP tokens, verified) and Sigstore (releases).
- **No TLS termination.** KyDrive's inbound HNDL exposure is the reverse proxy's. Outbound Go clients use Go defaults, which offer X25519MLKEM768 first.
  - The only `tls.Config` is the probe at tls_pin.go:170, with MinVersion only.
  - `GODEBUG=fips140=on` (optional, and run in CI per ci.yml:55) keeps the hybrid groups. That is verified in local go1.27.3 source at crypto/tls/defaults_fips140.go:35-43.
- **Step K (per-org data keys).** No open PR: `gh pr list --state open` returns none, and #170 merged the design. No pushed branch either.
  - Spec: docs/superpowers/specs/2026-11-20-tenancy-design.md:70 (D14), :486-521 ("Per-org data keys") and :1257-1276 (build step K).
  - The spec amendment's status line (:3) says the D14 amendment "awaits the owner's approval".
  - The work exists only as a **local, unpushed branch `feat/per-org-keys`** in ~/git/kydrive-server, with commits 352cb51 "wip: per-org keys", dd5a93b, 29bbb13 and ac85499 "wip: docs", dated 2026-11-25 19:23-19:44 -05:00. That is 72 files, +1056/-248, including the new internal/drive/orgkeys.go and orgkeys_test.go.
  - I read it through git objects only. Another worker owns it, so treat it as in flux.
  - **Wrapping algorithm:** AES-256-GCM, random nonce, AAD `kydrive:org-key:<kek>:<org_id>`. The KEK is HKDF-SHA256(deployment key, `kydrive:org-kek`).
  - **KMS:** none. The owner decided the KEK is the deployment key, with no KyIdentity-held key and no BYOK. The spec leaves `kek` as a version column for a later rewrap or a "two-part KEK with KyIdentity", and the branch refuses any `kek` other than 1.
  - **Recovery key use:** the org keys are not wrapped to the recovery key directly. The `drive_org_keys` table is copied into multi-tenant snapshots and capsules (branch spec text: "a capsule restore brings every key back"). The capsule also carries the deployment key and is sealed to the X-Wing recovery key, so recovery of org keys reduces to X-Wing.
  - The spec notes that backups keep wrapped keys until their retention ends (tenancy spec :1433-1435), so crypto-shredding is incomplete for backups.
  - Search keys are not yet per org; content search stays off in multi mode until R2.
- **E2E vault spec (draft, 2026-11-22):**
  - It is the only planned PQ design in these repos: age `mlkem768x25519` recipients plus Ed25519+ML-DSA-65 hybrid signatures.
  - The desktop has no age implementation, and Android needs ML-DSA (spec :50,56).
- **Postgres TLS:** set by the DSN `sslmode` (docs/STRONG-CRYPTO.md). No code-level TLS.

#### KyDrive-for-Android

- **Libraries:**
  - BouncyCastle bcprov-jdk18on 1.87, used only for Ed25519, because JCA has EdDSA only from API 33 (build.gradle.kts:96-97). bcpkix 1.87 is used in tests only.
  - Platform JCA/AndroidKeyStore and Conscrypt for TLS.
  - No Tink, no security-crypto.
- **No client-side file encryption.** The token and keys are Keystore-backed: AES-GCM 256 for the session, EC P-256 for signing, HMAC-SHA256 for the PIN pepper.
- **No release signing config in the repo.**
- **TLS:** platform default groups. Whether Android offers X25519MLKEM768 is unverified, so I marked it HNDL.

#### kydrive-desktop

- **Libraries:**
  - Go stdlib only for crypto (core/go.mod: go 1.26.11, `godebug fips140=on`, no toolchain line).
  - zalando/go-keyring v0.2.8, plus danieljoos/wincred v1.2.3 and godbus v5.2.4 (indirect).
  - Shells (Qt/QML on Linux, Swift on macOS, C#/WinUI on Windows) do no crypto. The core holds every token (macos/AGENTS.md:14).
- **Cross-check with OPENSSF_NATIVE_CRYPTO_REVIEW.md (kydrive-desktop section).** That review pins 7cbab3f (go 1.26.10), which is 143 commits behind 9596d67. Stale claims:
  - **"crypto_keylength: Unmet … no application minimum-key policy" is stale.**
    - 92c0c2b "fix: enforce strong TLS defaults in the sync core (#18)" added `godebug fips140=on` to core/go.mod.
    - Under Go's FIPS mode the TLS client accepts only RSA-2048+, P-256/384/521 or Ed25519 chain keys. That is per kydrive-server docs/STRONG-CRYPTO.md and https://go.dev/doc/security/fips140. I did not re-test a trusted RSA-1024 leaf against 9596d67 (unverified).
  - **"No bespoke cryptographic key agreement … only cryptographic key agreement found is Go TLS"** still holds for key agreement. The code now also does ECDSA P-256 request signing (2d100d3, #53) and Ed25519 signed TLS pin rollover with SPKI pinning (1066f7d, #55). The review does not mention either.
  - The review cites only link.go, daemon.go and go.mod. It does not cover core/api/sign.go, tlspin.go or credential.go (the keyring layout).
  - The review's PFS reasoning (ECDHE / TLS 1.3) still holds. With go 1.26.11 the default first key share is X25519MLKEM768, which the review does not mention.

#### KyNotes-server

- **Libraries:**
  - Go 1.26.9 with toolchain go1.27.4.
  - cloudflare/circl v1.6.5 (HPKE, in the Go reference and the MCP bridge only; the server never imports teamkeys, per doc.go:4).
  - golang.org/x/crypto v0.59.0, pkg/sftp v1.13.12 (tests).
  - ky-primitives b55ca6d (`v0.10.2-0.20261124003741-b55ca6d3313c`) and ky-primitives/offsite v0.3.0.
  - Web: @hpke/core 1.10.1, @hpke/dhkem-x25519 1.8.1, @hpke/chacha20poly1305 1.8.1, @noble/ciphers, curves and hashes 2.4.0, and WebCrypto (AES-GCM, PBKDF2).
- **This is the one product in the part with classical asymmetric E2EE key distribution:** HPKE mode_auth over X25519, both v3 and legacy v2.
  - Envelopes are stored server-side, so they are fully harvestable.
  - Any PQ migration means moving to a hybrid KEM, for example HPKE X-Wing as ky-primitives already uses. HPKE auth mode has no PQ KEM equivalent in RFC 9180, so sender authentication would need a signature (for example ML-DSA hybrid) or a separate design.
  - The repo has no PQ plan: no hits for ML-KEM, X-Wing or post-quantum.
- **Per-org keys:** none, and none planned. "Org keys" in internal/blobstore/AGENTS.md:61 and DESIGN.md:1013 are object-storage key prefixes, not encryption keys.
  - The tenancy spec (docs/superpowers/specs/2026-11-23-tenancy-design.md, merged #176) relies on E2EE: "the provider sees only ciphertext". No open PRs.
  - Many local tenancy branches exist (feat/tenancy-*). None of them carries data-key work (no commits match "per-org|org key|data key" except a purge PR).
- **Cross-check with OPENSSF_SERVER_CRYPTO_REVIEW.md, KyNotes-server section (pinned 1e007d4).** Stale claims:
  - "Consumes ky-primitives v0.10.0 and offsite v0.2.2". Now it is ky-primitives b55ca6d and **offsite v0.3.0**.
  - "crypto_weaknesses: Unmet — Optional offsite SFTP leaves x/crypto algorithm policy unset; defaults permit SHA1 KEX…".
    - offsite v0.3.0 sftp.go:69-75 now sets `ssh.SupportedAlgorithms()` for KEX, ciphers, MACs and host keys. In x/crypto v0.59.0 that list excludes the insecure SHA-1 and DSA algorithms and starts with mlkem768x25519-sha256.
    - It also checks key strength (`strongSFTPKey`).
    - This finding looks resolved (re-review needed).
  - "SMB/NTLM … no informed compatibility opt-in" is partly stale. SMB is now refused under `GODEBUG=fips140=on` (internal/config/blob_target.go:48-52), and offsite v0.3.0 README:79-84 documents the NTLMv2 risk.
  - The review's facts on envelopes (two-DH legacy, HPKE) and recipient-PFS still match. The current v3 envelope is RFC 9180 mode_auth (teamKeys.ts:10). That partly answers the review's "publish a mapping to a reviewed construction" item for v3; v2 remains custom (read only).
  - There is also a docker-compose.strong-crypto.yml (fips140=on), which the review predates or does not mention (unverified which).

#### kynotes-desktop

- An empty repo (README.md and LICENSE, one commit b357111, pushed 2026-11-23).
- Nothing to inventory. The README promises "offline, end-to-end encrypted notes", so it will inherit KyNotes' X25519 envelope exposure unless the design changes.

#### KyRecovery-server

- **Libraries:**
  - Go 1.26.9 with toolchain go1.27.4.
  - ky-primitives v0.10.1 and offsite v0.3.0.
  - coreos/go-oidc v3.21.0, go-jose v4.1.9, x/crypto v0.59.0 (ssh, hkdf), pkg/sftp v1.13.12, cloudsoda/go-smb2 (95be04a983b8), aws-sdk-go-v2 v1.48.0.
- **How it uses recoverykey:**
  - Only the ceremony WASM calls `recoverykey.Generate` and `Split`. It runs in the browser, and the private seed is handed only to Shamir.
  - The server calls `recoverykey.ParsePublicKey` on import (internal/server/recoverykey.go:50).
  - What is sealed to whom: every product (KyDrive, KyNotes, and the others) seals its kycap/3 capsule to the suite X-Wing public key. KyRecovery stores and replicates the ciphertext as a blind store (no decrypt path).
  - Restore happens in the product: the custodian shares are combined, for example in KyNotes cmd/kynotes-server/backup.go:180-188.
- **Restic:**
  - KyRecovery runs restic/rest-server 0.14.0 (append-only, private repos, TLS) through an overlay, and reads its data directory read-only for status.
  - Repository passwords belong to the products (KyDrive: HKDF(deployment key, `kydrive:restic`), hex). KyRecovery derives no restic key.
- **No pg_dump, age or manifest signing in KyRecovery.**
- **Cross-check with OPENSSF_SERVER_CRYPTO_REVIEW.md, KyRecovery section (pinned 9883d94).** Stale claims:
  - "Consumes ky-primitives v0.10.0 and offsite v0.2.2". Now it is **v0.10.1 and offsite v0.3.0**.
  - "crypto_weaknesses: Unmet — Both the offsite v0.2.2 client and the separate absolute-directory compatibility SFTP client leave SSH algorithm lists unset … Updating only the shared dependency will not repair internal/replication/sftp.go".
    - Now internal/replication/sftp.go:89-91 sets `ssh.SupportedAlgorithms()`, and sftp.go:222-243 enforces RSA-2048, ECDSA and Ed25519 key checks.
    - docs/STRONG-CRYPTO.md:15-27,88 documents this.
    - It looks resolved (re-review needed).
  - The SMB/NTLM "no informed compatibility mode" claim is stale. SMB is refused under fips140=on (internal/replication/offsite.go:188-192), and docs/STRONG-CRYPTO.md:113-135 documents an explicit SMB compatibility section.
  - "no custom TLS config was found in this repository" still holds (no `tls.Config` in non-test Go code).

#### kydrive-server: cross-check with OPENSSF_SERVER_CRYPTO_REVIEW.md (pinned c8b46b2, 2026-10-25)

- **Stale:** "Consumes ky-primitives v0.10.0". It is now pseudo-version v0.10.2-…-b5f5853.
- **Stale:** "internal/config/config.go requires only a nonempty KY_SESSION_SECRET in production". docs/STRONG-CRYPTO.md, added in 461d9c8 "security: enforce key floors and add the strong-key TLS profile", says secrets below 16 bytes are refused at startup. So are `KY_KYSIGNON_HMAC_SECRET` below 16 bytes and `KYDRIVE_EDITOR_SECRET` below 32 bytes, and RSA JWKS keys below 2048 bits are refused. The c8b46b2 tree has no docs/STRONG-CRYPTO.md.
- **Stale:** "Publish a concise supported strong-crypto profile". That profile is now docs/STRONG-CRYPTO.md (key table, fips140 overlay, HTTPS edge, out-of-scope list). The review's crypto_keylength "?" can probably be re-evaluated.
- **Stale or misleading:** "randomly generated TOTP secrets". Local MFA was removed. The `mfa_challenges` table is unused (tenancy spec :111), and only test fixtures still mention TOTP (internal/api/mfa_test.go). No production TOTP code was found.
- **Not mentioned by the review:**
  - The Ed25519 TLS-pin identity key and the ECDSA P-256 device request signatures.
  - S3 object storage (tenancy R2c, #175).
  - Per-org key work (step K, unpushed).
- **Still accurate:** age v1 with a deployment-derived wrap, HKDF/AES-256-GCM names, Argon2id, and the PFS exception for capsules.

### Part 6: kyguard-server, KyDNS-server, KyCalendar, KyPulse-server, KyYard-server, go-webdav

#### Snapshot, toolchain and libraries

Read-only inventory. Code was read with `git grep` / `git show` at these heads: kyguard-server `main` @ 37b302b, KyDNS-server `main` @ cdaae83, KyCalendar `main` @ 7bce306, KyPulse-server `master` @ 7a45d37, KyYard-server `master` @ 8148a97, go-webdav `kycalendar` @ 7f1337b. Branch-only code is labelled with its branch and SHA.

Go toolchains: every repo builds with `toolchain go1.27.4` (kyguard-server, KyCalendar, KyDNS-server, KyPulse-server, KyYard-server go.mod). Where a `tls.Config` sets no `CurvePreferences`, Go's default list applies. That default has preferred X25519MLKEM768 since Go 1.24 (https://go.dev/doc/go1.24#crypto-tls). The table marks those rows "PQ-hybrid already" for key exchange, with the caveat that the peer must also support it.

#### Per-repo notes

#### kyguard-server: what the spec says

The cache copy `KYGUARD_PAM_DESIGN_SPEC.md` is byte-identical to in-repo `docs/SPEC.md` @ 37b302b (`diff` was empty), so the line numbers below apply to both. Status: v2.4, Phase 0/1A normative (line 3).

- **PQ hybrids.**
  - §3.1 table, line 55: "Key encapsulation | X-Wing (ML-KEM-768 + X25519), HPKE base mode, HKDF-SHA256, AES-256-GCM | stdlib `crypto/hpke` with `hpke.MLKEM768X25519()`".
  - Line 57: "Signatures | ML-DSA-65 and Ed25519, both required | stdlib `crypto/mldsa` (Go 1.27) and `crypto/ed25519`".
  - Line 61: "no third-party crypto dependency".
  - Line 497 (threat model): "Harvest now, decrypt later: X-Wing HPKE, hybrid signatures, PQ key exchange on the broker listener".
- **Signed object header.**
  - Line 68: `HybridSig = {"alg":"mldsa65+ed25519",...}`. ML-DSA-65 uses an empty context, Ed25519 is pure (not ph), and both must verify.
  - Line 69: HybridPub (1952-byte ML-DSA pk, 32-byte Ed25519 pk).
  - Line 70: `sig_key_id` = SHA-256 over both pks.
  - Line 84 onwards: header fields type, deployment_id, epoch, scope, signer_role, signatures. The digest excludes signatures and approvals (line 67, domain-separated SHA-256 over JCS).
  - Lines 95-105: per-object signer table (M-of-N custodians for manifests, user, broker, cnf).
  - Line 123: custodian keys are Argon2id-wrapped software files, because "Hardware-held custodian keys wait for tokens that support ML-DSA".
- **Secret envelopes.**
  - HPKE with the X-Wing KEM, which is HPKE KEM `MLKEM768X25519`.
  - Line 81: DEK wrap via `hpke.NewSender(pk, HKDFSHA256, AES256GCM, "kyguard/1/dek-wrap")`, then `Seal(aad, dek)`. `enc` is 1120 bytes.
  - Line 199: envelope body (AES-256-GCM ciphertext plus a recipients list).
  - Line 210: recipient-set rules, with optional recovery escrow.
  - Line 71: `enc_key_id` = SHA-256 of the 1216-byte X-Wing pk.
- **Broker pairing.**
  - Line 263: separate TLS listener `tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}`.
  - Lines 265-269: one-time 10-minute token stored hashed, encoding the URL, the secret and the internal CA SHA-256. The broker generates its TLS key, hybrid signing key and X-Wing key locally and sends a CSR. The CP signs with the internal CA and binds broker_id.
  - The spec does not name the CA or leaf algorithm. Code uses Ed25519 (ca.go:69-84).
- **SSH certificates.** There is no SSH CA in Phase 0/1A. "SSH certificates" appears only as a Phase 4 JIT entitlement (line 351) and in the D.5 connector matrix (line 626). No CA algorithm (ed25519 or other) is specified.
- **Target SSH KEX.**
  - Line 320: "Dial with `golang.org/x/crypto/ssh`; the host-key callback compares SHA-256 of the wire-format host key with `ssh_host_key_sha256`". The spec says nothing about KexAlgorithms.
  - The code (branch `kyguard/connector-ssh` @ d6b7781, PR #14) sets neither `KeyExchanges` nor `HostKeyAlgorithms`. x/crypto v0.59.0 therefore offers `mlkem768x25519-sha256` first (ssh/common.go:98-106 in the module cache), which should negotiate with an OpenSSH 10 target.
  - The default list also includes `diffie-hellman-group14-sha1` and classical fallbacks. Nothing pins the PQ KEX, so a MITM-free downgrade happens only against old targets. The host key is pinned, so active downgrade is blocked by the host-key signature check.
- **Session recording.** §5, line 348, Phase 3: "recordings sealed to designated auditor keys and the recovery key, never readable by the Control Plane". D.4, line 616: "Recordings (`asciicast v2`, `kyrec/1`) chunked and sealed to designated auditor keys and the recovery key, never to the broker". No algorithm is stated. Presumably the §3 envelope applies, but that is unverified. No code exists.
- **Audit chain.** §9.3, line 455: chain key = `hkdf.Key(sha256.New, key, nil, "kyguard:auditchain", 32)` from `data/encryption.key`, using ky-primitives auditchain, which is HMAC-SHA256. Line 499: "Audit tampering: HMAC chain". Line 463: no external anchor in Phase 0. D.8 (line 644) plans signed checkpoints, algorithm unspecified.
- **Backup.**
  - §9.4, lines 467-471: base `.kycap` capsule sealed to the verified KyRecovery key. It carries `encryption.key`, `recovery.pub`, `broker-ca.key` and `broker-ca.crt`.
  - Line 468: recovery key and topology are frozen until migration ships.
  - Line 470: envelopes stay sealed to their own recipients.
  - Line 471: optional external `pg_dump` / pgBackRest / WAL-G.
  - D.7 (lines 636-641): recovery-key migration, deferred.
- **D.0** (line 586): v2.1 removed CP-held governance and maintenance signing keys. **D.1** (lines 591-593): multi-broker `rewrap_infra`, plus "Broker-to-broker mTLS gossip of signed `EpochCheckpoint`s". Neither names an algorithm.
- **TOTP secrets** (line 375): stored with AES-256-GCM via `recoveryclient.NewAESGCMSealer`.

#### kyguard-server: code on main versus spec-only

- **On main @ 37b302b:**
  - `internal/pqcrypto` (hybrid sig, X-Wing DEK wrap, envelopes, receipts, manifests, tx, golden vectors).
  - `internal/brokerproto` (Ed25519 internal CA, PQ-hybrid TLS listener, pairing).
  - `internal/broker` (keys, journal, rotation machine).
  - `internal/cli` (Argon2id key files).
  - Audit chain, TOTP, backup.
- **Branch-only (open PRs):**
  - Connectors: #13 AD (`kyguard/connector-ad`) and #14 SSH (`kyguard/connector-ssh`). There is no `internal/connectors` on main.
  - #12 scheduler, #15 enroll, #16 checkout. Also #20-#24 and #28 (inventory, scorecard, web).
  - Other branches: `kyguard/pqcrypto-envelopes`, `-manifests` and `-wire` (heads 57d4a01, 5f71eb9, 4f5a1c5; pqcrypto content already appears on main), and `kyguard/audit-chain` @ 896dc31 ("Broker audit records join the hash chain").
- **Spec-only (no code):** session proxy and recording (Phase 3), JIT and SSH certificates (Phase 4), the browser `pqcrypto.wasm` (D.9), the external audit anchor (D.8), multi-broker gossip (D.1) and recovery-key migration (D.7).
- **FIPS profile:** CI runs with `GODEBUG=fips140=on` (ci.yml:115, :159), and docker-compose.strong-crypto.yml:6 sets it. Under fips140=on, Go is believed to keep X25519MLKEM768 and drop plain X25519 (unverified for go1.27.4). The x/crypto ssh comment (kex.go:407) says mlkem768x25519 works with fips140=on but not fips140=only.

#### KyDNS-server

- KyDNS is a recursive/forwarding resolver with DNSSEC validation only.
  - There is no zone signing, KSK/ZSK or DNSSEC key storage, and no TSIG or zone transfer.
  - DoT and DoH exist only as upstream clients. No DoT/DoH server listener was found: no `tcp-tls` server, no `ListenAndServeTLS`.
- `cloudflare/circl` v1.6.5 is a direct dependency, used only for Ed448 verification (internal/dnssec/ed448.go). At review snapshot f41d491 it was indirect (v1.6.3).
- DNSSEC signatures are classical by protocol. The PQ story depends on IETF/IANA, with no PQ DNSSEC algorithm assigned (unverified as of this date).
- Replica pairing deliberately avoids a PAKE. Fingerprint confirmation by eye happens first (pake-selection spec).
- ky-primitives is v0.10.1 (go.mod).

#### KyCalendar

- At-rest content encryption is designed (docs/superpowers/specs/2026-11-22-content-encryption-design.md) and the library exists on main (`internal/contentkey`, X-Wing). It is explicitly not wired: "Nothing in the server uses these formats until build step CE2" (CONTENT-ENCRYPTION-FORMAT.md:8).
- Branches: `content/ce1a-keys` @ f78d25b (not an ancestor of main) and `content/ce1c-schema` @ 322b212 (not merged; the CE1c schema). `content/ce1b-skeleton` and `docs/content-encryption-spec` are merged. There are no open PRs (`gh pr list` returned `[]`).
- KyCalendar has no audit hash chain (no `auditchain` import).
- No iCal share-link or public-feed token feature was found. `internal/feed` handles inbound subscriptions to external ICS URLs, sealing the URL at rest.
- The legacy `totp_secret_enc` column exists (migrations.go:35), but no TOTP code was found.

#### go-webdav

The fork carries no crypto. KyCalendar's vendored copy (third_party/go-webdav, commit 7f9258bf) lags the fork branch head 7f1337b. The later commits are CI-only per `git log`.

#### KyPulse-server

- No outbound webhook signing (HMAC) exists. Webhooks are ntfy, Gotify, Discord or generic JSON, with optional Bearer. Only the KyPost send path is HMAC-signed (syncauth).
- It has its own audit-chain key, separate from the encryption key.
- No TOTP code was found (no `totp.` calls).

#### KyYard-server

- The agent protocol uses classical Ed25519 throughout: enroll, challenge, auth, rotate.
- Confidentiality of agent traffic rests entirely on TLS ≥1.2 with Go default curves. No `CurvePreferences` override exists in any of the five repos except kyguard's broker listener.

#### Cross-check against OPENSSF_SERVER_CRYPTO_REVIEW.md

Review snapshots: KyCalendar 772cc88, KyDNS f41d491, KyPulse 56aab1c, KyYard 5134c32.

- **All four:** the review says "Consumes ky-primitives v0.10.0". That is now stale:
  - KyCalendar: v0.10.2-0.20261124022836-b5f5853be771
  - KyDNS: v0.10.1
  - KyPulse: v0.10.2-0.20261114135120-7f9c247b0fbd
  - KyYard: v0.10.2-0.20261026050236-bae5c14dba4c

  The crypto_pfs "Unmet" rationale (HPKE capsules to a long-term recipient) still holds. The capsules are X-Wing, so they are PQ-hybrid but not forward-secret.
- **KyCalendar** (review lines 138-186):
  - The review's TLS ≥1.2 discovery claim still holds (discovery.go:68).
  - The review says "requires only a nonempty KY_SESSION_SECRET in production". Current code enforces ≥16 bytes (config.go:374), and KY_KYSIGNON_HMAC_SECRET is also ≥16 bytes (config.go:378).
  - The review does not mention `internal/contentkey` (added since). It also lists TOTP among the mechanisms, but no active TOTP code was found.
  - docs/STRONG-CRYPTO.md exists on main. Whether it fully satisfies the review's "publish profile" fix was not checked.
- **KyDNS** (review lines 187-234):
  - Still accurate on replica TLS 1.3 plus the Ed25519 pin (transport.go:66), DoT/DoH TLS ≥1.2 (dot.go:101), and health InsecureSkipVerify (checker.go:235).
  - It predates the DNSSEC validator and the direct circl/Ed448 dependency, which add new signature-verification surface (alg 8/10/13/14/15/16).
- **KyPulse** (review lines 486-534):
  - The egress TLS ≥1.2 claim still holds (egress.go:81). The 16-byte floor for KYPULSE_SESSION_SECRET and KYPULSE_KYSIGNON_HMAC_SECRET is now enforced (config.go:189-193).
  - The review omits the HMAC audit chain and its separate audit key.
  - The review mentions TOTP, but none was found in code.
- **KyYard** (review lines 585-632):
  - The agent TLS ≥1.2 (cmd/agent/main.go:203) and registry TLS ≥1.2 (registry/client.go:116) claims still hold.
  - The review says "private loopback agent-only challenge auth uses HMAC and Ed25519". In code, HMAC derives the Ed25519 seed (local_docker.go:42-44). It is not a MAC-based auth.
  - The KY_KYSIGNON_HMAC_SECRET ≥16-byte floor is enforced (config.go:181).

### Part 7: infrastructure (KyQuickStart, KyQuickStart-AI, the private infra repo, the private launch repo)

#### Snapshot, toolchain and libraries

Revisions read (origin, read-only, via `git show`/`git grep`): KyQuickStart master @ 950c3f8, KyQuickStart-AI master @ 3a7b8ef, the private infra repo master @ 2495cdf, the private launch repo main @ a5339f2.
Short names: KQS = KyQuickStart, KQA = KyQuickStart-AI, infra = the private infra repo, launch = the private launch repo.

#### Per-repo notes

**KyQuickStart (950c3f8)**
- Crypto library graph: stdlib `crypto/{ecdsa,elliptic,ed25519,rsa,rand,sha256,tls,x509}`, `golang.org/x/crypto v0.59.0` (ssh, ssh/agent, ssh/knownhosts), `github.com/Busnes-app/ky-primitives v0.10.1` (only `keyfile`), `filippo.io/edwards25519 v1.2.0` (indirect), client-go v0.37.2. Toolchain go1.26.11 (KQS:go.mod; Dockerfile:4 `golang:1.26.11`).
- No `CurvePreferences`, `ssl_ecdh_curve`, `ssl_conf_command` or `ssl_groups` anywhere (git grep). Nothing in KQS drops X25519MLKEM768 or the SSH ML-KEM KEX. The only explicit SSH algorithm list (ssh.go:81) is x/crypto's own supported set, which leads with mlkem768x25519-sha256.
- `GODEBUG=fips140=on` is the documented profile (docs/STRONG-CRYPTO.md, Dockerfile:27, backup.go:88). On Go 1.26 it keeps X25519MLKEM768 and SecP*MLKEM* and removes plain X25519. For SSH it keeps mlkem768x25519 and drops curve25519-sha256, so against a pre-9.9 OpenSSH server the fallback is ECDH P-256.
- The only PQ weak spot in the stack KQS deploys is the CNPG Postgres link: PG17 defaults to a P-256-only group, and PG18 (open PR #217 `chore/postgres-18-cnpg`, PR #216 `chore/postgres-18`) defaults to `X25519:prime256v1`. Both are classical. Fix: set `ssl_groups` (PG18) to include `X25519MLKEM768` once the image's OpenSSL is ≥3.5. The trixie-based CNPG image suggests OpenSSL 3.5 (unverified).
- The DB CA is ECDSA P-256 with a 10-year life and no renewal. Any later move to ML-DSA certificates would need a re-issue path that does not exist today (dbcluster.go:44).
- Cross-check against OPENSSF_CRYPTO_PROTOCOL_SCOPE.md (written at ceb0de4): still accurate. SSH is x/crypto/ssh, runner key is crypto/ed25519, the only ky-primitives import is `keyfile`, and restic is pinned at 0.19.1. New since then, and not in that doc: the installer-generated ECDSA P-256 database CA (dbcluster.go), the cert-manager Issuer and nginx edge, and the fips140 runner/restic profile.
- No WireGuard, Rosenpass, Tailscale, k3s/kind token generation, or internal CA beyond the DB CA. `test/e2e/sshd/Dockerfile` runs sshd with only `-h host_ed25519` and no algorithm overrides (test-only).

**KyQuickStart-AI (3a7b8ef)**
- Bash launcher; all crypto is in OpenSSH, kubectl and gh. `bin/ssh-policy` implements the subtractive fragment proposed in OPENSSF_AI_CRYPTO_RESEARCH.md almost verbatim. Line numbers in that doc are stale: keygen is now kyqs-ai:74 (doc: :60/:67) and the SA token is kyqs-ai:306 (doc: :270). Since that doc, `RequiredRSASize`, `ControlPath none` and the `KYQS_SSH_CONFIG` profile have been implemented (docs/STRONG-SSH.md).
- Branches `security/kubernetes-tls-profile`, `security/ssh-strength-policy` and `security/strong-update` are fully merged (0 commits ahead of master). No open PRs.
- Finding: `bin/kubectl-policy:54` accepts a Go 1.24 kubectl. Under fips140=on, Go 1.24 negotiates only P-256/P-384, so the strong profile is less PQ-safe than the default profile on that toolchain. The same applies to `gh` via `gh_strong` (kyqs-ai:684-690) if gh was built with Go 1.24.

**WireGuard / Rosenpass sweep across all repos in shas.txt**
- Searched with `git grep -I -E '[Ww]ire[Gg]uard|WIREGUARD|[Rr]osenpass|wg-quick|\bwg0\b' origin/<branch>` across every repo, with no file exclusions in the final run. One hit: KyDNS-server:internal/adminapi/dhcp_test.go:383 @ cdaae83, a test comment ("/32 Tailscale or WireGuard TUN"). There is no WireGuard configuration and no Rosenpass or PQ-WireGuard mention anywhere.
- An earlier case-insensitive run matched base64 blobs (`wg0` inside PNG data URIs and ML-DSA test vectors in kyguard-server), not real hits.
- `.github`, `kynotes-desktop` and `kymessages-desktop`: `gh search code --owner Busnes-app wireguard` and `rosenpass` returned nothing.

**Reverse-proxy PQ summary**
- nginx edge (nginx 1.30.6-alpine, unprivileged): no group override, so OpenSSL defaults apply. With OpenSSL ≥3.5 it offers and prefers X25519MLKEM768 (OpenSSL 3.5 NEWS; nginx `ssl_ecdh_curve auto` doc). The exact OpenSSL in the pinned digest is unverified (Alpine 3.23 ships 3.5.9).
- NPM 2.17.1 (OpenResty on debian:trixie-slim, libssl-dev, trixie OpenSSL 3.5.9): no `ssl_ecdh_curve`, so X25519MLKEM768 is likely by default. Unverified for the pinned digest.
- cloudflared 2026.10.0: PQ by default over QUIC with non-PQ fallback; none over http2 (Cloudflare docs).
- frpc v0.71.0: Go TLS with no curve override, so X25519MLKEM768 if built with Go ≥1.24 (go.mod `go 1.25.0`). Unverified for the release binary.
- Not found in any of the four repos: Caddy, Traefik, HAProxy.

### Part 8: KyPost (non-OpenPGP) and deployment keys / release signing

#### Snapshot, toolchain and libraries

Scope: KyPost-Server @ 928ba0be (main), KyPost-for-Android @ 01f304bb, KyPost-for-Linux @ ae383bf, KyPost-for-Mac @ 165148e, the private demo repo @ 31cf283, Busnes.app-site @ 23e10f6, the private site repo @ 4fd280e; Part B is every repo in shas.txt. I skipped all OpenPGP because another worker covers it. I read everything read-only through `git show/grep origin/<branch>` and `gh api`.

Go TLS baseline: KyPost-Server builds with `go 1.26.9` / `toolchain go1.27.4` (KyPost-Server:backend/go.mod:3-5 @ 928ba0be) and the image builds from `golang:1.27.4` (KyPost-Server:Dockerfile:16 @ 928ba0be). The backend sets no `CurvePreferences` and no `GODEBUG=tlsmlkem=0` anywhere (I grepped the whole backend and compose files). So every Go TLS endpoint below offers X25519MLKEM768 by default in TLS 1.3 (https://go.dev/doc/go1.24#crypto-tls). A TLS 1.2 peer, or a peer without ML-KEM, negotiates classical ECDHE.

#### Part B: release signing and deployment keys (all repos in shas.txt)

Legend: "Sigstore attest" = `actions/attest-build-provenance@4d10147 # v4.2.2` (or `actions/attest@1e69f48` in KyVault-backend), keyless and signed under the workflow's GitHub OIDC identity. The workflows check it with `gh attestation verify`. GHCR login always uses `REGISTRY_TOKEN`=`GITHUB_TOKEN` (`docker login ghcr.io --username "$GITHUB_ACTOR"`). No workflow in any repo uses cosign CLI, slsa-github-generator, webfactory/ssh-agent, `DEPLOY_KEY`, sops/age, minisign, dpkg-sig or rpmsign; I grepped all workflows for these.

| repo | release artifact | signing (alg/tool) | key holder | location |
|---|---|---|---|---|
| KyMessage-Server | `ghcr.io/busnes-app/kymessage-server`, `ghcr.io/busnes-app/kymessage-notes` :X.Y.Z then :stable | Sigstore attest + buildx provenance mode=max + SBOM; verified before :stable moves | GitHub OIDC (keyless) | KyMessage-Server:.github/workflows/release-image.yml:31-41, :163-193 @ 439babc |
| KyPulse-server | `ghcr.io/busnes-app/kypulse-server` :<sha>/:latest (CI) and :X.Y.Z/:stable | Sigstore attest (both CI and release) | GitHub OIDC | KyPulse-server:.github/workflows/ci.yml:402-442; release-image.yml:34, :166 @ 7a45d37 |
| KyIdentity-server | `ghcr.io/busnes-app/kyidentity-server` :<sha>/:latest, :X.Y.Z/:stable | Sigstore attest | GitHub OIDC | KyIdentity-server:.github/workflows/ci.yml:292-332; release-image.yml:34, :180 @ 6e7df38 |
| ky-server-base | `ghcr.io/busnes-app/ky-server-base` :<sha>/:latest | Sigstore attest | GitHub OIDC | ky-server-base:.github/workflows/ci.yml:405-445 @ eceb24e |
| kyguard-server | `ghcr.io/busnes-app/kyguard-server` :<sha>/:latest | Sigstore attest | GitHub OIDC | kyguard-server:.github/workflows/ci.yml:400-440 @ 37b302b |
| KyYard-server | `ghcr.io/busnes-app/kyyard` (+ `-agent` coordinate) :<sha>/:latest, :X.Y.Z/:stable | Sigstore attest | GitHub OIDC | KyYard-server:.github/workflows/ci.yml:464-504; release-image.yml:34, :167 @ 8148a97 |
| KyQuickStart | `ghcr.io/busnes-app/kyquickstart-runner` image + `kyquickstart-*` binaries on GitHub Releases + `.intoto.jsonl` bundle | Sigstore attest for image and binaries, re-verified after upload | GitHub OIDC | KyQuickStart:.github/workflows/release-image.yml:36, :202, :227-324 @ 950c3f8 |
| KyPost-Server | `ghcr.io/busnes-app/kypost-server` :main (publish-main) and :X.Y.Z/:stable | Sigstore attest + provenance + SBOM; `scripts/update-host.sh:114` verifies on hosts | GitHub OIDC | KyPost-Server:.github/workflows/publish-main.yml:44, :132; release-image.yml:41, :235-251 @ 928ba0be |
| KyMessages-Native | `ghcr.io/busnes-app/kymessage-server` :X.Y.Z/:stable (**same image name as KyMessage-Server**) | Sigstore attest | GitHub OIDC | KyMessages-Native:.github/workflows/release-image.yml:29, :164 @ 9202576 |
| KyNotes-server | `ghcr.io/busnes-app/kynotes-server` | Sigstore attest | GitHub OIDC | KyNotes-server:.github/workflows/ci.yml:329; release-image.yml:34, :160 @ 88c85c8 |
| kydrive-server | `ghcr.io/busnes-app/kydrive-server` | Sigstore attest | GitHub OIDC | kydrive-server:.github/workflows/ci.yml:185-191; release-image.yml:34, :179 @ 9d5a468 |
| KyVault-backend | Vaultwarden images to docker.io, ghcr.io, quay.io + binaries | `actions/attest` per registry, **but the whole job is gated `if: github.repository == 'dani-garcia/vaultwarden'`**, so nothing runs in the Busnes-app fork | Upstream secrets `DOCKERHUB_*`, `QUAY_*` (would be needed) | KyVault-backend:.github/workflows/release.yml:40, :109-144, :240, :366-387 @ c0a86c2a |
| KyCalendar | `ghcr.io/busnes-app/kycalendar` | Sigstore attest | GitHub OIDC | KyCalendar:.github/workflows/ci.yml:459-468; release-image.yml:34, :204 @ 7bce306 |
| KyPost-for-Linux | Flatpak OSTree repo on gh-pages (`busnes-app.github.io/KyPost-for-Linux`) + `.flatpak` bundle + `.flatpakrepo` with GPGKey | GPG RSA-4096 (`flatpak build-sign`/`build-update-repo --gpg-sign`) + Sigstore attest of the bundle | Maintainer; secrets `FLATPAK_GPG_PRIVATE_KEY`, `FLATPAK_GPG_KEY_ID` | KyPost-for-Linux:.github/workflows/flatpak.yml:434-629, :683; packaging/flatpak/gen-signing-key.sh:52-57 @ ae383bf |
| KyQuickStart-AI | none | **No signing / no release** | n/a | KyQuickStart-AI:.github/workflows/ci.yml @ 3a7b8ef |
| KyAuth-Linux | Flatpak OSTree repo on gh-pages + signed bundles | GPG RSA-4096 + Sigstore attest | Maintainer; `FLATPAK_GPG_*` secrets | KyAuth-Linux:.github/workflows/release.yml:163-251, :277; packaging/flatpak/gen-signing-key.sh:28-29 @ c2efea6 |
| ky-primitives | Go module (source) | **No signing** (Go checksum DB only) | n/a | ky-primitives:.github/workflows/{ci,fuzz,scorecard}.yml @ 871828c |
| ky-ui | none | **No signing** | n/a | ky-ui @ 1b0e466 |
| kydrive-desktop | GitHub Release: macOS zip, 2 Windows zips, 2 MSIX, Flatpak + SHA256SUMS | macOS: Developer ID codesign (hardened runtime, timestamp) + notarytool + staple (only if `APPLE_DEVELOPER_ID_P12` is set, otherwise `-unsigned.zip`). **MSIX unsigned** (`AppxPackageSigningEnabled=false`, sideload `-AllowUnsigned`), **Flatpak and zips unsigned**. Sigstore attest over `release/*` | Maintainer; `APPLE_DEVELOPER_ID_P12(_PASSWORD)`, `APPLE_TEAM_ID`, `APPLE_NOTARY_KEY/_KEY_ID/_ISSUER_ID` | kydrive-desktop:.github/workflows/ci.yml:241-298, :372, :427-483; .github/release-notes/prerelease.md:25-29 @ 9596d67 |
| KyVault-web | none | **No signing** | n/a | KyVault-web:.github/workflows/ci.yml @ 1344eb7 |
| go-webdav | none (library fork) | **No signing** | n/a | go-webdav:.github/workflows/test.yml @ 7f1337b |
| Busnes.app-site | GitHub Pages (legacy build from master) | **None** (no deploy workflow; site.yml only runs tests) | GitHub | Busnes.app-site:.github/workflows/site.yml:24-27; HOSTING.md:6-11 @ 23e10f6 |
| .github (MISSING locally) | org defaults | **No workflows** (tree has only FUNDING.yml, dependabot.yml) | n/a | gh api repos/Busnes-app/.github/git/trees/main @ b2ee038 |
| KyDNS-server | GitHub Release: tar.gz, .deb, .rpm (nfpm), RPi .img.xz, SHA256SUMS; `ghcr.io/busnes-app/kydns-server` | Release: Sigstore attest over all files + image. **deb/rpm not GPG-signed** (comment: "already downloading unsigned binaries"). **CI pushes :latest and :<sha> to GHCR without attestation** | GitHub OIDC | KyDNS-server:.github/workflows/release.yml:175-215, :237-285; ci.yml:352-389 @ cdaae83 |
| KyRecovery-server | `ghcr.io/busnes-app/kyrecovery-server` | Sigstore attest | GitHub OIDC | KyRecovery-server:.github/workflows/ci.yml:270-279; release-image.yml:34, :164 @ 45dfe28 |
| KyDrive-for-Android | none (no release workflow, no `signingConfigs`) | **No signing** | n/a | KyDrive-for-Android:.github/workflows/{ci,codeql,docs,scorecard,screenshots}.yml @ 60e755b |
| KyAuth-android | Signed APKs on GitHub Release + Play upload | apksigner (keystore alg not visible) + signer SHA-256 digest check + Sigstore attest; Play via service-account JSON (RS256) | Maintainer; `release` env secrets `KYAUTH_KEYSTORE_BASE64`, `KYAUTH_STORE_PASSWORD`, `KYAUTH_KEY_ALIAS`, `KYAUTH_KEY_PASSWORD`, `PLAY_SERVICE_ACCOUNT_JSON` | KyAuth-android:.github/workflows/release.yml:36-55, :75, :121; app/build.gradle.kts:21-49, :113 @ 559e687 |
| KyAuth-iOS | App Store Connect upload (archive, then export with destination=upload) | Apple Development identity for archive, cloud-managed distribution re-sign by Xcode; ASC API key (.p8, ES256) | Maintainer/Apple; `APPLE_DEVELOPMENT_CERTIFICATE(_PASSWORD)`, `APP_STORE_CONNECT_KEY_ID/ISSUER_ID/PRIVATE_KEY` | KyAuth-iOS:.github/workflows/release.yml:3-39, :92-96, :164-214 @ f31cc76 |
| kynotes-desktop (MISSING locally) | none | **No workflows** (no `.github/workflows` in tree) | n/a | gh api repos/Busnes-app/kynotes-desktop @ b357111 |
| kymessages-desktop (MISSING locally) | none | **No workflows** | n/a | gh api repos/Busnes-app/kymessages-desktop @ 0c3de83 |
| KyPost-for-Mac | macOS DMG (Developer ID codesign + notarytool + staple, `aps-environment` production checked) + iOS App Store upload + gopenpgp XCFramework | codesign/notarytool; Sigstore attest of DMG (`KyPost-<tag>.intoto.jsonl`) and of the XCFramework | Maintainer; `APPLE_DEVELOPMENT_CERTIFICATE`, `DEVELOPER_ID_CERTIFICATE(_PASSWORD)`, `APP_STORE_CONNECT_*` | KyPost-for-Mac:.github/workflows/release.yml:102-120, :181-186, :287-348, :361-386; gopenpgp-xcframework.yml:219 @ 165148e |
| KyPost-for-Android | Signed APK/AAB on GitHub Release + Play | apksigner + check against `RELEASE_KEY_SHA256` + Sigstore attest; CI uses a throwaway RSA-4096 keystore; Play via service-account JSON | Maintainer; `RELEASE_KEYSTORE_B64`, `RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`, `RELEASE_KEY_SHA256`, `GOOGLE_SERVICES_JSON`, `PLAY_SERVICE_ACCOUNT_JSON` | KyPost-for-Android:.github/workflows/release.yml:114-151, :213-238, :273, :379; ci.yml:169-174; app/build.gradle.kts:61-66, :160-163, :245 @ 01f304bb |

Repos with no release signing at all: the private dashboard repo (pushes images, unattested), the private infra repo, KyQuickStart-AI, ky-primitives, ky-ui, KyVault-web, go-webdav, the private demo repo, Busnes.app-site, the private site repo, .github, KyDrive-for-Android, the private launch repo, kynotes-desktop, kymessages-desktop. KyVault-backend is effectively in this group too, because its release job is gated to the upstream repository. Partial: kydrive-desktop (MSIX/Flatpak/zip unsigned, macOS only when secrets exist) and KyDNS-server (deb/rpm unsigned; CI :latest unattested).

#### Per-repo notes

- **KyPost-Server, TLS.** I found exactly five `tls.Config` literals in non-test backend code: api/tls.go:187, app/receiving_tls.go:319 and :439, api/pairing_pin.go:259, adapters/imap/import_source.go:133. There are also three `StartTLS`/`tls.Client` configs in mailmsg (smtp_send.go:203, :408; direct_mx.go:152). None sets `CurvePreferences` or `CipherSuites`. The comment at api/tls.go:174-178 explicitly avoids freezing suites. No server listens for IMAP or JMAP: the only listeners are HTTP(S) (api/server.go:1163) and the receiving TLS transport (app/receiving_tls.go:306). The SMTP listener is Maddy (external). `backend/third_party/go-imap` is a vendored client.
- **KyPost-Server, push architecture.** Web/UnifiedPush goes server to push service directly, with RFC 8291 encryption under the server's VAPID P-256 key. FCM and APNs go server to Cloudflare Worker relay (`worker/`, `worker-apns/`, maintainer-deployed), then Google/Apple. The relay holds the single Firebase service account and APNs .p8. `push-relay-shared/` is byte-copied with KyIdentity-server (push-relay-shared/AGENTS.md:15). The only open PR is #742, a dependabot bump of the relay group, with no crypto impact.
- **KyPost-Server, docs.** docs/STRONG-CRYPTO.md:21-49 is an authoritative key table that matches this inventory. Its only PQ entry is the X-Wing backup capsule (:37). There is no planned PQ work for TLS, device envelopes or push in the repo docs. The HNDL items worth migrating are the device-envelope HPKE P-256 (wraps users' OpenPGP private keys, and the ciphertext transits and may be stored on the server) and RFC 8291 push payloads (fixed by RFC, needs an IETF update).
- **Changes since the OpenSSF reviews** (snapshots 3a4c11b / 7de9e10 / 8fec1b4 / e336e27). Legacy v2/v3 custom ECDH device envelopes are now retired on the browser (frontend/src/lib/deviceEnrollment.ts:66), Android (DeviceEnvelope.kt:30), Linux (DeviceEnrollmentCrypto.cpp:170) and Mac (DeviceEnvelope.swift:31 lists only the two HPKE versions). That resolves the review's "crypto_published: ?" concern about live v2/v3. Android also gained a TLS key floor (security/StrongTls.kt) and a PGP strength policy (pgp/PgpStrengthPolicy.kt); the PGP part is out of scope here.
- **KyMessages-Native.** release-image.yml:29 publishes to `ghcr.io/busnes-app/kymessage-server`, the same coordinate as KyMessage-Server (release-image.yml:31). Two repos can move `:stable` on one image, and attestations from either repo would verify only with the matching `--repo`. Someone needs to confirm whether that is intended (successor repo?).
- **KyVault-backend.** It is a Vaultwarden fork. Its release.yml still targets `dani-garcia/vaultwarden` (line 40 gate, `vars.DOCKERHUB_REPO`/`GHCR_REPO`/`QUAY_REPO`), so the fork publishes nothing signed.
- **Sigstore key algorithm.** GitHub artifact attestations use Sigstore with ephemeral keys and Fulcio certificates bound to the workflow OIDC identity; private repos use GitHub's own Sigstore instance (https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds). I did not confirm the exact key algorithm (ECDSA P-256 assumed). Exposure is forgery-only. There is no long-term project key to rotate, which makes this the easiest signature path to migrate when Sigstore adds ML-DSA.
- **Flatpak GPG keys.** RSA-4096 with `Expire-Date: 0` in both KyPost-for-Linux and KyAuth-Linux. This is a long-lived classical signing key embedded in `.flatpakrepo` (`GPGKey=`). Migration would need a key rollover with OSTree's multi-key support (unverified).
- **Deployment keys.** No SSH deploy keys, sops/age or sealed-secrets appear in any workflow or in the private infra repo. Pushes to gh-pages use `x-access-token:$GITHUB_TOKEN` (KyAuth-Linux:.github/workflows/release.yml:269 @ c2efea6). The only SSH key material is KyQuickStart's runner key (Ed25519) and its known_hosts handling.

## 3. Gaps / unverified

### Part 1: ky-primitives, ky-server-base, the private dashboard repo, ky-ui, org `.github`

- Go 1.26 `fips140=on` TLS allowed-groups list. I only read local Go 1.27.3 `GOROOT/src/crypto/tls/defaults_fips140.go:35-43`, which allows X25519MLKEM768. I did not check whether Go 1.26.x (ky-primitives' declared `go 1.26.6`, no toolchain pin) allows it under fips140.
- The x/crypto ssh `SupportedAlgorithms()` KEX order and contents were read from the local module cache v0.59.0 (`ssh/common.go:62,87`), not from upstream. Whether real SFTP peers negotiate mlkem768x25519 is unverified.
- go-smb2 NTLM internals (MD4/HMAC-MD5/RC4) are taken from the OpenSSF review and were not re-read at the current pseudo-version.
- The algorithm behind Sigstore/GitHub attestation signing (ECDSA P-256) and the scorecard-action signing are background knowledge, not verified from source here.
- sum.golang.org note-signature algorithm: unverified. Whether ky-primitives is public and so covered by sumdb: unverified. VERIFYING-RELEASES.md assumes it is.
- Operator reverse-proxy TLS for ky-server-base and the private dashboard repo is outside the repos and unverified.
- The the private dashboard repo TOTP enrolment write path is unverified: there is no non-test `EncryptAESGCM` caller.
- IdP-advertised `id_token_signing_alg_values_supported` for KyIdentity determines which algs ky-server-base and the private dashboard repo accept. Not checked here; see the KyIdentity part.
- I did not run the go-oidc algorithm path or any tests (read-only brief).
- `.github` org rulesets are unreadable: `gh api orgs/Busnes-app/rulesets` returned 404 and needs the admin:org scope.
- Recovery-key generation ceremony and share custody live in KyRecovery-server (out of my scope).

### KyIdentity-server crypto inventory (master @ 6e7df38)

- **TLS edge:** whether the operator's TLS edge (nginx/Cloudflare) negotiates X25519MLKEM768 for inbound traffic. Not in the repo.
- **FIPS mode curves:** whether `GODEBUG=fips140=on` on Go 1.27.x keeps X25519MLKEM768 in client defaults. Unverified.
- **Peer TLS:** whether the actual outbound peers support PQ-hybrid TLS: SCIM targets, SMTP, AD DCs, relay Workers, ubports, Google attestation. AD LDAPS being classical is an assumption.
- **Apple root key type:** the Apple App Attest root key type (P-384) is from memory, not checked in the PEM.
- **Sigstore algorithm:** the Sigstore/Fulcio signing algorithm for GitHub attestations is from memory. Unverified.
- **PostgreSQL TLS:** sslmode in deployments is operator-defined.
- **Workers TLS:** Cloudflare Worker outbound TLS (to FCM and APNs) is Cloudflare's stack, and its key-exchange groups are unverified (STRONG-CRYPTO.md says the same).
- **Web Push library:** I did not read webpush-go v1.4.0 internals. RFC 8291 means aes128gcm, but the library's record-size and padding handling was not checked.
- **WebCrypto ML-KEM:** browser WebCrypto ML-KEM availability, which a keyring PQ upgrade would need, is unverified.
- **Fragment exposure:** I did not establish whether a keyring-handoff fragment could persist anywhere, such as browser history or Referer. Referer excludes fragments by spec. History retention is client-dependent.
- **Not deeply read:** `internal/attest/*` was not read beyond the signature, key-floor and URL lines. Nor was the `scim`/`recoveryclient` code in ky-primitives beyond the KEM, AEAD and syncauth lines.

### Part 3: KyAuth (Android, iOS, Linux) and KyVault (backend, web): crypto inventory

- Whether Android Conscrypt (API 31–36) offers X25519MLKEM768 by default: unverified.
- iOS 26 URLSession hybrid default: based on the Apple support URL above, not fetched. iOS 17–18 (supported, target 17.0) are classical.
- OpenSSL version in Flatpak `org.kde.Platform` 6.11 and Ubuntu Touch 24.04-1.x, and so whether Linux KyAuth negotiates X25519MLKEM768: unverified.
- KyIdentity's TLS terminator group support: not in these repos. Hybrid on the client only helps if the server offers it.
- UnifiedPush connector 3.3.6 internal key storage and crypto: not read.
- Android upload key / iOS distribution cert key algorithms: not in the repos.
- Bitwarden SDK internals (exact RSA-OAEP hash for type 4, V2 signing algorithm, COSE parameters): not read. Taken from enum names and TS comments.
- KyVault-backend `ROCKET_TLS` provider selection under rocket 0.5.2: inferred from the global ring provider, not traced.
- webauthn-rs 0.5.5 default COSE algorithm list: not checked.
- PR #1 Recovery Kit client-side wrapping algorithm: no client code found in KyVault-web main; `kdf_params_json` content unknown.
- ky-primitives `syncauth` construction (assumed HMAC): not read in this part.
- QR pairing token entropy (sets the strength of HMAC pairing proof K): generated by KyIdentity, not checked.

### Part 4: KyMessages (KyMessages-Native, KyMessage-Server, kymessages-desktop): crypto inventory

- **kymessages-desktop:** the repo is empty (`0c3de83`). Electron, its key storage (safeStorage/keytar), auto-update signing and code signing are all unverified because they do not exist yet. The marketing site shows a desktop screenshot "from local builds", so code may exist off GitHub (unverified).
- **Native call DTLS:** the DTLS version, certificate algorithm and SRTP profiles are browser-chosen and were not tested. The operator-supplied LiveKit's DTLS policy is unknown.
- **Frame cipher key lengths:**
  - E6's frame cipher and key length are not specified in the Native spec.
  - MatrixRTC frame keys are assumed to be AES-128-GCM from 16-byte keys (livekit-client HKDF). This is unverified at the pinned livekit-client and rtc-node versions.
- **Upstream cipher details:**
  - vodozemac's pickle cipher details are from upstream docs, not read at the tag.
  - MAS's encryption-key cipher and Element Web's IndexedDB store encryption are unverified.
- **Synapse:**
  - whether its OpenSSL 3.5.x federation and pusher TLS negotiates X25519MLKEM768 is unverified (rows marked HNDL);
  - whether its Rust reqwest/rustls 0.23.31 client offers a hybrid group is unverified.
- **LiveKit** TURN/TLS listener key exchange at v1.13.7 is unverified.
- **TURN credentials:** the MD5/HMAC-SHA1 derivation is from the prior report, not re-read.
- **Notes bot crypto store:** "not encrypted at rest" is inferred from `initRustCrypto` being called without a storage key or passphrase. It was not confirmed against the matrix-js-sdk 44.0.0 source.
- **ky-primitives internals** were not re-audited here: Argon2id parameters, TOTP key size, SigV4 in `ky-primitives/s3`, syncauth's HMAC and the AES-GCM sealer label handling.
- **Sigstore** signing key algorithm for `actions/attest-build-provenance` v4.2.2 is unverified.
- **Native lacks floors that Server has:**
  - no `KY_SESSION_SECRET` length floor;
  - no LiveKit API-secret length floor;
  - no JWKS RSA-size floor.
  None of these is a PQ issue, but they are key-strength gaps.
- **Native E2EE trust:** until E3 ships, room keys go to any device the server lists (documented in PR #32). Main carries E2 unreleased.

### Part 5: KyDrive (server, Android, desktop), KyNotes (server, desktop), KyRecovery-server

1. kydrive-server step K exists only as an unpushed local branch (`feat/per-org-keys` @ ac85499, WIP commits from 2026-11-25). Its contents may change, and the D14 amendment is marked as awaiting owner approval (tenancy spec :3). There is no PR number.
2. HNDL on inbound TLS for kydrive-server and KyRecovery-server depends on the operator's reverse proxy and its TLS library. Neither repo pins hybrid groups (unverified whether the documented nginx/OpenSSL edge negotiates X25519MLKEM768).
3. KyDrive-for-Android: whether the platform TLS stack (Conscrypt on API 31-36) offers X25519MLKEM768 is unverified.
4. kydrive-desktop: core/go.mod has no `toolchain` line, so the build toolchain (and so the default PQ groups) depends on CI's setup-go (not checked). I did not re-run the RSA-1024 leaf probe the native review used against 9596d67.
5. Recovery capsules are sealed (HPKE base mode, X-Wing) but **not signed**. Anyone with the recovery public key can mint a capsule. KyRecovery reads the manifest unverified (`capsule.ReadUnverifiedManifest`), and authenticity rests on the product's deposit bearer token and the restore operator. No signing of backup manifests exists in any repo here.
6. The age file key is 128 bits (age v1 spec). Whether that warrants a Grover note is a policy call. I marked the blob row "symmetric, PQ-safe at 256-bit" because the payload cipher key is 256-bit and is derived from it (age spec: https://age-encryption.org/v1, not re-read for this report).
7. These are not re-verified from primary sources: Restic internals (scrypt, AES-256-CTR, Poly1305-AES), and the Sigstore Fulcio key algorithm for attest-build-provenance.
8. The size floors of the KyPost pairing secret in kydrive-server (internal/api/kypost.go:222) and of the KyNotes syncauth secret were not checked.
9. Android biometric Keystore key size: no `setKeySize` (lock/Device.kt:109-117), so it takes the Keystore default, which I did not check.
10. restic/rest-server 0.14.0's Go version and TLS groups are unverified.
11. KyRecovery's backup of its own SQLite database (if any) was not located.
12. ky-primitives `auditchain` was read only from its package comment. That it uses HMAC-SHA256 is inferred (unverified).
13. KyNotes web: I did not exhaustively check every WebCrypto call site for an AES-128/192 import path. crypto.ts:97-100 refuses non-32-byte content keys.

### Part 6: kyguard-server, KyDNS-server, KyCalendar, KyPulse-server, KyYard-server, go-webdav

- `GODEBUG=fips140=on` behaviour of `CurvePreferences [X25519MLKEM768, X25519]` on go1.27.4: believed to keep the hybrid and drop X25519, but not checked against Go source.
- The kyguard SSH connector KEX result against a real OpenSSH 10 target. Inferred from the x/crypto v0.59.0 default list, not observed. PR #14's tests run against "OpenSSH + linux-pam", but the negotiated KEX was not read.
- AD/LDAPS (PR #13): whether Windows Server DCs negotiate X25519MLKEM768 is unverified. Likely not, so the `P_old`/`P_new` transport is probably HNDL-exposed.
- Session-recording encryption algorithm: not specified in the spec (§5, D.4). No code.
- Spec D.8 checkpoint signing algorithm and D.1 EpochCheckpoint signature algorithm: unspecified.
- The internal broker CA algorithm is not in the spec. Code uses Ed25519, and no PQ or hybrid X.509 is planned anywhere in the spec.
- Sigstore/Fulcio signature algorithm (assumed ECDSA P-256): unverified.
- KyYard: client-go/apiserver PQ KEX depends on the cluster's Go version. Unverified.
- KyDNS: `ProtonMail/go-crypto` indirect dependency origin. Not traced (`go mod why` not run, per the no-build rule).
- KyCalendar: does docs/STRONG-CRYPTO.md close the OpenSSF "supported profile" fix? Not read in full.
- Whether the kyguard backup actually includes `broker-ca.key` (spec §9.4 rule 3) was not checked in `collectFiles`/`backup.Collect`.

### Part 7: infrastructure (KyQuickStart, KyQuickStart-AI, the private infra repo, the private launch repo)

- OpenSSL version inside the pinned `nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116e…` and `jc21/nginx-proxy-manager:2.17.1@sha256:04a9d0…` digests. Images were not pulled.
- Whether CloudNativePG 1.30.1 sets `ssl_ecdh_curve`/`ssl_groups` on its clusters. The OpenSSL version in `cloudnative-pg/postgresql:17.12-minimal-trixie`.
- cert-manager's default algorithm when `privateKey.algorithm` is unset (docs fetched quote only the size defaults), and the ACME account-key algorithms for cert-manager and certbot.
- Certbot version inside NPM 2.17.1 (the ECDSA default needs ≥2.0.0).
- Go toolchain of the restic 0.19.1 release image, the frpc v0.71.0 binary, cloudflared, the operator's `gh` and `kubectl` builds.
- cloudflared version behind infra's digest `sha256:51c9ce…`. Which PQ group cloudflared negotiates.
- Sigstore ephemeral key type for actions/attest-build-provenance v4.2.2 (believed ECDSA P-256).
- LiveKit TURN-TLS curve configuration and pion DTLS groups (KyMessage part).
- Live cluster settings not in infra: Cilium encryption, etcd encryption-at-rest, Longhorn volume encryption, kube-apiserver TLS and SA-token signing algorithm.
- Target sshd versions, which decide whether SSH actually negotiates mlkem768x25519/sntrup761 or falls back.

### Part 8: KyPost (non-OpenPGP) and deployment keys / release signing

- Go 1.27 `fips140=on`: whether X25519MLKEM768 or SecP256r1MLKEM768 stays enabled. This affects the KyPost strong-crypto overlay.
- Maddy v0.9.5 release binary: Go version and TLS curve defaults for inbound SMTP.
- go-msgauth v0.7.0 DKIM verification: which algorithms it accepts (rsa-sha1, ed25519-sha256).
- Android Conscrypt / KDE 6.11 OpenSSL / Node 26 OpenSSL / Apple URLSession 26: whether each offers X25519MLKEM768 by default. I marked all of them HNDL rather than assume PQ.
- androidx security-crypto 1.1.0 exact AEAD defaults (AES-256-GCM/SIV assumed from library docs).
- CryptoKit X-Wing HPKE ciphersuite availability on 26.0.
- Release signing key algorithms that sit in secrets and so can't be seen: Android release keystores (KyAuth, KyPost), Apple Developer ID / Development certificates, and the Play service-account key type.
- x/crypto v0.59.0 `ssh.SupportedAlgorithms().KeyExchanges` includes mlkem768x25519-sha256 (KyQuickStart).
- restic crypto statement comes from restic docs, not from reading code.
- I did not inspect the Cloudflare Worker TLS to FCM/APNs or the GitHub Pages TLS; both are outside the repos.

### Merge-level (samphire)

- Go stdlib TLS/HPKE/ML-DSA facts were read from Fedora's go1.27.3 GOROOT on the build host (`/usr/lib/golang`, VERSION go1.27.3);
  builds use 1.27.4 (K hosts, `golang:1.27.4` images). Identical content in 1.27.4 is unverified.
- Where a part says the `fips140=on` profile "may turn the hybrid off" (KyPost part), that is superseded by the Go
  source check in the headline section: X25519MLKEM768 stays allowed and first under `fips140=on` in Go 1.27.
- Whether any IETF draft defines a PQ variant of RFC 8291 Web Push encryption: unverified (none found in repos).
- Table rows were produced by eight read-only sweeps and spot-checked by samphire for: `recoverykey` X-Wing
  (`ky-primitives:recoverykey/recoverykey.go:14-21,27,40-41 @ 871828c`), KyIdentity AD-password HPKE X25519
  (`KyIdentity-server:internal/adpass/adpass.go:25,58-82 @ 6e7df38`), KyNotes envelope v3 X25519 mode_auth
  (`KyNotes-server:web/src/teamKeys.ts:8-18 @ 88c85c8`), and the curve-override grep across all repos. Other rows
  were not independently re-checked.
- PQ status of mobile/OS TLS stacks (Android Conscrypt, Apple URLSession below iOS 26, distro OpenSSL), the OpenSSL
  version inside pinned nginx/NPM images, and key algorithms held only in CI secrets: unverified.

