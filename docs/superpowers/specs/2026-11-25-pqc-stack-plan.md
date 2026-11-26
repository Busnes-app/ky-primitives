# Ky stack post-quantum migration, plan

Date: 2026-11-25. Status: **approved** (see "Owner answers"). W0, the cell mesh and the KyVault evaluation are being built. Owner request (2026-11-25): "I would like to see the whole stack migrated to PQC." KyPost goes first, in
its own spec (**A**: `KyPost-Server/docs/superpowers/specs/2026-11-25-pqc-openpgp-v6-design.md`, PR
Busnes-app/KyPost-Server#743). This plan covers every other place the suite does key exchange, encryption to a
public key, or signatures, and sets the order.

## Owner answers (2026-11-25)

- **Approved as recommended:** Q3 (browser PQ code as ky-primitives Go WASM), Q4, Q6, Q8, Q9, Q12, Q13, Q14.
- **Q7: no custom crypto, agreed.** KyMessages waits for upstream PQ Olm or MLS. Meanwhile everything around Olm
  becomes PQ.
- **Q10: explore a WireGuard mesh.** Explored in "Cell links" below; decided in the second round.
- **Second round (2026-11-25, later):**
  - **Q1 approved:** build and test W0. KyGuard's SSH connector rejects SHA-1 key exchange, and its broker
    listener goes hybrid-only. Both were handed to the KyGuard thread.
  - **Q2 approved:** category 3 for now.
  - **Q5 approved:** Ky relying parties get ML-DSA-65 tokens; third parties keep RS256. The third parties are
    admin-added OIDC apps, Himmelblau and XCreds workstation sign-in, and Vaultwarden SSO.
  - **KyMessages:** the Matrix-based KyMessage-Server is deprecated; KyMessages-Native is the chat client. Its
    rows below are marked deprecated. Native still uses vodozemac Olm/Megolm, so Q7 stands for it.
  - **Q11:** a worker evaluates swapping KyVault's crypto. If no swap is worthwhile, it switches rustls to the
    `aws-lc-rs` provider for hybrid TLS.
  - **Q10a-e decided:** mTLS plus a mesh; strict; built in a private infra repo, never shipped to third parties;
    monthly rotation plus rotation on every host change; alerts as recommended.
- **Spec A answers that touch this plan:**
  - Users' stored mail is re-encrypted to v6 (A P6).
  - The browser pins an openpgp.js v7 commit and falls back to gopenpgp compiled to WASM. A Node 26 spike of
    gopenpgp `profile.PQC()` under `GOOS=js GOARCH=wasm` produced an 8.8 MB module (2.4 MB gzipped) with 4-18 ms
    operations.

Companion files in this directory:

- `2026-11-25-pqc-research.md` (**R**): primary-source research on RFC 9580, RFC 9980, FIPS 203/204/205, NIST
  SP 800-227 and IR 8547, the IETF hybrid drafts, Signal PQXDH/SPQR, Go 1.27 and the OpenPGP libraries.
- `2026-11-25-pqc-stack-inventory.md` (**I**): the full per-repo inventory (about 480 rows) with every file and line
  reference this table condenses. Rows for private repos are kept out of this public repository.

**Why this lives in ky-primitives.** The shared PQ code every app needs (X-Wing sealing, hybrid signatures, ML-DSA
JWS verification, TLS tests) lands here, and the suite's strong-crypto policy already lives here
(`docs/STRONG-CRYPTO.md`). KyIdentity-server is one app among many and would bury a suite-wide plan in an app's docs.

Line references are `Repo:path:line @ sha` at each repo's `origin` default branch on 2026-11-25 (snapshot table in
I). They come from read-only sweeps by four workers; the riskiest were spot-checked in code (KyIdentity `adpass.go`,
KyNotes `teamKeys.ts`, KyCalendar `contentkey/suite.go`, kyguard `pqcrypto/sig.go` and `seal.go`, ky-primitives
`recoverykey.go`, KyPost's device envelope). **Nothing was run.** "Unverified" marks claims nobody checked.

## Summary

- **TLS key exchange is already hybrid wherever Go talks to Go.** No Go repo sets `tls.Config.CurvePreferences`
  except kyguard-server, and none sets `GODEBUG=tlsmlkem=0`. So every Go 1.26/1.27 client and listener offers
  X25519MLKEM768 (RFC 10024) first. Under the suite's `GODEBUG=fips140=on` profile the hybrid stays first and only
  plain X25519 is dropped (go1.27 `crypto/tls/defaults_fips140.go:35-43`). Nothing is lost, but nothing proves it
  either: W0 adds the tests. Classical legs remain at the edges: the reverse proxy (OpenSSL version unverified),
  PostgreSQL (prime256v1 or `X25519:prime256v1` by default), LDAPS to AD, Synapse federation, SMTP peers,
  KyVault's rustls `ring` provider, and native mobile TLS before iOS 26.
- **Already post-quantum:** backup capsules (`recoverykey`/`capsule`, HPKE X-Wing, used by every product), kyguard's
  DEK wraps (X-Wing) and signed objects (ML-DSA-65 + Ed25519, both must verify), KyCalendar's content-key library
  (X-Wing, not yet wired in), and Go SSH clients (`mlkem768x25519-sha256` first).
- **The harvest-now-decrypt-later (HNDL) work is short, and it is ours.** Six classical key wraps carry long-lived
  secrets on Ky code at both ends. Each is a swap to HPKE X-Wing (KEM 0x647A, Go 1.26+ `crypto/hpke.MLKEM768X25519()`):
  1. KyPost's device envelope (P-256 HPKE, carries the account OpenPGP key). It is in spec A, phase P2.
  2. KyIdentity's AD password queue (X25519 HPKE, carries plaintext AD passwords).
  3. KyNotes team container-key envelopes (X25519 HPKE mode_auth: one envelope plus a future quantum computer
     opens every note in its container).
  4. KyNotes device linking.
  5. KyIdentity keyring device transfer (P-256 ECDH, mitigated by a secret HKDF salt).
  6. KyIdentity keyring cross-origin handoff (P-256 ECDH, zero salt).
- **Signatures are forgery-only.** They can be broken only once a quantum computer exists, so they come second.
  Long-lived trust comes first: internal CAs, pinned identities, the OIDC signing key and release keys.
- **Several things cannot go PQ yet and are outside our control:**
  - **WebAuthn and passkeys:** almost no authenticator makes ML-DSA credentials (only 1Password 8.12.44, partially),
    and existing credentials cannot migrate.
  - **KyMessages' Olm and Megolm:** vodozemac has no PQ; its PQXDH PR #120 has been on hold since 2026-06-04, and
    no Matrix MSC exists.
  - **Standards with no PQ variant:** Web Push RFC 8291 and VAPID, DKIM, DNSSEC and public WebPKI certificates.
    CA/B Forum ballot SC-106 closed unmerged on 2026-10-21.
  - **Upstream products:** FCM/APNs tokens and the Bitwarden SDK that KyVault uses.
- **Per-org keys need no PQ work.** KyDrive step K's per-org keys are symmetric: AES-256-GCM under an
  HKDF(deployment key) KEK, on the local branch `feat/per-org-keys` @ `ac85499`, unpushed. The same holds for
  KyNotes' content keys. What KyNotes needs is the team envelope swap above.
- **No WireGuard is planned anywhere** (searched every repo), and no Rosenpass. The hosted cells have no link
  design yet (Q10).

## Defaults (apply to every row unless a question changes them)

1. **Hybrid, never PQ alone.** Key exchange: X-Wing (ML-KEM-768 + X25519) for HPKE, X25519MLKEM768 for TLS,
   `mlkem768x25519-sha256` for SSH. Signatures: ML-DSA-65 + Ed25519, both required, for Ky-internal objects;
   ML-DSA-65 next to the classical algorithm where a standard format must interoperate (JWS, X.509). This follows
   NIST SP 800-227 §4.6 and IR 8547 §3.2 (R §4), and protects against a flaw in the young PQ implementations.
2. **NIST category 3** (ML-KEM-768, ML-DSA-65) everywhere; category 5 only for an Enterprise CNSA 2.0 option (Q2).
3. **Go standard library first:** `crypto/hpke`, `crypto/mlkem`, `crypto/mldsa`, `crypto/x509` (Go 1.27). No CIRCL in
   new code. For FIPS deployments, Go 1.27.5 or later carries the CMVP #5581 module with ML-DSA (we are on 1.27.4).
4. **Versioned formats.** Every new envelope or signature carries a version and an algorithm label in its
   authenticated data. Readers keep the old version until every writer has moved, and then stop issuing it.
5. **One implementation, shared.** Each primitive is built once in ky-primitives and used by every app, with shared
   test vectors. Browsers get it as Go `js/wasm`, as KyRecovery's ceremony already does
   (`KyRecovery-server:cmd/ceremony-wasm/main.go:13-25 @ 45dfe28`), unless Q3 picks a JS library.
6. **Each security property gets a test that fails without the change.** For example: the X-Wing seal refuses a
   P-256 envelope after cut-over; hybrid verification fails when either half is wrong; a TLS test fails if
   `CurveID != X25519MLKEM768`.

## Waves

| Wave | What | Changes for users | Gate |
|---|---|---|---|
| **W0** | Prove and pin hybrid key exchange: TLS handshake tests in every Go service (with and without `fips140=on`); a CI check refusing `CurvePreferences`/`tlsmlkem` overrides; explicit `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1` and an OpenSSL ≥ 3.5 check on the KyQuickStart nginx edge; PG18 `ssl_groups`; cloudflared strict PQ; KyQuickStart-AI Go ≥ 1.25 floor; kyguard drops SHA-1 SSH KEX; KyVault rustls `aws-lc-rs` (if Q11 keeps it) | None | Usual merge gate |
| **W1** | Replace every classical key wrap on Ky code with X-Wing HPKE. Order: (1) ky-primitives `xwing` seal helper and its WASM build; (2) KyIdentity AD password queue; (3) KyPost device envelope (spec A P2); (4) KyNotes team envelopes and device linking; (5) KyIdentity keyring transfer and handoff; (6) KyCalendar CE2 wiring on the shared helper; (7) KyMessages guest call key, specified PQ before it is built; (8) local-only device key wraps: Android's RSA KEK becomes an auth-bound Keystore AES key; Apple moves to Secure Enclave ML-KEM where available (row 26) | Re-keying: KyNotes members, the AD DC agent and enrolled KyPost devices each re-key once | Owner approval for each re-key PR (it changes what existing keys can do) |
| **W2** | Hybrid signatures where we control both ends, long-lived trust first: (1) ky-primitives `hybridsig` (lifted from kyguard); (2) internal CAs and pinned identities (kyguard broker CA, KyDNS replicas, KyPost hosted receiving, KyYard agents) to ML-DSA-65 X.509 (RFC 9881); (3) TLS-pin rollover statements (KyPost relay, kydrive); (4) KyIdentity OIDC: multi-key JWKS and rotation first, then ML-DSA-65 JWS (RFC 9964) for Ky relying parties, RS256 kept for third parties; `oidcverify` and go-oidc RPs accept ML-DSA-65; (5) KyIdentity AD queue signing and KyAuth/kydrive device signatures where keys are in software; (6) optional capsule manifest signing (Q13); (7) release-key hygiene (Flatpak keys get an expiry) | Re-pairing for pinned identities; a new JWKS key | Owner approval for the OIDC change and each re-pair |
| **W3** | Track upstream; adopt when it ships: vodozemac PQXDH / MLS PQ suites; Bitwarden PQ; WebAuthn ML-DSA (list COSE -49 now, Q6); Web Push; FCM/APNs; DKIM; DNSSEC; WebPKI ML-DSA; OpenSSH ML-DSA keys; Synapse federation; SMTP peers; Sigstore ML-DSA | None until adopted | Re-checked each quarter against R's sources |

KyPost's OpenPGP work (spec A) runs in parallel. A's P2 is W1 step 3, and A's P0 can start at once.

## Shared code for ky-primitives

ky-primitives has no generic envelope, signing or TLS-config helper today: only `recoverykey`
(`recoverykey/recoverykey.go:42,63-150 @ 871828c`) and the capsule-specific `capsule`. Five additions, each one
small PR:

1. **`xwing`**: an X-Wing keypair type (generalised from `recoverykey`, which stays as a thin wrapper so capsules
   do not change) and `Seal(pub, info, aad, msg)` / `Open(priv, info, aad, ct)` with wire format
   `version ‖ enc (1120 B) ‖ ct`. Lift from `KyCalendar:internal/contentkey/suite.go:94-123 @ 7bce306` and
   `kyguard-server:internal/pqcrypto/seal.go:30-68 @ 37b302b`. Plus a `js/wasm` build and shared test vectors
   (`recoverykey/testdata/xwing-vector.json` already exists).
2. **`hybridsig`**: ML-DSA-65 + Ed25519, both required, lifted from `kyguard-server:internal/pqcrypto/sig.go:12-123
   @ 37b302b` (stdlib `crypto/mldsa`, empty context, Ed25519 over a domain-separated SHA-256 digest). It is
   documented as a Ky-internal format, **not** the RFC 10073 X.509 composite or the draft JOSE composite. Kotlin
   and Swift verifiers are needed for the TLS-pin statements: Bouncy Castle 1.87 and CryptoKit `MLDSA65`, both
   unverified.
3. **`oidcverify`**: accept ML-DSA-65 JWS with AKP JWKs (RFC 9964) next to RS256, preferring ML-DSA-65 when the
   JWKS offers it. Add a multi-key JWKS helper for KyIdentity, and one shared AKP-aware key-strength check to
   replace the per-repo `jwks_strength.go` copies. go-jose v4.1.9 already has `MLDSA65` behind a go1.27 build tag.
   go-oidc v3.21.0 drops it from discovered algorithms (`oidc.go:180-191,339`), so go-oidc RPs must set
   `SupportedSigningAlgs` explicitly. Read from the module cache; untested.
4. **`pinnedca`**: an internal CA and pinned-identity TLS helper issuing ML-DSA-65 X.509 (RFC 9881, Go 1.27
   `crypto/x509`), lifted from `kyguard-server:internal/brokerproto/ca.go` and `tls.go`.
5. **TLS PQ test helper**: assert `tls.ConnectionState.CurveID == tls.X25519MLKEM768` (Go 1.25+), with and
   without `GODEBUG=fips140=on`, extending `crypto_profile_test.go:30-60`.

## Specific answers the owner asked for

- **KyIdentity's zero-knowledge keyring (#295/#296, merged).**
  - Device transfer is ephemeral ECDH P-256, HKDF with a 256-bit approval secret as salt, then AES-256-GCM
    (`KyIdentity-server:web/src/keyringCrypto.ts:119-177 @ 6e7df38`). The secret never reaches the server, so a
    recorded transfer cannot be opened by breaking P-256 alone. Mitigated, but still W1.
  - The cross-origin handoff uses P-256 ECDH with a **zero** HKDF salt, carried in the URL fragment
    (`keyringCrypto.ts:193-238`). It is not mitigated.
  - Both move to X-Wing. A 1216-byte X-Wing public key is about 1.6 KB base64 in a query parameter; whether URLs
    allow that length is unverified.
  - Wrapped subkeys are AES-256-GCM: no change.
- **KyIdentity OIDC/JWT.**
  - Today: one RSA-2048 key, RS256, never rotated, an unencrypted 0600 file, one JWK
    (`internal/crypto/crypto.go:270-407 @ 6e7df38`).
  - Rotation comes first, then ML-DSA-65 next to RS256 (W2.4).
  - Third-party relying parties stay on RS256 until they support RFC 9964.
- **WebAuthn and passkeys cannot go PQ yet.**
  - KyIdentity offers ES256 only (`internal/webauthn/webauthn.go:39-40`).
  - Listing COSE -49 (ML-DSA-65) first is harmless, and go-webauthn v0.18.2 verifies it on Go 1.27. But almost
    every user's authenticator will still make an ES256 credential, and existing credentials cannot be upgraded.
  - So passkey sign-in stays classical for the user population for now.
- **KyMessages E2EE.**
  - vodozemac Olm (Curve25519 triple-DH plus Double Ratchet) and Megolm are classical, and recording Olm traffic
    exposes every room key.
  - The references for the fix are Signal's **PQXDH** (adds ML-KEM to the initial agreement) and **SPQR / the
    Triple Ratchet** (an ML-KEM braid mixed into the ratchet, rolling out since 2025-10-02). MLS's PQ ciphersuites
    (X-Wing, draft-ietf-mls-pq-ciphersuites-08, in IETF Last Call) are the other path.
  - None of these is in vodozemac (R §5). Q7 decides between waiting and building.
- **KyDrive and KyNotes encryption at rest and per-org keys.**
  - All of it is symmetric: KyDrive age STREAM and AES-256-GCM; step K's per-org keys are AES-256-GCM under an HKDF
    KEK; KyNotes content is AES-256-GCM. No PQ work.
  - KyDrive's planned end-to-end vault (D15) is designed PQ from day one (age `mlkem768x25519`,
    Ed25519 + ML-DSA-65).
  - The KyNotes team envelopes and linking are the HNDL items (W1.4).
- **KyRecovery:** `recoverykey` is already X-Wing HPKE (`recoverykey/recoverykey.go:42`), and its browser ceremony
  runs the same Go code as WASM. Capsule manifests are unsigned (`capsule/seal.go:35-37`); that is not a PQ
  problem, but W2 can fix it (Q13).
- **KyGuard** already does X-Wing and ML-DSA-65 + Ed25519. Two gaps: its broker listener still allows an X25519
  fallback (`internal/brokerproto/tls.go:13`), although both ends are Go 1.27; and its SSH connector branch keeps
  `diffie-hellman-group14-sha1`. Both are W0.
- **TLS:** see Summary and rows 1-15. The one stack-internal link where Go clients cannot get the hybrid today is
  PostgreSQL. PG18's `ssl_groups` fixes it if the image has OpenSSL ≥ 3.5.
- **WireGuard for hosted cells:** nothing is designed. Rosenpass (a PQ key exchange that feeds WireGuard a rotating
  pre-shared key) is the standard way to make WireGuard PQ (Q10).
- **Push relays:**
  - Payload encryption is RFC 8291 (P-256 ECDH, AES-128-GCM). VAPID is ES256, FCM uses an RS256 service-account
    JWT and APNs an ES256 token. None has a PQ variant.
  - The mitigation is to keep secrets out of payloads (Q8).
- **Backups:** capsules are X-Wing; restic repositories are symmetric (AES-256-CTR + Poly1305).
- **Deployment and release keys:**
  - Sigstore keyless provenance in 13 repos (ECDSA P-256, upstream).
  - Flatpak OSTree GPG RSA-4096 keys that never expire.
  - apksigner and Apple codesign (upstream).
  - No SSH deploy keys, sops, age or sealed-secrets anywhere.

## KyMessages-Native E3 and E5 (built PQ from the start)

These phases (`KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md` §3, §5, §10) are new formats, so
they start PQ instead of migrating later. Olm and Megolm stay vodozemac's (Q7: no custom crypto around them). They
use ky-primitives `xwing` and `hybridsig` (being built, W1.1 and W2.1): Go on the server, and the same Go compiled
to WASM in the browser (Q3). If the KyMessages worker prefers RustCrypto inside `web/crypto`, it must pass the
ky-primitives test vectors, and the switch away from Q3's single implementation needs owner approval.

| Item | Use | Why |
|---|---|---|
| Recovery key | 256-bit random secret, symmetric only. Per-purpose subkeys via HKDF-SHA256 with labels (`kymessages.recovery.v1/backup-key`, `/master-key`). Wraps are AES-256-GCM with the version and label in the AAD | Symmetric 256-bit is PQ-adequate. No public-key step |
| Key backup | **An X-Wing backup keypair.** The public key (1216 B) is published, signed by the master key (hybrid). Any verified device seals each Megolm session to it with `xwing.Seal` (info `kymessages.backup.v1`, AAD = room ID ‖ session ID). The backup private key is stored only wrapped under the recovery key | Devices add keys without holding the recovery key, as Matrix's `curve25519` backup does, but without its HNDL exposure (plan row 48) |
| User master key | **`hybridsig` ML-DSA-65 + Ed25519, both must verify**, from day one. It signs devices, bots and the backup public key. Signed strings move to `kymessages.device.v2` and include the `alg` tag | It is long-lived pinned trust (TOFU). Changing it later would raise "identity changed" in every shared room for every user |
| Device identity | vodozemac Curve25519/Ed25519, unchanged (upstream). The master key's signature over the device is hybrid | Olm needs vodozemac's keys |
| Fingerprints, TOFU, QR | SHA-256 over a domain label plus the full hybrid master public key. QR codes carry fingerprints and secrets, never ML-DSA public keys (1952 B; too large for a QR code) | Fits a QR code; binds the full hybrid key |
| Device verification and secret transfer | Two layers. The QR from the verified device carries a one-time 256-bit secret `s` and the master fingerprint. The new device sends an ephemeral X-Wing public key over the server. The verified device encrypts the master key and backup key under HKDF(`s`) with AES-256-GCM, then `xwing.Seal`s that to the ephemeral key. One-time, short TTL, confirmed on both screens | `s` never reaches the server, so the transfer is PQ even if X-Wing were broken. The X-Wing layer protects against a photographed QR combined with a copy of server traffic. Never classical X25519 |
| Attachments and thumbnails (E5) | AES-256-GCM per file, with a **separate random key for each file and each thumbnail**; SHA-256 of the ciphertext inside the encrypted message. Metadata carries `v` and `alg` (`A256GCM`); AAD = `kymessages.attachment.v1` ‖ kind (`file`, `thumb`). The server-side S3 seal stays as is (a second, symmetric layer) | Symmetric and hash-based: already PQ-adequate (AES-256: ~128-bit against Grover; SHA-256 collision and preimage margins hold). Versioning is what avoids a later migration. If files can exceed what one AES-GCM call should hold in memory, choose a chunked (STREAM) format now rather than later |
| Guest call key (E6) | `xwing.Seal` to the guest's ephemeral key, not X25519 (row 22) | Specify it PQ before it is built |

Residual, stated plainly: room keys still travel between devices over Olm, which is classical. Recorded
to-device ciphertext (server mailbox rows and their backups) is harvest-now-decrypt-later exposed until vodozemac
ships PQ. Delete to-device rows on acknowledgement so the window stays short.

## Cell links (owner Q10: explore a WireGuard mesh)

Research is in `2026-11-25-pqc-wireguard-mesh-research.md`. Read from primary sources; nothing was built or run.

**What a cell's hosts send each other.** HTTPS from the edge to the replicas, the PostgreSQL wire protocol (clients,
PgBouncer, streaming replication), Ky-to-Ky mTLS (MX to receiving), operator SSH, and metrics. Nothing needs network
connectivity between cells (KyPost multi-host spec `:67-72,599-615`; KyIdentity tenancy "Cells"). The provider's
private networks are isolated but not encrypted, and its cloud firewalls cannot filter them.

**WireGuard is classical on its own.** The handshake is X25519. Its only post-quantum hook is the optional 32-byte
pre-shared key (PSK), which the whitepaper adds for exactly the record-now-decrypt-later case. A PSK delivered over a
PQ channel makes recorded traffic safe against a future quantum computer.

**The options today (2026-11-25):**

| Option | PQ property | State | Verdict |
|---|---|---|---|
| A. Hybrid mTLS only | HNDL-safe on Go links; PostgreSQL needs PG18 `ssl_groups` and OpenSSL ≥ 3.5; PgBouncer/HAProxy rely on OpenSSL defaults | Mostly in place (W0) | Do regardless |
| B. Kernel WireGuard + static random PSK per host pair, pushed over SSH (`mlkem768x25519-sha256`) and rotated on a schedule | HNDL-safe; no PQ forward secrecy between rotations; authentication X25519 | Debian packages only, nothing new to run | **Simplest PQ mesh** |
| C. Kernel WireGuard + Rosenpass, strict | HNDL-safe with a 2-minute PSK rotation | Released v0.2.3 still uses **Kyber-512 round 3**; ML-KEM (protocol v3) is merged but unreleased; not packaged for Debian; 0.5 MB McEliece public keys; upstream calls it a research project | Later, once ML-KEM ships in a release |
| D. Headscale + Tailscale clients | ML-KEM-768 hybrid WireGuard handshake, merged 2026-11-17, **not in a stable release**; control plane stays classical Noise | Watch | Re-check when stable |
| NetBird + Rosenpass | As C | **Deprecated upstream in v0.82.0 (2026-10-29)** | No |
| Nebula, Netmaker, innernet, Cilium WireGuard | Classical today | — | No |

**Recommendation:** A now. If you want a mesh for firewalling and defence in depth (every internal port listening
only on `wg0`, public firewalls reduced to the WireGuard port plus 443 from the edge), use **B in strict mode**: a link
with no PSK carries nothing. Move to C or D when they ship ML-KEM in a release. The mesh never replaces app-level
authentication: pins and `verify-full` stay.

**Decisions for Q10** (each with a recommendation):

- **10a. Mesh or not.** Recommend A plus B.
- **10b. Strict or permissive.** Recommend strict inside a cell, because every host is ours.
- **10c. Who manages it.** KyQuickStart is frozen against new orchestration features
  (`KyQuickStart:AGENTS.md:683-686`). Recommend a small script in the private infra repo for the hosted cells, not
  a KyQuickStart feature. Self-hosters keep option A.
- **10d. PSK rotation.** Recommend monthly, and on every host change. A retired or compromised host's pairs are
  re-keyed at once.
- **10e. Monitoring.** Recommend alerts on a handshake older than 180 s and on any peer with no PSK.

## Plan table

One row per distinct crypto use. Rows that are the same use in several repos are merged. Columns: **Today** =
the algorithm in use; **PQC target**; **Blocker**; **Wave** (W0-W3 as above; `A` = KyPost spec; `—` = symmetric,
no change). Row 9 is a private-repo row kept out of this public copy; the numbers are otherwise those of the
working table, so cross-references stay valid.

| # | App(s) | Use | Where | Today | PQC target | Blocker | Wave |
|---|---|---|---|---|---|---|---|
| 1 | All Go services and clients: ky-primitives (recoveryclient, s3, offsite S3), ky-server-base, dashboard (private), KyIdentity, KyMessages-Native, KyMessage-Server console, kydrive-server, kydrive-desktop, KyNotes, KyRecovery, KyDNS DoT/DoH, KyCalendar, KyPulse, KyYard (registry, client-go), KyQuickStart, KyVault worker (PR #1) | Outbound TLS key exchange | `KyIdentity-server:internal/netguard/netguard.go:62-71 @ 6e7df38`; `ky-primitives:recoveryclient/client.go:62,110,300 @ 871828c` | Go default groups. X25519MLKEM768 offered first. No `CurvePreferences` or `tlsmlkem=0` anywhere except kyguard. Stays first under `fips140=on` (go1.27.3 `defaults_fips140.go:35-43`) | X25519MLKEM768 (RFC 10024), already offered. Add a handshake test asserting `ConnectionState.CurveID == X25519MLKEM768` (Go 1.25+), with and without `fips140=on`, plus a CI grep that refuses `CurvePreferences` and `tlsmlkem` | none on our side. Per peer: SMTP, AD, SCIM, S3, IdP and apiserver peers are unverified | W0 |
| 2 | KyPost-Server (direct TLS, hosted receiving mTLS), KyDNS replica, kyguard broker listener, KyYard agent↔server, kydrive TLS-pin probe | In-process Go TLS listeners and Ky↔Ky links | `KyPost-Server:backend/internal/api/tls.go:179-190 @ 928ba0be`; `kyguard-server:internal/brokerproto/tls.go:13 @ 37b302b` | Go defaults. kyguard sets `[X25519MLKEM768, X25519]` explicitly. TLS 1.2 clients get classical ECDHE | X25519MLKEM768, already negotiated Go↔Go. Add tests. Where both ends are ours (kyguard broker, KyDNS replica, KyPost receiving, KyYard agent) consider hybrid-only `CurvePreferences` to refuse classical fallback | none | W0 |
| 3 | Every plain-HTTP server behind an edge (ky-server-base, dashboard (private), KyIdentity, kydrive, KyRecovery, KyNotes, KyCalendar, KyMessages-Native, KyPost, KyVault…); KQS nginx edge; NPM 2.17.1 | Inbound TLS at the reverse proxy | `KyQuickStart:internal/edge/nginxconf.go:63-67 @ 950c3f8`; `KyQuickStart:internal/catalog/apps/npm/manifest.yaml:8 @ 950c3f8`; `KyIdentity-server:docs/STRONG-CRYPTO.md` ("Configure the independent HTTPS edge") | No `ssl_ecdh_curve`, so OpenSSL defaults apply. OpenSSL in the pinned nginx 1.30.6-alpine and NPM digests: unverified (Alpine 3.23 and trixie ship 3.5.9) | X25519MLKEM768 via OpenSSL ≥3.5. Set `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1` explicitly, add an image OpenSSL-version check and a handshake probe in KQS e2e, and fix the documented edge examples in each `docs/STRONG-CRYPTO.md` | none (OpenSSL version in the digests unverified). Operator-run proxies are out of our control | W0 |
| 4 | KyQuickStart, private infra repo | Tunnel connectors: cloudflared, frpc | `KyQuickStart:internal/edge/connector.go:26-88 @ 950c3f8`; (private infra repo) | cloudflared: PQ by default over QUIC, with silent non-PQ fallback and none over http2 (Cloudflare docs). frpc v0.71.0: Go TLS defaults (release-binary Go version unverified) | cloudflared `--post-quantum` (strict) and refuse `--protocol http2`. frpc: confirm the Go ≥1.24 build. The frps side is the operator's | none (frps peer is operator-run) | W0 |
| 5 | KyQuickStart, KyRecovery (rest-server 0.14.0), kydrive and KyPost bulk backup | Restic → rest-server transport TLS | `KyQuickStart:internal/dockerhost/backup.go:88 @ 950c3f8`; `KyRecovery-server:docker-compose.restic.yml @ 45dfe28` | restic 0.19.1 Go TLS under `fips140=on` (Go 1.25 FIPS allows X25519MLKEM768). rest-server's Go version and groups: unverified | X25519MLKEM768, already on the client. Pin a rest-server build on Go ≥1.24 and add a handshake probe | none (rest-server build unverified). The payload is a symmetric restic repo, and capsules are X-Wing | W0 |
| 6 | KyAuth-android, KyDrive-for-Android, KyPost-for-Android | Android native TLS (Conscrypt, OkHttp 5.4.0) | `KyAuth-android:app/src/main/java/org/kysecurity/authenticator/pairing/ServerTls.kt:20-34 @ 559e687`; `KyPost-for-Android:app/src/main/java/org/kysecurity/mail/PairingAuthHeaders.kt:58-81 @ 01f304bb` | Platform default groups (minSdk 31). X25519MLKEM768 support: unverified | X25519MLKEM768 if Conscrypt offers it. Otherwise bundle an updated Conscrypt provider or set groups explicitly. Add an instrumented handshake test | platform: Conscrypt ML-KEM support on API 31–36 is unverified | W0 |
| 7 | KyAuth-iOS (target 17.0), KyPost-for-Mac (macOS and iOS 26.0) | Apple native TLS (URLSession/ATS) | `KyAuth-iOS:KyAuth/Networking/HTTPClient.swift:42-50 @ f31cc76`; `KyPost-for-Mac:KyPost/Data/Networking/PinnedSessionDelegate.swift:81-130 @ 165148e` | Groups not set. Apple says iOS/macOS 26 URLSession uses X25519MLKEM768 by default (unverified). iOS 17–18 are classical | X25519MLKEM768 on OS 26+. Record the negotiated group in `docs/native-tls-evidence.md`. Decide whether to raise KyAuth-iOS to iOS 26 | platform (Apple OS 26). Raising the minimum is an owner call | W0 |
| 8 | KyAuth-Linux, KyPost-for-Linux | Linux native TLS (Qt + OpenSSL) | `KyAuth-Linux:src/app/controller.cpp:785-806 @ c2efea6`; `KyPost-for-Linux:core/net/HttpClient.cpp:125-172 @ ae383bf` | Groups not set, so the runtime OpenSSL decides. OpenSSL in Flatpak KDE 6.11 and Ubuntu Touch 24.04: unverified | X25519MLKEM768 via OpenSSL ≥3.5. Check the runtime OpenSSL version in CI, optionally set groups explicitly, and add a handshake test | runtime OpenSSL version (unverified) | W0 |
| 10 | KyQuickStart, ky-primitives offsite SFTP, KyRecovery SFTP replication, kyguard SSH connector (PR #14, branch) | SSH key exchange (Go x/crypto/ssh v0.59.0) | `KyQuickStart:internal/remote/ssh.go:79-86 @ 950c3f8`; `ky-primitives:offsite/sftp.go:68-75 @ 871828c`; `kyguard-server:internal/connectors/sshpasswd/sshpasswd.go:50-80 @ d6b7781` | `mlkem768x25519-sha256` first. Classical fallback against sshd <9.9 (x/crypto has no sntrup761). kyguard leaves the library default list, which includes `diffie-hellman-group14-sha1` | Keep `mlkem768x25519-sha256`. Add a test that it is negotiated against OpenSSH 10. kyguard: set `KeyExchanges` explicitly (drop SHA-1) | peer: target sshd version | W0 |
| 11 | KyQuickStart-AI | OpenSSH client policy (launcher, `bin/on`, `bin/handover`) | `KyQuickStart-AI:bin/ssh-policy:7-27 @ 3a7b8ef`; test `test/unit.sh:258-264` | Subtractive lists keep OpenSSH's PQ defaults (mlkem768x25519 on ≥9.9, sntrup761x25519 on ≥9.0). A test already guards this | already negotiated. No change | peer: target sshd version | W0 |
| 12 | KyQuickStart-AI | Strong kubectl and gh profile (`fips140=on`) | `KyQuickStart-AI:bin/kubectl-policy:54 @ 3a7b8ef`; `kyqs-ai:684-690` | Accepts a Go 1.24 kubectl, whose FIPS list is P-256/P-384 only, so the hybrid is dropped (go1.24.0 `defaults.go:103-105`). gh build Go version unverified | Raise the floor to Go ≥1.25, which keeps X25519MLKEM768 under FIPS | none | W0 |
| 13 | KyQuickStart (CNPG), KyPost-Server/ky-server-base DSNs | PostgreSQL TLS key exchange | `KyQuickStart:internal/kube/dbcluster.go:82 @ 950c3f8`; image `ghcr.io/cloudnative-pg/postgresql:17.12-minimal-trixie` | PG17 `ssl_ecdh_curve` default `prime256v1`, so classical even to Go clients. PG18 default `ssl_groups` is `X25519:prime256v1` (KQS PR #217), also classical. ky-server-base default DSN is `sslmode=disable` | PG18 `ssl_groups = 'X25519MLKEM768:X25519:prime256v1'` (needs OpenSSL ≥3.5 in the image, unverified). Add a handshake test in KQS e2e | needs PG18 (PR #217). Whether CNPG lets us set `ssl_groups` is unverified | W0 |
| 14 | KyIdentity (server sync and dc-agent), kyguard AD connector (PR #13, branch) | LDAPS to Active Directory | `KyIdentity-server:internal/sync/ad.go:178 @ 6e7df38`; `KyIdentity-server:cmd/kyidentity-dc-agent/main.go:316 @ 6e7df38`; `kyguard-server:internal/connectors/adldaps/adldaps.go:61 @ f8b4fd1` | Go offers the hybrid. Windows Schannel almost certainly negotiates classical ECDHE (unverified). Carries the bind password and kyguard `P_old`/`P_new` | X25519MLKEM768 once DCs offer it. Config only: keep Go defaults and log the negotiated group | peer: Windows Server Schannel ML-KEM support is unverified | W0 |
| 15 | KyVault-backend | Outbound TLS (reqwest, lettre SMTP, opendal) and optional `ROCKET_TLS` | `KyVault-backend:src/main.rs:75,203-207 @ c0a86c2a`; `Cargo.toml:128,165-193` | rustls 0.23.46 with the **ring** provider: X25519/P-256/P-384 only, so classical even against PQ peers | Switch to the rustls aws-lc-rs provider (X25519MLKEM768). Whether it is the default group for 0.23.46 is unverified | none (Cargo feature on our fork). Merging from upstream Vaultwarden is the cost | W0 |
| 16 | KyIdentity | AD password queue (server → DC agent) | `KyIdentity-server:internal/adpass/adpass.go:25-83 @ 6e7df38`; `cmd/kyidentity-dc-agent/main.go:36,151` | HPKE base DHKEM(X25519) 0x0020 / HKDF-SHA256 / AES-256-GCM (stdlib). Agent key `x25519:` + 32 B. Carries plaintext AD passwords | HPKE KEM 0x647A X-Wing via Go `crypto/hpke.MLKEM768X25519()`. New `xwing:` key prefix (1216 B pk) and versioned info `kyidentity-ad-password/2`. Agent re-keys | none | W1 |
| 17 | KyNotes-server web, Go teamkeys, MCP bridge; kynotes-desktop (empty, inherits) | Team container-key envelopes | `KyNotes-server:web/src/teamKeys.ts:10-16,65-93 @ 88c85c8`; `internal/teamkeys/envelope.go:18,36`; `cmd/kynotes-mcp/client.go:103-115` | HPKE **mode_auth** DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305 (@hpke/core 1.10.1, CIRCL v1.6.5). Legacy v2 is read-only. Stored server-side, so harvestable: one envelope opens every note in its container | HPKE base KEM 0x647A X-Wing (Go: stdlib `crypto/hpke`, replacing CIRCL). Sender authentication moves to a signature over the envelope, because X-Wing has no AuthEncap: Ed25519 now, ML-DSA-65+Ed25519 under W2. Member identity keys become X-Wing, so every member re-keys | browser lib: WebCrypto has no ML-KEM. Needs a JS/WASM X-Wing (an `@hpke` X-Wing package or the Go helper as WASM, both unverified) | W1 |
| 18 | KyNotes-server web | Device linking (moves the identity private key) | `KyNotes-server:web/src/linking.ts:1-71 @ 88c85c8` | HPKE mode_auth X25519 between one-time keys, plus a 6-digit SAS | HPKE base X-Wing 0x647A. Keep the SAS, but it must cover the X-Wing public key | browser lib (as #17) | W1 |
| 19 | KyIdentity | Keyring device-to-device transfer (SRK) | `KyIdentity-server:web/src/keyringCrypto.ts:119-177 @ 6e7df38`; `internal/api/keyring.go:137-140,335,360` | Ephemeral ECDH P-256 (WebCrypto), HKDF salt = 256-bit out-of-band approval secret, AES-256-GCM. Mitigated: the server ciphertext alone is not enough | HPKE base X-Wing 0x647A, or X-Wing plus the existing secret salt. Server point check becomes a 1216 B X-Wing pk parse | browser lib: WebCrypto has no ML-KEM (unverified per browser) | W1 |
| 20 | KyIdentity, every RP that consumes the keyring (app JS) | Keyring cross-origin OIDC key handoff (`#kh=`) | `KyIdentity-server:web/src/keyringCrypto.ts:193-238 @ 6e7df38`; `internal/api/keyring_handoff.go:61-62` | App ephemeral P-256 `keyring_pk` + page ephemeral P-256 → ECDH → HKDF (**zero salt**) → AES-256-GCM. Lives in the URL fragment | HPKE base X-Wing 0x647A. `keyring_pk` becomes an X-Wing pk (1216 B, about 1.6 KB base64 in a query parameter; URL length unverified) | browser lib (as #19), and every RP's JS must ship it | W1 |
| 21 | KyCalendar | Content-key wraps (account, calendar, worker, previous key) | `KyCalendar:internal/contentkey/suite.go:21-23,94-123 @ 7bce306`; `docs/CONTENT-ENCRYPTION-FORMAT.md:8,15-29` | HPKE X-Wing 0x647A / HKDF-SHA256 / AES-256-GCM. Library exists but nothing imports it ("until build step CE2") | X-Wing 0x647A, already. Wire it in (CE2). Move to the shared helper | none (build step CE2 pending; branches `content/ce1a-keys` and `ce1c-schema` unmerged) | W1 |
| 22 | KyMessages-Native (planned E6, not built) | Guest call-key transport | `KyMessages-Native:docs/superpowers/specs/2026-11-22-e2ee-design.md:100-113 @ 9202576` | Planned: call key encrypted to an ephemeral **X25519** key, plus a 4-word code | Specify HPKE base X-Wing 0x647A before building, so we do not ship classical | browser lib (as #17) | W1 |
| 23 | ky-primitives capsule/recoverykey; every product's backups (ky-server-base, dashboard (private), KyIdentity, KyMessages ×2, kydrive, KyNotes, KyRecovery ceremony, kyguard, KyDNS, KyCalendar, KyPulse, KyYard, KyPost) | Backup capsule KEM, kycap/3 | `ky-primitives:recoverykey/recoverykey.go:42 @ 871828c`; `ky-primitives:capsule/hpke.go:15-17 @ 871828c`; `KyRecovery-server:cmd/ceremony-wasm/main.go:13-25 @ 45dfe28` | HPKE base X-Wing 0x647A / HKDF-SHA256 / AES-256-GCM. Every pinned consumer commit has it | X-Wing 0x647A, already. No change. Unsigned manifests are covered by #33 | none | W1 |
| 24 | kyguard-server | Secret-envelope DEK wrap | `kyguard-server:internal/pqcrypto/seal.go:30-68 @ 37b302b` | HPKE base X-Wing via `recoverykey` key type, info `kyguard/1/dek-wrap`, enc 1120 B | X-Wing 0x647A, already. No change | none | W1 |
| 25 | kydrive-server (planned D15, draft only) | End-to-end vault recipients and signatures | `kydrive-server:docs/superpowers/specs/2026-11-22-e2e-vault-design.md:47-63 @ 9d5a468` | Design: age `mlkem768x25519` recipients (age v1.3.2 has it) plus Ed25519+ML-DSA-65 | As designed (PQ from day one) | desktop has no age implementation, and Android needs ML-DSA (spec :50,56) | W1 |
| 26 | KyAuth-android (vault KEK), KyPost-for-Android (app-lock), KyPost-for-Mac (PIN pepper SE self-ECDH, vault-record HPKE P-256) | Local-only device key wraps (never transmitted) | `KyAuth-android:app/src/main/java/org/kysecurity/authenticator/security/VaultKek.kt:26,70-90 @ 559e687`; KyPost-for-Android `…/security/BiometricUnlockVault.kt:96-111 @ 01f304bb`; KyPost-for-Mac `…/PinPepper.swift:79,136-152`, `…/DeviceAgreementKey.swift:134-167 @ 165148e` | RSA-2048-OAEP Keystore KEK (wrap without a prompt). Secure Enclave P-256 ECDH. Threat is a seized device plus a CRQC, not HNDL | Android: replace the RSA KEK with an auth-bound AndroidKeyStore AES-256-GCM key (prompt on wrap). Apple: the Secure Enclave has no AES keys, so use a CryptoKit `SecureEnclave.MLKEM768` key where the OS offers it (iOS/macOS 26, availability unverified); otherwise keep the Secure Enclave P-256 wrap, which never leaves the device | Android: prompt-on-wrap is a UX change. Apple: `SecureEnclave.MLKEM768` availability unverified | W1 |
| 27 | KyIdentity (issuer); every RP | OIDC id_token/access_token/logout_token signing and JWKS | `KyIdentity-server:internal/crypto/crypto.go:270-305,328-329,354-369,380,407 @ 6e7df38`; `internal/oauth/oauth.go:113,116,690,719` | RS256, a single RSA-2048 key, never rotated, unencrypted 0600 file. JWKS has one RSA JWK. Discovery lists only `RS256`. Own verification is RS256-only | ML-DSA-65 JWS (RFC 9964) alongside RS256. Prerequisite: multi-key JWKS with `kid` rotation. Publish an AKP JWK and list `ML-DSA-65` in discovery. Per client (or `id_token_signed_response_alg`) choose ML-DSA-65 for Ky RPs and keep RS256 for third parties. Signer: go-jose v4.1.9 has `MLDSA65` (`shared.go:124`, `//go:build go1.27`); golang-jwt v5.3.1 has none (a custom SigningMethod is needed) | none on the issuer side. RPs: see #28 and #29 | W2 |
| 28 | ky-primitives `oidcverify` → KyPost-Server, KyNotes, KyCalendar, KyVault worker; KyMessages-Native logout | Ky RP token verification (RS256-only path) | `ky-primitives:oidcverify/oidcverify.go:169,193-194,445,468 @ 871828c`; `KyMessages-Native:internal/sso/logout.go:17,52 @ 9202576` | RS256 only. JWKS filtered to kty=RSA | Accept ML-DSA-65 (stdlib `crypto/mldsa`, AKP JWK) next to RS256. Prefer ML-DSA-65 when the JWKS offers it | none | W2 |
| 29 | go-oidc RPs: ky-server-base, dashboard (private), KyMessages-Native, KyMessage-Server console, kydrive, KyRecovery, kyguard, KyDNS, KyCalendar, KyPulse, KyYard, KyPost | Token verification via go-oidc v3.21.0 / go-jose v4.1.9 | `ky-server-base:internal/sso/oauth.go:73 @ eceb24e`; each repo's `internal/sso/jwks_strength.go` | Uses the algorithms the IdP advertises. go-oidc's `supportedAlgorithms` (oidc.go:180-191) has no ML-DSA and filters discovery at oidc.go:339, so ML-DSA-65 tokens are refused today (local module cache read) | Set `oidc.Config.SupportedSigningAlgs` explicitly to `["ML-DSA-65","RS256"]`. go-jose v4.1.9 verifies ML-DSA on Go 1.27 (unproven end to end). Each `jwks_strength.go` must pass AKP keys (unverified) | upstream go-oidc lacks ML-DSA in discovery. An explicit-config workaround exists (untested) | W2 |
| 30 | KyIdentity (verify); KyAuth-android, KyAuth-iOS, KyAuth-Linux (sign) | KyAuth device signatures: push approve/deny, token refresh, revoke, ES256 jwt-bearer sign-on | `KyIdentity-server:internal/mfa/mfa.go:582-600 @ 6e7df38`; `internal/oauth/device_assertion.go:120-150`; `KyAuth-android:…/pairing/DeviceSigningKey.kt:52-53,115-139 @ 559e687`; `KyAuth-iOS:KyAuth/Pairing/DeviceSigningKey.swift:33-42 @ f31cc76`; `KyAuth-Linux:src/core/crypto.cpp:151-161 @ c2efea6` | ECDSA P-256 in StrongBox/TEE/Secure Enclave. Software key on Linux. Short-lived, forgery-only | ML-DSA-65+Ed25519 hybrid when hardware allows. KyAuth-Linux can do it now in software. Add an alg field to the `kyidentity-push-v3` message | hardware: StrongBox/TEE/SE have no ML-DSA (unverified) | W2 |
| 31 | kydrive-server (verify), KyDrive-for-Android, kydrive-desktop; KyPost-Server native sign-on PoP | Device request signatures and PoP | `kydrive-server:internal/api/devicesig.go:57-89 @ 9d5a468`; `kydrive-desktop:core/api/sign.go:24-38 @ 9596d67`; `KyPost-Server:backend/internal/api/native_signon.go:195-225 @ 928ba0be` | ECDSA P-256 (Android TEE; desktop software key in the OS keyring; KyPost ephemeral app key) | ML-DSA-65+Ed25519 for software keys (desktop) now. Hardware-held keys later | hardware for Android (as #30). Desktop: none | W2 |
| 32 | kydrive-server (+ Android, desktop verifiers); KyPost-Server (+ Android, Mac, Linux verifiers) | Signed TLS-pin rollover statements | `kydrive-server:internal/api/tls_pin.go:31-60 @ 9d5a468`; `KyPost-Server:backend/internal/api/relay_identity.go:31-45 @ 928ba0be`; `KyDrive-for-Android:…/core/TlsPin.kt:57-95 @ 60e755b` | Ed25519 seed, never rotated (linked apps hold the public half). Clients require exactly 32-byte keys. A CRQC could forge a re-pin to a MITM leaf | ML-DSA-65+Ed25519, both required (kyguard construction, lifted), as statement `…-tls-pin/2`. Deliver the hybrid pubkey through a classical-signed rollover before Q-day | client libs: Kotlin via BouncyCastle 1.87 ML-DSA (unverified in bcprov), Swift ML-DSA (unverified), Qt/OpenSSL ≥3.5 ML-DSA (unverified) | W2 |
| 33 | ky-primitives capsule; KyRecovery deposit | Capsule/manifest authenticity (none today) | `ky-primitives:capsule/seal.go:35-37 @ 871828c`; `KyRecovery-server:internal/server/deposit.go:68-115 @ 45dfe28` | Unsigned: anyone with the recovery public key can mint a capsule. KyRecovery uses `ReadUnverifiedManifest` | Optional: sign manifests with a per-product ML-DSA-65+Ed25519 key. This is new behaviour, not a migration, so it needs an owner decision | none (design) | W2 |
| 34 | kyguard-server | Signed objects (manifests, tx, envelopes, receipts, PoP) | `kyguard-server:internal/pqcrypto/sig.go:12,54-70,84-105,123 @ 37b302b` | ML-DSA-65 (stdlib, empty context) + pure Ed25519 over a domain-separated SHA-256 digest. Both must verify | Already hybrid. Lift to ky-primitives (see Shared code). Hardware custodian keys wait (spec line 123) | hardware tokens with ML-DSA | W2 |
| 35 | kyguard-server | Internal broker CA, leaf and broker client certificates | `kyguard-server:internal/brokerproto/ca.go:39-41,69-84,167-216 @ 37b302b` | Ed25519 self-signed CA (20-year), leaf (1-year), client certs (10-year). The CA key is carried in capsules | ML-DSA-65 X.509 (RFC 9881) via Go 1.27 `crypto/x509` and TLS 1.3 ML-DSA schemes, both ends Go. Composite RFC 10073 is not in Go (proposal golang/go#83343). CA pin is by SHA-256, so re-pin at re-pair | none for pure ML-DSA. Composite is upstream Go | W2 |
| 36 | KyDNS-server | Replica node identity and pinned mTLS | `KyDNS-server:internal/replica/identity.go:24-39 @ cdaae83`; `internal/replica/transport.go:35-49,59-74` | Ed25519 seed, self-signed 100-year cert, fingerprint pin, TLS 1.3 | ML-DSA-65 self-signed (RFC 9881) or a hybrid identity statement. Re-pair replicas | none | W2 |
| 37 | KyPost-Server | Hosted receiving transport mTLS identity (MX host ↔ replica) | `KyPost-Server:backend/internal/app/receiving_tls.go:144-157,170,205,319-322,438-442 @ 928ba0be` | Ed25519 keys, SPKI-SHA256 pins both ways (multi-tenant only) | ML-DSA-65 self-signed (RFC 9881), Go 1.27 both ends. Re-pin | none | W2 |
| 38 | KyQuickStart (CNPG) | Database CA and server certificate | `KyQuickStart:internal/kube/dbcluster.go:44-45,146-191 @ 950c3f8` | ECDSA P-256 CA and leaf, 10-year, CA key discarded, no renewal path | Build a re-issue path first. Then ML-DSA when PostgreSQL/OpenSSL and libpq support it | upstream: PostgreSQL and OpenSSL ML-DSA certificates are unverified | W2 |
| 39 | KyYard-server | Server instance identity and agent identity (enroll, auth, rotate, local Docker agent) | `KyYard-server:internal/agent/protocol/messages.go:132-144 @ 8148a97`; `internal/agent/protocol/sign.go:48-59`; `internal/api/local_docker.go:42-44` | Ed25519 throughout. Agent pins the server fingerprint | ML-DSA-65+Ed25519, both required (lift kyguard). The existing rotation flow carries the new key | none | W2 |
| 40 | KyIdentity | AD queue entry signing | `KyIdentity-server:internal/adpass/adpass.go:100-133 @ 6e7df38`; `internal/store/ad.go:53-71` | Ed25519, seed derived from encryption.key. Agent pins the `ed25519:` pubkey | ML-DSA-65+Ed25519 (derive both seeds). Ship together with #16 | none | W2 |
| 41 | KyPost-Server (`cfreceiving`, receiving-worker) | Cloudflare continuous-receiving routing documents | `KyPost-Server:backend/internal/cfreceiving/wire.go:58-59,81-88 @ 928ba0be` | Ed25519-signed, verified in a Cloudflare Worker | ML-DSA-65+Ed25519 | Worker runtime: WebCrypto ML-DSA in workerd is unverified, so a JS/WASM ML-DSA is needed | W2 |
| 42 | KyIdentity, KyPost-Server (`worker/`, `worker-apns/`) | Push relays: FCM service-account JWT and APNs provider token | `KyIdentity-server:workers/fcn/src/fcm.ts:43-82 @ 6e7df38`; `KyPost-Server:worker-apns/src/apns.ts:50-84 @ 928ba0be` | RS256 (Google-issued key), ES256 (Apple .p8) | upstream | Google and Apple define the formats | W3 |
| 43 | ky-server-base, KyIdentity, KyAuth-android, KyAuth-Linux, KyMessages-Native, KyMessage-Server, kydrive (server, desktop), KyNotes, KyRecovery, kyguard, KyDNS, KyCalendar, KyPulse, KyYard, KyQuickStart, KyPost (server, Android, Linux, Mac, XCFramework) | Release and image provenance (Sigstore keyless) | `KyPost-Server:.github/workflows/release-image.yml:235 @ 928ba0be`; `KyIdentity-server:.github/workflows/release-image.yml:176-193 @ 6e7df38` | `actions/attest-build-provenance` v4.2.2. Fulcio ephemeral key, ECDSA P-256 assumed (unverified). Not signed at all: dashboard (private), KyVault (gated to upstream), KyDNS CI `:latest`, deb/rpm | upstream: adopt when Sigstore/GitHub add ML-DSA. No long-term key to rotate | upstream Sigstore/GitHub | W2 |
| 44 | KyPost-for-Linux, KyAuth-Linux | Flatpak OSTree repo and bundle signing | `KyPost-for-Linux:packaging/flatpak/gen-signing-key.sh:52-57 @ ae383bf`; `KyAuth-Linux:packaging/flatpak/gen-signing-key.sh:28-29 @ c2efea6` | GPG RSA-4096, `Expire-Date: 0`, embedded in `.flatpakrepo` | Now: add expiry and a rollover runbook (OSTree multi-key, unverified). PQ: upstream | upstream: OSTree/Flatpak have no PQ signature type (unverified) | W2 |
| 45 | KyAuth-android, KyPost-for-Android; KyAuth-iOS, KyPost-for-Mac, kydrive-desktop | APK/AAB signing; Apple codesign, notarization, ASC API key | `KyPost-for-Android:.github/workflows/release.yml:138-151 @ 01f304bb`; `KyPost-for-Mac:.github/workflows/release.yml:114-120,328-348 @ 165148e` | apksigner (keystore algorithm in secrets, unverified). Play App Signing re-signs. Apple Developer ID certs (algorithm unverified), ES256 ASC key | upstream | upstream: Google APK Signature Scheme and Apple code signing | W2 |
| 46 | ky-primitives (Go module consumers) | Module integrity | `ky-primitives:docs/VERIFYING-RELEASES.md:5-27 @ 871828c` | Unsigned git tags. sum.golang.org (note algorithm unverified) | upstream | upstream Go sumdb | W2 |
| 47 | KyMessages-Native (vodozemac 0.11.2 WASM); KyMessage-Server (Element v1.12.30 → vodozemac 0.10.0; notes bot → 0.11.2) | Olm pairwise setup, device/OTK keys, Megolm room keys and signatures | `KyMessages-Native:web/crypto/src/lib.rs:56-139,226-260 @ 9202576`; `internal/api/e2ee_handlers.go:42,46,58`; `KyMessage-Server:docker-compose.matrix.yml:222 @ 439babc` | Olm: triple Curve25519 DH plus Double Ratchet. Ed25519 device and Megolm signatures. Recording Olm traffic exposes every room key | PQXDH-style hybrid Olm when vodozemac ships it. Alternative: an in-repo X-Wing layer in Native `web/crypto` (owner call). The Native E3 master key spec should name ML-DSA-65+Ed25519 now | upstream vodozemac: PR #120 PQXDH on hold (2026-06-04); no PQ in 0.11.2; no Matrix MSC found | W3 |
| 48 | KyMessage-Server (Element, upstream) | Server-side key backup `m.megolm_backup.v1.curve25519-aes-sha2` | spec URL in inventory; ciphertext lands in Synapse DB dumps inside capsules | Ephemeral Curve25519 to the backup public key | upstream Matrix | Matrix spec and upstream | deprecated (KyMessage-Server) |
| 49 | KyMessage-Server | Cross-signing, SAS verification, Synapse federation signing key, MAS signing keys, MAS upstream OIDC | `KyMessage-Server:internal/matrixinit/matrixinit.go:278-279,350,584-591,611-655 @ 439babc`; `templates/mas.yaml.tmpl:55-64` | Ed25519 (cross-signing, federation X-Matrix), SAS curve25519-hkdf, MAS RSA-2048/P-256, RS256 from KyIdentity | upstream. MAS keeps RS256 from KyIdentity | upstream Synapse/MAS/Matrix spec | deprecated (KyMessage-Server) |
| 50 | KyMessage-Server (Synapse) | Federation and pusher outbound TLS | `KyMessage-Server:internal/matrixinit/templates/homeserver.yaml.tmpl:9,39-41 @ 439babc` | OpenSSL 3.5.x in the image (per prior report). Groups in Synapse context unverified. Federation is closed by default | X25519MLKEM768 if Synapse/Twisted uses OpenSSL defaults (verify) | peer: federation homeservers and push gateways | deprecated (KyMessage-Server) |
| 51 | KyMessages-Native (P2P/SFU), KyMessage-Server (LiveKit v1.13.7), private infra repo | WebRTC DTLS-SRTP and TURN/TLS | `KyMessages-Native:web/src/rtc/hybridCall.ts:863 @ 9202576`; `KyMessage-Server:docker-compose.matrix.yml:243 @ 439babc`; (private infra repo) | DTLS 1.2 ECDHE (browser and Pion). SFU sees media until E6. TURN-TLS groups unverified | Media confidentiality via E6/MatrixRTC frame E2EE, with keys sent over a PQ channel (#22, #47). DTLS PQ: upstream | browsers and Pion: no PQ DTLS (unverified) | W3 |
| 52 | KyIdentity (+ ubuntupush), KyAuth-android, KyAuth-iOS, KyAuth-Linux, KyMessages-Native, KyPost-Server, KyPost-for-Android, KyPost-for-Linux | Web Push / UnifiedPush payload encryption (RFC 8291) | `KyIdentity-server:internal/mfa/push_ubuntupush.go:119-180 @ 6e7df38`; `KyMessages-Native:internal/push/crypto.go:51-65 @ 9202576`; `KyPost-Server:backend/internal/processor/native_sender.go:418-427 @ 928ba0be` | Ephemeral P-256 ECDH + HKDF + AES-128-GCM (aes128gcm) | none: no standard (no PQ RFC 8291 draft found, unverified). For KyAuth (both ends ours, via relays), an inner X-Wing layer is possible (owner call). Minimise payloads | standard missing; browser push services | W3 |
| 53 | KyIdentity, KyMessages-Native, KyNotes, KyPost-Server | VAPID sender authentication (RFC 8292) | `KyIdentity-server:internal/mfa/push_unifiedpush.go:98-139 @ 6e7df38`; `KyMessages-Native:internal/push/vapid.go:21-35 @ 9202576`; `KyNotes-server:internal/webpush/webpush.go:65-76 @ 88c85c8`; `KyPost-Server:backend/internal/config/config.go:886-905 @ 928ba0be` | ES256 (P-256) | none: no standard | standard missing; push services | W3 |
| 54 | KyIdentity (login factor and keyring PRF passkey); KyVault-backend (webauthn-rs 2FA); KyVault-web (stored vault passkeys) | WebAuthn / passkeys | `KyIdentity-server:internal/webauthn/webauthn.go:39-40 @ 6e7df38`; `web/src/keyringPRF.ts:3-5`; `KyVault-web:libs/common/src/platform/services/fido2/fido2-authenticator.service.ts:75,473-498 @ 1344eb7` | `pubKeyCredParams` = [-7] ES256 only | KyIdentity: list COSE -49 (ML-DSA-65, RFC 9964) ahead of -7. go-webauthn v0.18.2 verifies AKP/ML-DSA on Go 1.27 (`protocol/webauthncose/akp.go:94`, `//go:build go1.27`). Keep ES256. KyVault: upstream | authenticators: almost none make ML-DSA credentials (1Password 8.12.44 only). Existing credentials cannot migrate | W3 |
| 55 | KyIdentity | Android key attestation and Apple App Attest verification | `KyIdentity-server:internal/attest/verify.go:56,142-151 @ 6e7df38`; `internal/appattest/appattest.go:177-199` | X.509 chains to Google and Apple roots (P-384 Apple root, unverified) | upstream | Google and Apple | W3 |
| 56 | KyVault-web (`@bitwarden/sdk-internal` 0.2.0-main.1126); KyVault-backend (stores ciphertext) | Org-key shares, admin reset, emergency access, login-with-device, trusted devices, key-connector; V2 signing key | `KyVault-web:libs/legacy-crypto/src/services/encrypt.service.implementation.ts:206-220 @ 1344eb7`; `KyVault-backend:src/db/models/organization.rs:36-37,52,55 @ c0a86c2a` | RSA-2048-OAEP (SHA-1 per SDK, unverified). Stored server-side for years. V2 Ed25519 signing (unverified). PR #1 hosted mode disables reset, Send and emergency access, but org sharing stays RSA | upstream (Bitwarden PQ, none known). The PR #1 Recovery Kit wrap algorithm is unverified | upstream Bitwarden SDK | W3 |
| 57 | KyVault-backend | Session/refresh/invite JWTs; SSO RP | `KyVault-backend:src/auth.rs:44,52,70-100 @ c0a86c2a`; `src/sso_client.rs:228-245` | RS256 RSA-2048 (jsonwebtoken 11.1.0). openidconnect 4.1.0 RP | upstream (jsonwebtoken ML-DSA support unverified). The SSO RP keeps RS256 from KyIdentity | upstream Vaultwarden/jsonwebtoken | W3 |
| 58 | KyPost-Server | DKIM signing (direct delivery) and verification (go-msgauth v0.7.0, Rspamd) | `KyPost-Server:backend/internal/mailmsg/dkim.go:78-80,104-107,260-262 @ 928ba0be`; `backend/internal/adapters/imap/dkim_verify.go:69-71` | RSA-2048 rsa-sha256 (no ed25519-sha256). Admin-driven rotation, 180 days advised | none: no PQ DKIM standard. Meanwhile, optionally add ed25519-sha256 dual-signing | standard missing; receiving MTAs | W3 |
| 59 | KyPost-Server (Maddy inbound, relay submit, direct MX, IMAP import); KyIdentity SMTP | SMTP/IMAP transport to outside peers | `KyPost-Server:backend/internal/mailmsg/smtp_send.go:203,408 @ 928ba0be`; `backend/internal/mailmsg/direct_mx.go:149-152`; `backend/internal/adapters/imap/import_source.go:125-133`; `KyIdentity-server:internal/mail/mail.go:142 @ 6e7df38` | Go defaults on our dialers (hybrid offered). Peers mostly classical. Maddy's Go build unverified. No MTA-STS/DANE | X25519MLKEM768 when peers offer it. Pin a Maddy build on Go ≥1.24 | peer: SMTP/IMAP providers and MXs | W3 |
| 60 | KyDNS-server | DNSSEC validation | `KyDNS-server:internal/dnssec/validator.go:671-675 @ cdaae83` | Alg 8/10/13/14/15/16. No signing, no TSIG | none: no PQ DNSSEC algorithm assigned (unverified) | standard missing (IETF/IANA) | W3 |
| 61 | KyQuickStart (cert-manager, NPM certbot), private infra repo (TURN and native-mail certbot), operator edge certs; certificate-chain checks in every Go client and native app | Public WebPKI certificates | `KyQuickStart:internal/edge/nginx.go:336-373 @ 950c3f8`; `KyQuickStart:internal/edge/certs.go:213-226`; (private infra repo) | Let's Encrypt via cert-manager (RSA-2048 default, unverified) and certbot (ECDSA P-256) | upstream | CA/B Forum: SC-106 closed unmerged 2026-10-21, so no ML-DSA in public TLS | W3 |
| 62 | KyQuickStart (runner key, host pins), KyQuickStart-AI (ssh-keygen ed25519, keyscan pin), ky-primitives offsite and KyRecovery SFTP (host and client keys) | SSH host and user key signatures | `KyQuickStart:internal/runner/state.go:166-196 @ 950c3f8`; `KyQuickStart:internal/remote/ssh.go:178-260`; `KyQuickStart-AI:kyqs-ai:67-75 @ 3a7b8ef` | Ed25519, ECDSA, RSA ≥2048 with SHA-2. Live-only forgery | upstream (x/crypto has ML-DSA SSH only under go1.27 tags, `ssh/mldsa.go:5`; standard and OpenSSH support unverified) | peer: OpenSSH has no ML-DSA keys (unverified) | W3 |
| 63 | KyQuickStart-AI, KyYard (client-go), KyQuickStart | Kubernetes SA token and apiserver PKI | `KyQuickStart-AI:kyqs-ai:296-310 @ 3a7b8ef` | Cluster SA issuer key (RS256/ES256, unverified). Cluster CA | upstream | cluster owner and Kubernetes | W3 |
| 64 | KyPost (server, browser, Android, Mac/iOS, Linux) | OpenPGP keys, encryption, signatures, WKD/Autocrypt publishing | `KyPost-Server:backend/internal/pgpmail/mime.go:179 @ 928ba0be`; `frontend/src/lib/pgpClient.ts:36-41,63-68` | v4 EdDSA-legacy / Curve25519 everywhere; `crypto.PGP()` = `profile.Default()` | RFC 9580 v6 + RFC 9980 (KyPost spec) | KyPost spec: openpgp.js v7 unreleased; Linux GnuPG has no v6 | A |
| 65 | KyPost-Server framing, browser, Android, Mac, Linux | Device enrollment envelope (carries the account private key), enrollment pubkey publish, SAS | `KyPost-Server:backend/internal/users/pgp_device_delivery.go:32,60-84 @ 928ba0be`; `frontend/src/lib/deviceEnrollment.ts:26,65-71,380-393` | HPKE base DHKEM(P-256) / HKDF-SHA256 / AES-256-GCM, v4/v5, enc 65 B | HPKE KEM 0x647A X-Wing (KyPost spec) | KyPost spec: device keystores have no ML-KEM (unverified). The CryptoKit X-Wing suite on 26.0 is unverified | A |
| 66 | ky-primitives sealer; ky-server-base; dashboard (private) | AES-256-GCM at rest (KyRecovery token sealer, deployment key, TOTP secret) | `ky-primitives:recoveryclient/sealer.go:27-55 @ 871828c`; `ky-server-base:internal/crypto/crypto.go:27-65 @ eceb24e`; (private dashboard repo) | AES-256-GCM, 32-byte keys | no change | none | — |
| 67 | KyIdentity | AES-256-GCM at rest: `v2:` row secrets, KyRecovery pin, zero-knowledge keyring wrappers and app subkeys (client-side) | `KyIdentity-server:internal/crypto/crypto.go:109-113,136-200 @ 6e7df38`; `web/src/keyringCrypto.ts:14,52-73,94-102` | AES-256-GCM under HMAC/HKDF subkeys. Keyring: HKDF zero salt → AES-256-GCM | no change | none | — |
| 68 | KyAuth-android, KyAuth-iOS, KyAuth-Linux | Vaults at rest (TOTP vault, push keys, PIN wrap) | `KyAuth-android:…/totp/TotpVault.kt:19-20,78-79 @ 559e687`; `KyAuth-iOS:KyAuth/Totp/TotpVault.swift:17-34 @ f31cc76`; `KyAuth-Linux:src/core/vault.cpp:12,94-95 @ c2efea6` | AES-256-GCM (Keystore, Keychain, scrypt) | no change (the RSA KEK is #26) | none | — |
| 69 | KyVault-web, KyVault-backend | Vault item crypto and Send | `KyVault-web:libs/legacy-crypto/src/enums/encryption-type.enum.ts:7-16 @ 1344eb7` | AES-256-CBC-HMAC (V1), XChaCha20-Poly1305 COSE (V2) | no change | none | — |
| 70 | KyMessages-Native | At rest: pickles and pickle-key wrap, search index, TOTP secret, S3 attachment seal (one deployment-wide key, org bound by AAD), backup mirror | `KyMessages-Native:web/src/crypto/store.ts:3-5,113-116 @ 9202576`; `internal/blobs/seal.go:12,24-54` | AES-256-GCM. vodozemac pickle AES-256-CBC+HMAC | no change | none | — |
| 71 | KyMessage-Server | At rest: media backup mirror, MAS key, SSSS, Matrix encrypted attachments, notes-bot attachments | `KyMessage-Server:internal/backup/media/media.go:305-322 @ 439babc` | AES-256-GCM, AES-256-CTR+HMAC | no change. The notes-bot crypto store is apparently unencrypted at rest (inferred, unverified): a hygiene issue, not PQ | none | — |
| 72 | kydrive-server (+ step K, unpushed) | At rest: KYB2 age STREAM, kydrive age stanza wrap, names, search index, WebDAV locks, restic password, per-org data keys (step K) | `kydrive-server:internal/drive/sealed.go:19-23,68-94 @ 9d5a468`; `internal/drive/names.go:22-30`; local `feat/per-org-keys:internal/drive/orgkeys.go:79-99 @ ac85499` | ChaCha20-Poly1305 (age, 128-bit file key), AES-256-GCM under HKDF(deployment key). Per-org keys: AES-256-GCM under an HKDF(deployment key) KEK. No asymmetric crypto | no change. The per-org key wrap is symmetric, so there is no PQ work. Review the 128-bit age file key (#81) | none | — |
| 73 | KyDrive-for-Android | Session token and biometric gate at rest | `KyDrive-for-Android:…/drive/Session.kt:32,107-136 @ 60e755b` | AES-256-GCM Keystore (biometric key size is the default, unverified) | no change | none | — |
| 74 | KyNotes-server | Note, comment and attachment content; identity wrap; share links; PG archive | `KyNotes-server:web/src/crypto.ts:97-107,136-164 @ 88c85c8`; `internal/backup/pg_archive.go:19-22,64-72` | AES-256-GCM under HKDF(container key / PBKDF2 KEK / backup key) | no change | none | — |
| 75 | KyRecovery-server | Stored credentials at rest | `KyRecovery-server:internal/crypto/envelope.go:14-60 @ 45dfe28` | AES-256-GCM under HKDF(server key) | no change | none | — |
| 76 | kyguard-server | Secret payloads, key-file wrap, TOTP/recovery seal; broker key file | `kyguard-server:internal/pqcrypto/sealenv.go @ 37b302b`; `internal/cli/keyfile.go:85,143-147`; `internal/broker/keys.go:46-80` | AES-256-GCM, Argon2id KEK. Broker seeds are an unencrypted 0600 hex file (by spec §4.1) | no change | none | — |
| 77 | KyDNS, KyCalendar, KyPulse, KyYard | At rest: recovery token, feed and video URLs, webhook/mail/pairing settings, app env and registry secrets, TOTP | `KyCalendar:internal/feed/feed.go:128-133 @ 7bce306`; `KyYard-server:internal/store/application_secrets.go:53-66 @ 8148a97`; `KyPulse-server:internal/monitor/webhook.go:32 @ 7a45d37`; `KyDNS-server:internal/backup/backup.go:47-51 @ cdaae83` | AES-256-GCM, 32-byte keys | no change | none | — |
| 78 | KyPost-Server, KyPost-for-Android, KyPost-for-Linux | At rest: cryptutil seals (IMAP config, TOTP, outbox, DKIM, documents…), replica anchor, restic, EncryptedSharedPreferences, Linux credential seal | `KyPost-Server:backend/internal/cryptutil/cryptutil.go:49-58,155-173 @ 928ba0be` | AES-256-GCM / AES-256-SIV, Argon2id | no change | none | — |
| 79 | KyQuickStart, private infra repo | Restic repo encryption; generated 32-byte app secrets | `KyQuickStart:internal/dockerhost/backup.go:20-36 @ 950c3f8`; `internal/dockerhost/secrets.go:14,65-105` | AES-256-CTR + Poly1305-AES (per restic docs). 32 random bytes | no change | none | — |
| 80 | All apps | MACs, KDFs, password hashing, token hashes, Shamir: HMAC-SHA256 (audit chains, syncauth, CSRF, PoW, pairing, replica fingerprints, SigV4, HS256 LiveKit/editor/Duo), Argon2id, PBKDF2, scrypt, SHA-256 bearer tokens, Shamir GF(2^8) | `ky-primitives:auditchain/auditchain.go:37,281 @ 871828c`; `ky-primitives:password/password.go:51-58`; `ky-primitives:shamir/shamir.go:10 @ 871828c` | Symmetric or hash, mostly 256-bit keys | no change | none | — |
| 81 | ky-primitives syncauth (16-byte floor) and consumers; `KY_SESSION_SECRET` floors (ky-server-base, dashboard (private), kydrive, KyCalendar, KyMessage-Server); KyMessages-Native (no floor at all); TOTP (ky-primitives floor 16 B, KyAuth floor 10 B); KyNotes recovery code; kydrive age file key; KQS SSH AES-128-GCM first; SRTP AES-128; MatrixRTC 16-byte frame keys; TURN MD5/HMAC-SHA1; RFC 8291 AES-128 CEK; KyIdentity MFA recovery codes (about 40 bits) | 128-bit or short-secret review items | `ky-primitives:syncauth/syncauth.go:48 @ 871828c`; `ky-primitives:totp/totp.go:42,111-112`; `KyNotes-server:web/src/recovery.ts:11-12 @ 88c85c8`; `KyQuickStart:internal/remote/ssh.go:81 @ 950c3f8` | 128-bit floors or keys (Grover gives about 64-bit for key search; HMAC forgery is not bound that way) | Review separately: raise floors to 32 bytes where we mint, and prefer AES-256-GCM in the KQS SSH cipher list. Not part of PQC | none | — |
| 82 | ky-primitives offsite, KyNotes, KyRecovery | SMB/NTLMv2 offsite targets | `ky-primitives:offsite/smb.go:88-89 @ 871828c` | MD4/HMAC-MD5/RC4. Refused under `fips140=on` | no change (classically weak already, out of PQ scope) | none | — |

Not listed (n/a): random identifiers, PKCE S256, digest pins, recovery-key pins, static bearer tokens, and the
empty desktop repos (kymessages-desktop; kynotes-desktop inherits row 17). Static sites, ky-ui and the org
`.github` have no crypto.

## Owner questions

Each has a recommendation.

1. **Order.** Approve the waves as set: W0 (tests and config), then W1 (X-Wing key wraps, in the order given),
   then W2 (hybrid signatures, long-lived trust first), with W3 tracked quarterly. KyPost's spec A runs in
   parallel, and its P2 is W1.3. **Recommend yes.**
2. **Security level.** Category 3 (ML-KEM-768, ML-DSA-65) everywhere. CNSA 2.0 asks for category 5 (ML-KEM-1024,
   ML-DSA-87) for US national-security systems. **Recommend category 3 now, and category 5 as an Enterprise option
   only if a customer needs CNSA 2.0.** This is the same as spec A's Q7.
3. **Browser PQ code.** WebCrypto has no ML-KEM or ML-DSA. (a) Compile the ky-primitives `xwing`/`hybridsig` Go code
   to WASM: one implementation and the same vectors, already proven by KyRecovery's ceremony, but a bundle of
   several MB, lazily loaded. (b) A JS library: `@noble/post-quantum`, which openpgp.js v7 uses, or an `@hpke`
   X-Wing package (neither audited by us). **Recommend (a)** for KyIdentity, KyNotes and KyMessages. KyPost's
   OpenPGP stays on openpgp.js (spec A Q5).
4. **KyNotes sender authentication.** X-Wing has no HPKE auth mode, so the team envelopes' sender proof must become
   a signature over the envelope (Ed25519 now, hybrid in W2), and every member re-keys once. **Recommend yes.**
5. **KyIdentity signing-key rotation.** Dual-publishing needs a multi-key JWKS. The docs today say never to replace
   the RSA key. **Recommend:** build rotation (W2.4), keep the RSA key as one JWKS entry for third parties, and add
   an ML-DSA-65 key that Ky relying parties prefer.
6. **Passkeys.** (a) List ML-DSA-65 (COSE -49) ahead of ES256 now, knowing almost no authenticator will use it.
   (b) Wait. **Recommend (a)**, after a test that go-webauthn v0.18.2 verifies an ML-DSA attestation end to end.
7. **KyMessages.** (a) Wait for vodozemac PQXDH (on hold upstream) or MLS PQ suites, and make everything around Olm
   PQ meanwhile: guest call keys, recovery-key wraps and backups. (b) Build our own X-Wing layer over Olm, which is
   custom protocol cryptography in the most sensitive place. (c) Contribute to vodozemac PR #120. **Recommend (a),
   plus (c) if you want to spend effort upstream.** Re-check at the next KyMessages E2EE phase.
8. **Push payloads.** RFC 8291 has no PQ variant. **Recommend:** confirm every push payload carries only a "fetch
   now" hint, never a secret or message content, so the classical encryption protects nothing long-lived. An inner
   X-Wing layer for KyAuth approvals (both ends ours) is possible, but not worth it if the payload holds no secret.
9. **Hybrid-only TLS on Ky-to-Ky links** (kyguard broker, KyDNS replicas, KyPost hosted receiving, KyYard agents):
   refuse a classical fallback where both ends are ours. **Recommend yes, in W0.**
10. **Hosted cell links.** No WireGuard is designed. (a) Service-to-service mTLS with X25519MLKEM768 between cell
    hosts, which is what the Go services already do. (b) WireGuard with Rosenpass. (c) Plain WireGuard (classical).
    **Recommend (a).** If a WireGuard mesh is wanted for operations, (b) is required, not (c).
11. **KyVault.** You ruled out a Ky password manager on 2026-11-15. KyVault's crypto is upstream Vaultwarden and
    Bitwarden, and its image ships upstream's web vault. **Recommend: KyVault is out of scope for this plan**,
    except the one-line rustls `aws-lc-rs` switch if it ships at all.
12. **KyAuth on iOS 17-25.** Apple's PQ TLS needs iOS 26 (unverified). **Recommend: keep iOS 17 as the minimum.**
    Push approvals are signed and short-lived, and the device signing key is not exposed by classical TLS.
13. **Sign backup capsule manifests.** This is new behaviour, not a migration. **Recommend yes, in W2**, with a
    per-product hybrid key, so KyRecovery stops reading manifests unverified.
14. **Release-key hygiene.** The Flatpak signing keys (RSA-4096 GPG) never expire. **Recommend: add an expiry and a
    rollover runbook now.** This is classical hygiene that PQ will need later anyway.
