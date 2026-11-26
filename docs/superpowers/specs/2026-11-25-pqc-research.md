# PQC primary-source research for Ky (worker: lichen, 2026-11-25)

Scope: RFC 9580 / OpenPGP PQC, NIST PQC standards, hybrid guidance, messaging, Go stdlib and libraries,
OpenPGP client ecosystem, sizes and performance. Every external claim links its primary source. Code claims
cite `repo:path:line @ ref`. "unverified" marks what I could not confirm from a primary source.
Datatracker "time" values are last-modified times (from `https://datatracker.ietf.org/api/v1/doc/document/<name>/`),
not publication dates; RFC months come from the RFC header.

**Headline: the OpenPGP PQC draft is now RFC 9980 (Standards Track, June 2026).** It is no longer a draft.

---

## 1. RFC 9580 (OpenPGP, "v6")

Source: https://www.rfc-editor.org/rfc/rfc9580.txt (Standards Track, July 2024; obsoletes RFC 4880, 5581, 6637).

**Formats**
- **v6 public key** (§5.5.2.3): version 6, 4-byte creation time, 1-byte algorithm, **4-byte length of the key material**,
  then the material. The length field lets parsers skip unknown algorithms.
- **v6 fingerprint** (§5.5.4.3): SHA2-256 over `0x9B || 4-byte length || Public Key packet body`, so **32 bytes**.
  The Key ID is the high 64 bits. A v4 fingerprint is a 20-byte SHA-1 (§5.5.4.2). §14.1: never squeeze a v6
  fingerprint into 20-byte fields (for example OpenPGP card slots).
- **v6 signature** (§5.2.3): carries a random **salt** whose size is fixed per hash (Table 23): SHA2-256 16,
  SHA2-384 24, SHA2-512 32, SHA3-256 16, SHA3-512 32 bytes. A v6 key MUST make v6 signatures only
  (§10.3.2.2). A v6 signature made by a v6 key with a non-v6 version is ignored, not fatal (§5.2.3 notes, around line 2878).
- **v6 PKESK** (§5.1.2): names the recipient by key version plus fingerprint. The fingerprint can be omitted for an
  "anonymous recipient". It carries no symmetric algorithm ID. It MUST precede a v2 SEIPD and never a v1 SEIPD.
  A v3 PKESK MUST NOT precede a v2 SEIPD (§5.1.1).
- **SEIPDv2** (§5.13.2): version 2, cipher ID, AEAD ID, chunk size, 32-byte salt, then chunked AEAD output and a final
  tag. The message key and IV come from HKDF-SHA256 over the session key and salt.
- **One message uses one row of Table 26** (§10.3.2.1): either v3 PKESK/v4 SKESK + v1 SEIPD, or v6 PKESK/v6 SKESK + v2 SEIPD.
  So **one message cannot mix a v1-SEIPD recipient and a v2-SEIPD recipient**. Mixed recipient sets fall back to v1
  SEIPD (§13.7: use v2 when all recipients advertise the v2 SEIPD Feature flag 0x08 or are v6 keys with no Features
  subpacket; otherwise you MAY use v1).
- **Certificate structure** (§10.1.1): a v6 certificate needs a **Direct Key signature**, which now holds the
  preferences. A User ID is optional for v6. "Every subkey for a version 6 primary key MUST be a version 6 subkey."
  §10.1.3: "Every subkey for a version 4 primary key MUST be a version 4 subkey."

**Mandatory to implement** (§9.1, line ~4760; Appendix B): Ed25519 (27) and X25519 (25). Ed448 and X448 are SHOULD.
**OCB is MUST** ("Implementations MUST implement OCB. Implementations MAY implement EAX, GCM", §9.6). AES-128 is MUST,
SHA2-256 is MUST.

**Argon2 S2K** (§3.7.1.4): type 4, 16-byte salt, passes t, parallelism p, encoded_m (memory = 2^m KiB). Argon2id with
version 0x13. §3.7.2: "It is RECOMMENDED that implementations use Argon2." Simple S2K MUST NOT be generated.
§13.7: secret keys in v6 packets SHOULD be protected with AEAD (S2K usage 253).

**Deprecations** (Appendix B):
- RSA (SHOULD NOT generate), DSA, ElGamal.
- EdDSALegacy and Curve25519Legacy for v6 keys (MUST NOT, §9.2).
- MD5, SHA-1, RIPEMD160; IDEA, 3DES, CAST5; Simple S2K; MalleableCFB.
- SED packets (MUST NOT generate); Literal Data filename and date; v3 keys and signatures.
- **v4 keys themselves are deprecated:** "an implementation SHOULD NOT generate a version 4 key but SHOULD accept it"
  (§5.5.2).
- The Revocation Key subpacket is deprecated (§5.2.3.23).

**How v6 keys look to v4-only implementations.** RFC 9580 does not define legacy behaviour; it only designs v6 so
parsers can skip it. In practice:
- GnuPG "breaks when getting v6 keys" / "gpg can't process v6 certificates" (2026 OpenPGP Email Summit minutes,
  https://www.openpgp.org/community/email-summit/2026/minutes/).
- "once we have a new format key, classic RNP cannot load the keyring at all" (same minutes).
- Proton found "Thunderbird choked on v6 signatures" and older Thunderbird and go-crypto "failed on unknown subkey
  algorithms" (same minutes).

So a v6 or PQC object can break, not just be ignored by, deployed v4 clients.

**Can one certificate carry v4 and v6? No.** The certificate's version is the primary key's version, and §10.1.1/§10.1.3
force every subkey to match it. "Two certs" means two separate Transferable Public Keys with their own primary keys,
fingerprints and self-signatures (one v4, one v6) for the same User ID. They may be concatenated in one transfer:
"Transferable Public Key packet sequences may be concatenated" (§10.1, §3.6).

How each channel advertises them:
- **WKD** returns "concatenated key blocks" from one GET (draft-koch-openpgp-webkey-service-22 §3.1,
  https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-22.txt), so serving v4+v6 together is in spec.
  The same text requires each key to "carry a User ID packet ... with that mail address", so a UID-less v6 cert
  is not WKD-valid. How clients pick among several returned certs is not specified (implementation-defined).
- **Autocrypt 1.1** carries exactly one certificate per header (exactly five packets) (https://autocrypt.org/level1.html).
  Thunderbird says it "would need two headers, one for autocrypt v1 and one for autocrypt v2" (2026 summit minutes).
- **HKPv2** (draft-ietf-openpgp-hkp-02, WG document) has a "canonical bundle" of "one or more certs" and clients "must
  ignore unknown key versions" (summit minutes; I did not read the draft text itself, unverified beyond the minutes).
- The **replacement-key mechanism** (draft-ietf-openpgp-replacementkey-09, WG document, 2026-11-17) is what links
  an old cert to its successor. Proton says exporting v6 keys is blocked on it (summit minutes).

---

## 2. OpenPGP PQC: RFC 9980 (was draft-ietf-openpgp-pqc)

Status: the final draft revision was **-17**. It was published as **RFC 9980, Post-Quantum Cryptography in OpenPGP,
Standards Track, June 2026**. Authors: Kousidis (BSI), Roth and Strenzke (MTG), Wussler (Proton).
- Datatracker: https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/ (state "RFC", became_rfc → rfc9980).
- Text: https://www.rfc-editor.org/rfc/rfc9980.txt

**Algorithm IDs and requirement levels** (§2.1, Tables 1–2):

| ID | Algorithm | Level |
|---|---|---|
| 30 | ML-DSA-65+Ed25519 | **MUST** |
| 31 | ML-DSA-87+Ed448 | SHOULD |
| 32 | SLH-DSA-SHAKE-128s | MAY |
| 33 | SLH-DSA-SHAKE-128f | MAY |
| 34 | SLH-DSA-SHAKE-256s | MAY |
| 35 | ML-KEM-768+X25519 | **MUST** |
| 36 | ML-KEM-1024+X448 | SHOULD |

The schemes take no parameters; the ID fixes everything. RFC 9980 defines no NIST-curve or Brainpool composites.
Those are in **draft-ietf-openpgp-nist-bp-comp-05**, which is "In WG Last Call" (datatracker, 2026-11-18).

**v4 vs v6** (§3.5, §4.3.2, §5.3, §6.2):
- "All PQ(/T) asymmetric algorithms are to be used only in v6 ... keys and certificates, with the single exception of
  ML-KEM-768+X25519 (algorithm ID 35), which is also allowed in v4 encryption-capable subkeys."
- ID 36 is v6 only. The ML-DSA composites and SLH-DSA are v6 keys and **v6 signatures only**.

So a v4 primary key can gain a PQ *encryption* subkey (ID 35) but can never make PQ *signatures*.

**Sizes in bytes** (Tables 3, 4, 6, 7, 8). The secret keys are stored as seeds.

| | public key | secret (stored) | ciphertext / signature |
|---|---|---|---|
| ML-KEM-768 | 1184 | 64 (seed d‖z) | 1088 |
| ML-KEM-1024 | 1568 | 64 | 1568 |
| X25519 / X448 | 32 / 56 | 32 / 56 | 32 / 56 (ephemeral) |
| ML-DSA-65 | 1952 | 32 (seed ξ) | 3309 |
| ML-DSA-87 | 2592 | 32 | 4627 |
| SLH-DSA-SHAKE-128s / 128f / 256s | 32 / 32 / 64 | 64 / 64 / 128 | 7856 / 17088 / 29792 |

**Composite KEM and combiner** (§4.2, §4.2.1):
- Both component KEMs run in parallel. The KEK is
  `KEK = SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText || ecdhPublicKey || algId || "OpenPGPCompositeKDFv1" || 21)`.
  The RFC describes this as the QSF/X-Wing-style construction.
- The session key is wrapped with AES-256 Key Wrap (RFC 3394).
- The PKESK carries the ECDH ephemeral, then the ML-KEM ciphertext, then a 1-byte length, then (v3 PKESK only)
  a cleartext symmetric algorithm ID, then the wrapped key (§4.3.1). With a v3 PKESK the symmetric cipher MUST
  be AES-128/192/256. SED packets MUST NOT be used.

**Composite signature** (§5.2): independent EdDSA and ML-DSA signatures over the same digest. **Both MUST verify.**
ML-DSA and SLH-DSA use the hedged, pure variant with an empty context (§5.1.2, §6.1.2). The hash digest must be
≥256 bits (§5.3.1, §6.2.1).

**Symmetric choices** (§7.1): AES-256 is MUST. A cert with a PQ key SHOULD list AES-256 and AES-256+OCB. If they
are not listed, they are implicitly appended.

**Mixing PQC and classical recipients** (§3.1, §8.1):
- An implementation "MAY, by default, encrypt messages to both PQ(/T) and traditional keys ... optionally
  displaying a warning".
- But "the confidentiality of a message is not post-quantum secure when using multiple PKESKs unless all of them
  use PQ(/T) encryption schemes".

**Mixing PQC and classical signatures** (§3.3, §8.2–8.3):
- You MAY sign with both a traditional and a PQ key. Verifiers SHOULD accept if at least one non-ignored
  signature verifies.
- A PQ-aware verifier MAY ignore the traditional signatures of a peer known to have a PQ signing key.
- "signing with only PQ(/T) key material is not backwards compatible."
- §8.4: generate fresh secrets. Reusing ECC key material in PQ keys "does not provide backwards compatibility".

---

## 3. FIPS 203, 204, 205

All three were published and took effect **August 13, 2024**:
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf

**FIPS 203 (ML-KEM)**, Table 3, bytes. The shared secret is always 32. Security categories are 1, 3 and 5 (§1/§8).
The 64-byte seed (d, z) "can be stored for later expansion" (§3.3 / §7.1).

| | encapsulation key | decapsulation key | ciphertext |
|---|---|---|---|
| ML-KEM-512 | 800 | 1632 | 768 |
| ML-KEM-768 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 1568 | 3168 | 1568 |

**FIPS 204 (ML-DSA)**, Table 2, bytes. Claimed categories are 2, 3 and 5. The 32-byte seed ξ is the RFC 9980 stored form.

| | private key | public key | signature |
|---|---|---|---|
| ML-DSA-44 | 2560 | 1312 | 2420 |
| ML-DSA-65 | 4032 | 1952 | 3309 |
| ML-DSA-87 | 4896 | 2592 | 4627 |

**FIPS 205 (SLH-DSA)**: hash-based, 12 parameter sets (SHA2 or SHAKE × 128/192/256 × s/f). Table 2 sizes:
- 128s: pk 32, sig 7,856
- 128f: pk 32, sig 17,088
- 192s: pk 48, sig 16,224
- 192f: pk 48, sig 35,664
- 256s: pk 64, sig 29,792

---

## 4. Hybrid and migration guidance

### NIST and NSA
- **NIST SP 800-227**, *Recommendations for Key-Encapsulation Mechanisms*, final, **September 2025**
  (https://csrc.nist.gov/pubs/sp/800/227/final, PDF https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf).
  - §4.6 defines composite KEMs. It names X-Wing as an example PQ/T KEM.
  - §4.6.2 lists approved combiners: SP 800-56C key-derivation methods applied to `Z = (S1, S2)`, and
    SP 800-133 combinations.
  - My reading (unverified): RFC 9980's SHA3-256 combiner, which puts the ML-KEM share first, has the shape of an
    SP 800-56C one-step KDF. Whether a FIPS lab accepts it is unproven.
- **NIST IR 8547**, *Transition to Post-Quantum Cryptography Standards*, **final October 2026**
  (https://csrc.nist.gov/pubs/ir/8547/final, PDF https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf).
  It replaced the Nov 2024 draft on 2026-10-27.
  - "NIST will deprecate quantum-vulnerable public-key cryptography after 2030 and disallow its use under NIST
    standards and guidelines after 2035." Table 2 applies this to ECDSA (≥112-bit), **EdDSA (≥128-bit)** and RSA;
    Table 4 applies it to DH, MQV and RSA key establishment.
  - It cites EO 14412 and OMB M-26-15: high-value or high-impact federal systems must use PQC key establishment by
    **Dec 31, 2030** and signatures by **Dec 31, 2031**. I did not read those documents themselves.
  - §3.2: hybrid KEMs and dual signatures are accommodated in FIPS 140 validation "when suitably combined with a
    NIST-approved scheme".
  - A generic `Z' = Z || T` composite is allowed via SP 800-56C. The order may be reversed, and SP 800-56C will be
    updated for FIPS 203.
- **CNSA 2.0 (NSA): unverified.** media.defense.gov returned HTTP 403 to every fetch. What search snippets of the
  NSA FAQ (https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) say:
  - ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512, and LMS/XMSS for firmware.
  - NSS equipment that cannot support CNSA 2.0 to be phased out by Dec 31, 2030; CNSA 2.0 mandated by Dec 31, 2031.
  - The 2022 per-category "exclusive use" dates (2030–2033) are repeated only by secondary sources.
  - Note: CNSA 2.0 wants the **level-5** sets (1024/87). OpenPGP's MUSTs are level 3 (768/65).

### IETF and IANA

| Item | Status | Source |
|---|---|---|
| **TLS hybrid** (draft-ietf-tls-ecdhe-mlkem) | **RFC 10024**, Standards Track, Aug 2026. IANA TLS Supported Groups: **X25519MLKEM768 = 4588 (0x11EC), Recommended = Y**; SecP256r1MLKEM768 = 4587; SecP384r1MLKEM1024 = 4589. Pure ML-KEM groups 512/513/514 come from draft-ietf-tls-mlkem-11 (Informational, in the RFC Editor queue) | https://www.rfc-editor.org/rfc/rfc10024.txt, https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv |
| **X-Wing** (draft-connolly-cfrg-xwing-kem) | **-11**, 2026-09-23, Informational. Individual draft, Independent Submission stream ("Submission Received"). Not a CFRG RG document | https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ |
| **HPKE PQ** (draft-ietf-hpke-pq) | **-05**, WG document, 2026-07-06. IANA HPKE KEM IDs already assigned: ML-KEM-512/768/1024 = 0x0040/0x0041/0x0042; MLKEM768-P256 = 0x0050; MLKEM1024-P384 = 0x0051; **X-Wing (MLKEM768-X25519) = 0x647A**. HPKE base: RFC 9180, with draft-ietf-hpke-hpke-06 in the RFC Editor queue | https://www.iana.org/assignments/hpke/hpke.xml, https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt |
| **Composite ML-DSA, X.509** (draft-ietf-lamps-pq-composite-sigs) | **RFC 10073**, Standards Track, Nov 2026. Pure ML-DSA in X.509 is **RFC 9881** (Oct 2025); ML-KEM in X.509 is **RFC 9935** (Mar 2026) | https://www.rfc-editor.org/rfc/rfc10073.txt |
| **ML-DSA in JOSE/COSE** (draft-ietf-cose-dilithium) | **RFC 9964**, May 2026. JWS `alg` = `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`. COSE alg **-48 / -49 / -50**, key type AKP. Composite ML-DSA for JOSE/COSE is still a draft: draft-ietf-jose-pq-composite-sigs-07 (WG doc, 2026-11-23) | https://www.iana.org/assignments/cose/cose.xhtml, https://www.iana.org/assignments/jose/jose.xhtml |

### WebPKI (CA/B Forum)
- **No ML-DSA in publicly trusted TLS certificates yet.** Ballot SC-106 (https://github.com/cabforum/servercert/pull/679)
  was opened 2026-08-26 and **closed unmerged 2026-10-21**.
- The author's closing comment records that Chrome wants to keep the rule against a classical CA signing an
  ML-DSA key, and that the cross-signing question is still open.
- S/MIME Baseline Requirements v1.0.11 (ballot **SMC013**, "Introduction of PQC Algorithms", 2025-08-22) added
  PQC algorithms (https://cabforum.org/working-groups/smime/requirements/). The current version is 1.0.17. Exactly
  which algorithms SMC013 allows is unverified (the page was truncated).

### WebAuthn and passkeys
- The COSE IDs for ML-DSA are registered (RFC 9964).
- **1Password 8.12.44 creates ML-DSA passkeys** (blog, 2026-10-20, https://1password.com/blog/post-quantum-passkeys).
  It does so only for sites that list ML-DSA. It cannot create them on iOS or through the native macOS autofill
  extension. No way to upgrade an existing passkey exists yet ("engaged in the W3C and the FIDO Alliance").
- Claims that hardware authenticators lack ML-DSA in the FIDO MDS and that FIDO conformance vectors are pending
  came from secondary sources and are unverified.
- **Plainly: passkeys cannot go PQ yet as a population.**
  - A relying party can list COSE -49 (ML-DSA-65) ahead of -7/-8 so capable authenticators make PQ credentials.
  - In practice almost every user's authenticator (platform passkeys, security keys) will still produce ECDSA or
    EdDSA credentials. Existing credentials cannot be migrated.
  - Server-side ML-DSA verification is needed. Go 1.27 `crypto/mldsa` provides it (§6). Whether Go WebAuthn
    libraries accept AKP/ML-DSA is unverified.

---

## 5. Messaging references

- **Signal PQXDH**: *The PQXDH Key Agreement Protocol*, **Revision 3**, 2023-05-24, last updated 2024-01-23
  (https://signal.org/docs/specifications/pqxdh/).
  - It adds a post-quantum KEM to X3DH; the spec's example is "Crystals-Kyber-1024".
- **Signal SPQR / Triple Ratchet**: blog "Signal Protocol and Post-Quantum Ratchets", **2025-10-02**
  (https://signal.org/blog/spqr/).
  - SPQR is mixed with the Double Ratchet "in a combination we refer to as the Triple Ratchet". It "is rolling out".
  - Specs:
    - *ML-KEM Braid*, Revision 1, 2025-02-21, updated 2025-09-26 (https://signal.org/docs/specifications/mlkembraid/).
      It is a "sparse continuous key agreement" built on ML-KEM-512/768/1024 via an incremental interface.
    - *Double Ratchet*, **Revision 4, 2025-11-04** (https://signal.org/docs/specifications/doubleratchet/).
      §5 covers SPQR and §6 the Triple Ratchet.
  - Reference code: https://github.com/signalapp/sparsepostquantumratchet
- **Apple iMessage PQ3**: blog **2024-02-21** (https://security.apple.com/blog/imessage-pq3/).
  - It uses Kyber keys for initial key establishment plus periodic PQ rekeying. Apple calls this "Level 3".
  - It shipped with iOS 17.4, iPadOS 17.4, macOS 14.4 and watchOS 10.4.
- **MLS PQ ciphersuites**: draft-ietf-mls-pq-ciphersuites **-08** (2026-11-19), IESG state **In Last Call**
  (https://www.ietf.org/archive/id/draft-ietf-mls-pq-ciphersuites-08.txt).
  - 0x0010/0x0011: `MLS_128_MLKEM768X25519_*_Ed25519`. These use HPKE KEM 0x647A (X-Wing). Signatures stay Ed25519.
  - 0x0012–0x0014: P-256/P-384 hybrids.
  - 0x0015–0x0017: pure ML-KEM.
  - 0x0020–0x0022: ML-KEM with **ML-DSA-44/65/87 signatures**.
- **Matrix / vodozemac: no shipped PQ.**
  - vodozemac PR #120 "Add support for PQXDH" (opened 2024-01-30) is still open. The maintainer said "No updates,
    still on hold" on 2026-06-04 (https://github.com/matrix-org/vodozemac/pull/120).
  - The latest vodozemac release is 0.11.2 (2026-11-05).
  - A GitHub search of matrix-org/matrix-spec-proposals for "quantum", "PQXDH", "ML-KEM" and "kyber" found **no PQ
    MSC** (2026-11-25). This is absence of evidence: an MSC under another name could exist (unverified).

---

## 6. Go (we run Go 1.27.4)

Release notes: https://go.dev/doc/go1.24, https://go.dev/doc/go1.25, https://go.dev/doc/go1.26, https://go.dev/doc/go1.27.
Source cited at tag `go1.27.4` (commit 7b2881024c).

### Standard library
- **`crypto/mlkem`** (Go 1.24): ML-KEM-768 and ML-KEM-1024, FIPS 203.
  - Go 1.26 added `DecapsulationKey*.Encapsulator`, `crypto/mlkem/mlkemtest` (derandomized encapsulation for KATs)
    and about 18% faster encapsulation and decapsulation.
  - There is no ML-KEM-512.
- **`crypto/hpke`** (new in **Go 1.26**): "implements ... RFC 9180, including support for post-quantum hybrid KEMs".
  - `NewKEM` IDs (`golang/go:src/crypto/hpke/kem.go:46-65 @ go1.27.4`): 0x0010–0x0012 (P-256/384/521), 0x0020 (X25519),
    0x0041/0x0042 (ML-KEM-768/1024), **0x647a MLKEM768-X25519**, 0x0050 MLKEM768-P256, 0x0051 MLKEM1024-P384.
  - `pq.go:39-40`: "MLKEM768X25519 returns a KEM implementing MLKEM768-X25519 (a.k.a. X-Wing) from draft-ietf-hpke-pq."
  - So **X-Wing is in the stdlib**, and its codepoint follows a draft. Which draft revision it tracks is unverified.
- **`crypto/mldsa`** (new in **Go 1.27**): ML-DSA-44/65/87.
  - `crypto/x509` parses and creates ML-DSA keys and signatures. `crypto/tls` gains ML-DSA SignatureSchemes in TLS 1.3.
  - `Options.Context` supports FIPS 204 contexts up to 255 bytes (`src/crypto/mldsa/mldsa.go:86-92`).
  - "unavailable if using the FIPS 140-3 Go Cryptographic Module v1.0.0 ... available if using v1.26.0 or later"
    (`mldsa.go:8-10`; stubs in `mldsa_fips140v1.0.go`).
  - Open follow-ups: proposal golang/go#83343 (composite ML-DSA, RFC 10073) and #79533/#80272 (external-mu).
- **`crypto/tls` key-exchange defaults** (`src/crypto/tls/defaults.go:16-41 @ go1.27.4`):
  - X25519MLKEM768 has been the default since Go 1.24 (`tlsmlkem=0` reverts).
  - SecP256r1MLKEM768 and SecP384r1MLKEM1024 were added and made default in **Go 1.26** (golang/go#71206; `tlssecpmlkem=0`).
  - Pure MLKEM1024 was added in Go 1.27, opt-in via `CurvePreferences`.
  - Preference order: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM1024, X25519, P-256, P-384, P-521.
  - Go 1.25: X25519MLKEM768 and Ed25519 are allowed in FIPS mode.
- **FIPS 140-3** (https://go.dev/doc/security/fips140):
  - Module v1.0.0 (frozen from Go 1.24) is covered by **CMVP #5247**. It has no ML-DSA.
  - Module **v1.26.0** "Implemented ML-DSA" and is covered by **CMVP #5581**. The frozen module is "available from
    Go 1.26.12, Go 1.27.5"; earlier 1.26/1.27 point releases carry "an earlier iteration".
  - **On Go 1.27.4 we do not yet have the frozen v1.26.0 module.** That only matters if a deployment wants
    `GOFIPS140`.
- **`golang.org/x/crypto/openpgp`** is deprecated: "unsafe by design ... not maintained ... consider
  github.com/ProtonMail/go-crypto/openpgp" (https://pkg.go.dev/golang.org/x/crypto/openpgp). It is v4 / RFC 4880 only.

### Third-party Go libraries
- `filippo.io/mldsa` **v1.0.0**: a wrapper over `crypto/mldsa` on Go 1.27 with module v1.26+, a standalone copy
  otherwise (https://github.com/FiloSottile/mldsa). Not needed on Go 1.27.
- `filippo.io/mlkem768`: "as of Go 1.26 it is just a wrapper for `crypto/mlkem`". It also has an `xwing` subpackage.
- **Cloudflare CIRCL v1.6.5** (2026-08-05, https://github.com/cloudflare/circl/releases) has `sign/mldsa/{mldsa44,65,87}`,
  `sign/slhdsa`, `sign/eddilithium2/3`, `kem/mlkem/{512,768,1024}`, `kem/xwing` (tracks draft-connolly-cfrg-xwing-kem)
  and `kem/hybrid`.

---

## 7. Go OpenPGP libraries

**`github.com/ProtonMail/go-crypto`**: the latest tag is **v1.5.2** (2026-09-28; `-proton` twin tags add Proton-only
forwarding, `openpgp/forwarding.go`).
- **v6 / RFC 9580** is supported since **v1.1.0 (2024-11-07)**: "full support for ... RFC 9580 ... improved
  non-backwards compatible v2 API ... in a separate `v2` package".
  - Both `openpgp` and `openpgp/v2` read and write v6 (`keys_v6_test.go` in both).
  - Opt-in for generation: `packet.Config.V6Keys` (`openpgp/packet/config.go:106-108 @ v1.5.2`).
  - AEAD/SEIPDv2 is opt-in via `Config.AEADConfig` ("By default, it is disabled", `config.go:98-105`).
  - Argon2 via `S2KConfig` (`s2k.Argon2S2K`).
- **PQC is in mainline since v1.5.0 (2026-09-23)**: PR #316 "Implement ML-KEM, ML-DSA, and SLH-DSA", merged 2026-07-15
  (https://github.com/ProtonMail/go-crypto/pull/316).
  - The algorithm IDs are **RFC 9980 final** (`openpgp/packet/packet.go:524-534 @ v1.5.2`): Mldsa65Ed25519 = 30,
    Mldsa87Ed448 = 31, SlhdsaShake128s/128f/256s = 32/33/34, Mlkem768X25519 = 35, Mlkem1024X448 = 36.
  - Packages: `openpgp/mlkem_ecdh`, `openpgp/mldsa_eddsa`, `openpgp/slhdsa`. There is **no build tag**.
  - The PQ maths uses **CIRCL** (`go.mod`: circl v1.6.3; `mlkem_ecdh.go:15` imports `circl/kem`), not the Go stdlib.
  - The combiner matches RFC 9980 (`mlkem_ecdh.go:21,154-162`, domSep "OpenPGPCompositeKDFv1").
- **v4 rules are enforced in key generation** (`openpgp/v2/key_generation.go @ v1.5.2`):
  - ML-DSA and SLH-DSA require v6 (lines 405-407, 420-422).
  - ML-KEM-1024+X448 requires v6, while ML-KEM-768+X25519 may be v4 (lines 480-482).
  - A v6 primary key makes v6 subkeys (lines 271-273).

**`github.com/ProtonMail/gopenpgp/v3`**: the latest tag is **v3.5.2** (2026-09-30). It depends on go-crypto v1.5.2.
Presets live in `profile/preset.go @ v3.5.2`:
- `Default()` (lines 13-32): EdDSA, v4.
- `RFC4880()` (lines 36-52).
- `RFC9580()` (lines 56-81): Ed25519 or Ed448, AEAD, Argon2, `V6: true`.
- **`PQC()`** (lines 84-117): ML-DSA-65+Ed25519 (ML-DSA-87+Ed448 at high security), SHA-512, AES-256,
  **AEAD default mode GCM** (not OCB), Argon2, `V6: true`.

So gopenpgp's PQC profile makes **v6 ML-DSA primary keys**, not v4 keys with PQ subkeys. GCM is a Proton choice;
RFC 9580 only makes OCB mandatory to implement, so GCM output needs recipients that advertise GCM.

**Proton's production rollout**: blog "Proton Mail introduces post-quantum encryption", **2026-05-05**
(https://proton.me/blog/introducing-post-quantum-encryption).
- Opt-in, on all plans, rolled out gradually. It applies to new mail only. It pauses E2EE forwarding.
- Support page with minimum app versions: https://proton.me/support/mail-post-quantum-protection.
- Neither page names algorithms or key versions. At the March 2026 summit Proton said it will "not by default expose
  v6/PQC keys to outside users" and is waiting on the replacement-key mechanism to export v6 keys.

---

## 8. Client ecosystem (Nov 2026)

| Client / library | RFC 9580 v6 | RFC 9980 PQC | Source |
|---|---|---|---|
| **GnuPG** 2.5.24 (2026-09-23; 2.5.25 unreleased) | **No.** Speaks LibrePGP (v5). "gpg can't process v6 certificates" (summit). NEWS never mentions reading v6 keys (absence; unverified) | Default is LibrePGP Kyber composites (v5 subkeys) since 2.5.0. **2.5.23 (2026-09-22) added `--allow-9980`**: in "9980 mode" it does ML-KEM encryption "with X448, X25519, Brainpool, or NIST curves". It is "only recommended if external policy requirements demand" it; others "should keep on using the standard LibrePGP Kyber". **No ML-DSA** in NEWS. Summit: GnuPG can "import a v4 PQC subkey and gracefully ignore it, but only of type 35" | https://github.com/gpg/gnupg/blob/master/NEWS (mirror of dev.gnupg.org, which was unreachable) |
| **Thunderbird** (RNP) | Not shipped. RNP **v0.18.1** (2025-11-21, latest release): `ENABLE_CRYPTO_REFRESH` and `ENABLE_PQC` are compile options, **off by default**, using **pre-RFC IDs** (Kyber768+X25519 = 105 …) (`rnpgp/rnp:include/repgp/repgp_def.h:220-230 @ v0.18.1`). RNP main has crypto-refresh **ON by default**, and PQC is still opt-in with IDs 35/36/30/31 (`CMakeLists.txt:126-127`, `repgp_def.h:223-233 @ f6cfd01310`) | Summit plan: "v4 PQC support in Thunderbird could be there maybe end of the year", "thunderbird will always have a v4 traditional encryption subkey in addition to pqc". No shipped release found (unverified) | https://github.com/rnpgp/rnp, summit minutes |
| **Proton Mail** | Yes internally (gopenpgp) | Yes, opt-in since 2026-05-05; not exposed to outsiders by default | §7 |
| **Sequoia** | sequoia-openpgp **2.0.0** (2025-03-04): "adds support for RFC 9580" | **2.4.0** (2026-07-02): "support for post-quantum cryptography as defined in RFC 9580 [sic, 9980]" with OpenSSL and RustCrypto backends, including SLH-DSA. Latest is **2.5.0** (2026-11-25). `sq` CLI is 1.5.0 (2026-10-07); whether `sq key generate` exposes PQC is unverified | https://gitlab.com/sequoia-pgp/sequoia/-/raw/main/openpgp/NEWS, crates.io |
| **OpenPGP.js** | Yes since **v6.0.0** (2024-11-04). AEAD behind `config.aeadProtect` | **Not in any release.** Latest is v6.3.3 (2026-11-20) with no `post_quantum`. On **unreleased main/v7**: ML-KEM-768+X25519 and ML-DSA-65+Ed25519 (PR #2022, merged 2026-07-10, ref. draft -17) using `@noble/post-quantum`; ML-KEM-1024+X448 and ML-DSA-87+Ed448 in open PR #2077 | https://github.com/openpgpjs/openpgpjs |
| **Gmail** | No OpenPGP | No. Client-side encryption uses **S/MIME 3.2** with X.509 certificates, or "encryption with guest accounts" with Assured Controls | https://knowledge.workspace.google.com/admin/security/gmail-only-configure-s-mime-for-client-side-encryption, https://support.google.com/mail/answer/13317990 |
| **Apple Mail + GPGTools** | No. Latest GPG Suite is **2023.3** (2023-07-23), bundling MacGPG/GnuPG **2.2.41** | No | https://gpgtools.org/releases/gpgsuite/release-notes.html |
| **K-9 / Thunderbird for Android** (OpenKeychain) | No. OpenKeychain says "no longer actively developed"; last tag v6.0.4, last push 2024-05-16 | No. Summit: "might be better to use pgpainless instead of openkeychain" | https://github.com/open-keychain/open-keychain |
| **Mailvelope** | No. v6.3.0 (2026-06-11) pins **openpgp 5.11.3** | No | https://github.com/mailvelope/mailvelope |
| **FlowCrypt** (browser) | Via openpgp 6.3.3 (v6 capable) | No (6.3.3 has no PQC) | https://github.com/FlowCrypt/flowcrypt-browser |
| **Delta Chat** (chatmail core v2.69.0, rpgp 0.21.1 with `pqc` feature compiled in) | rpgp reads and writes v6 | The library can, but core still **generates v4 Ed25519Legacy** keys (`chatmail/core:src/pgp.rs:46 @ eb05e0c204`). Summit: Delta Chat is "planning to deploy v6 + PQC + Forward secrecy all at once" | https://github.com/chatmail/core |

**Autocrypt**
- **Autocrypt 1.1.0** (https://autocrypt.org/level1.html): exactly one TPK of 5 packets per header. MUST handle
  Ed25519/Cv25519. Headers "above 10 KiB ... SHOULD treat ... as invalid".
- **A v6 ML-DSA-65 certificate does not fit** (about 10–14 KB binary before base64; see §10). A v4 cert plus an
  ML-KEM-768 subkey does fit (about 2 KB).
- **Autocrypt v2**: draft-autocrypt-openpgp-v2-cert **-03** (2026-07-06, individual,
  https://www.ietf.org/archive/id/draft-autocrypt-openpgp-v2-cert-03.txt).
  - A **v6 certificate with an Ed25519 primary** (algorithm 27, not ML-DSA) plus an ML-KEM-768+X25519 **fallback**
    subkey and ML-KEM-768+X25519 **rotating** subkeys (algorithm 35), for forward secrecy by time-boxed rotation.
  - It is PQ for confidentiality and classical for authentication, presumably to keep the size down (inference).

**WKD**: draft-koch-openpgp-webkey-service **-22** (2026-07-22), still an individual draft. See §1 for the multi-cert
and UID rules. The draft cites only RFC 4880 and LibrePGP; it does not mention RFC 9580.

---

## 9. Mobile and web libraries

- **Browser: OpenPGP.js.** v6 is usable today. PQC exists only on unreleased main (v7, §8). No release date was found
  (unverified).
- **Bouncy Castle (Java/Kotlin)**, bc-java.
  - v6 packets: `PublicKeyPacket.VERSION_6` (`pg/.../bcpg/PublicKeyPacket.java:52 @ r1rv87`).
  - **RFC 9980 PQC lands in 1.87** (tag `r1rv87`, 2026-11-12). It has `PublicKeyAlgorithmTags` 30–36 (`:109-164`)
    plus the `MLKEMComposite*`, `MLDSAComposite*` and `SLHDSA*` BCPGKey classes. They are absent at `r1rv86`
    (2026-09-11).
  - Maven Central publication of 1.87 is unverified.
- **Swift / iOS.** ObjectivePGP's last release is 1.0 (2024-05-04), last push 2024-05-20. It is dual-licensed and
  commercial use needs a paid license. Its README advertises no RFC 9580 or PQC support.
  - **Viable Swift paths**: gopenpgp via gomobile (Proton's own approach; the gopenpgp README mentions mobile builds,
    unverified), Sequoia via FFI, or rpgp via FFI (uniffi is not verified).
- **rpgp (Rust)**: `pgp` **0.21.1** (2026-11-11). README: "implementation of OpenPGP as specified in RFC9580 ...
  v6 key formats and AEAD".
  - Feature **`pqc`**: "PQC support as specified in RFC 9980 (this feature was previously called `draft-pqc`)".
    It uses RustCrypto `ml-kem` 0.2.1, `ml-dsa` 0.0.4 and `slh-dsa` 0.0.3 (`rpgp/rpgp:Cargo.toml:107-146`, main).
  - Note: ml-dsa 0.0.x is pre-1.0.
- **Sequoia FFI**: v6 since 2.0, PQC since 2.4. The C/Swift binding status of the current FFI crate is unverified.

---

## 10. Performance and sizes

### Measured timings (primary sources)
- **Go `crypto/mlkem`, ML-KEM-768** (benchmarks use `GenerateKeyInternal768` / `NewDecapsulationKey768`,
  `src/crypto/mlkem/mlkem_test.go:225-239 @ go1.26.0`). From golang/go commit 592775ec7d
  (https://github.com/golang/go/commit/592775ec7d, Apple M2, before → after the Go 1.26 optimisation):
  - KeyGen 28.95 → **28.64 µs**
  - Encaps 43.13 → **35.02 µs**
  - Decaps 43.80 → **35.49 µs**
- **Go ML-DSA-44 Sign** (commit 9962d95fed): **244.5 µs** on Apple M2 and **386.5 µs** on AMD EPYC 7443P.
- **ML-DSA-65 keygen, sign and verify timings for Go or CIRCL: no published primary-source numbers found.** Gap.
  They can be measured with `go test -bench` in `crypto/mldsa`, which this read-only task forbids.
- RFC 9980 §10.1 discusses SLH-DSA performance qualitatively. The "f" variants sign faster with larger signatures.

### OpenPGP size estimates
These are **my arithmetic** from RFC 9580/9980 field sizes; they are estimates, not measurements. Assumptions: ~100
bytes of subpackets per self-signature, SHA-512 hashing (32-byte salt), new-format headers (2–5 bytes).
- **v6 PQC certificate**: ML-DSA-65+Ed25519 primary, one UID, one ML-KEM-768+X25519 subkey.
  - Primary key packet: about 1,997 B (10 + 32 + 1952).
  - Each v6 composite self-signature: about 3,520 B (64 + 3309 + 32 salt + subpackets). The cert has three
    (direct-key, certification, subkey binding).
  - Subkey packet: about 1,229 B.
  - Total: **about 13.8 KB binary, about 18.5 KB armored**. Without a UID (allowed for v6): about 10.3 KB.
  - With ML-DSA-87+Ed448 and ML-KEM-1024+X448: about 18.5 KB binary.
- **v4 certificate plus a PQ encryption subkey** (existing Ed25519 v4 cert, about 0.5 KB, plus ID 35 subkey and v4
  Ed25519 binding): **about +1.4 KB, about 2 KB total**. It fits Autocrypt's 10 KiB limit.
- **Per-recipient PKESK for ID 35**: v6 is about 1,200 B (fingerprint 32 + 32 + 1088 + 1 + 40 wrapped AES-256 key
  + headers); v3 is about 1,175 B. A classical X25519 PKESK is about 90–110 B.
- **ML-DSA-65+Ed25519 v6 signature**: about 3.45 KB per signature, against about 0.15 KB for a v6 Ed25519 signature.

---

## Gaps / unverified
1. **CNSA 2.0**: NSA sites return 403. The dates above come from search snippets only.
2. Exact algorithms permitted by CA/B Forum S/MIME ballot SMC013 (page truncated).
3. WebAuthn: the FIDO MDS and conformance status of ML-DSA authenticators; Go WebAuthn library support for COSE AKP / -49.
4. Whether GnuPG 2.5.x can *read* RFC 9580 v6 keys in `--allow-9980` mode (NEWS is silent; the summit said no).
5. Thunderbird: no release with v4 PQC confirmed; I did not read Thunderbird release notes directly.
6. `sq` CLI PQC key-generation flags; Sequoia FFI binding status.
7. OpenPGP.js v7 release date; Bouncy Castle 1.87 on Maven Central.
8. HKPv2 draft text (only the summit summary was read); WKD client behaviour with several returned certs.
9. ML-DSA-65 Go/CIRCL timings (none published); all OpenPGP size figures are estimates.
10. Which draft-ietf-hpke-pq revision Go's 0x647a implementation tracks; FIPS-lab acceptability of the RFC 9980 combiner.
11. Matrix: no PQ MSC found by search (absence, not proof).
12. EO 14412 and OMB M-26-15 are cited only as NIST IR 8547 describes them.

## Implications for Ky

**Ky's current stack**
- KyPost-Server `backend/go.mod:3,10,11 @ 928ba0be` pins `go 1.26.9`, **go-crypto v1.5.2** and **gopenpgp v3.5.2**,
  both of which already contain RFC 9980.
- It generates and encrypts through the default profile: `crypto.PGP()` in `backend/internal/pgpmail/mime.go:179`,
  which is v4 EdDSA (`gopenpgp profile/preset.go:13-15`).
- The frontend pins `openpgp ^6.3.3` (`frontend/package.json:20 @ 928ba0be`), which has **no PQC**.

**Ready today**
- RFC 9580 v6, AEAD and Argon2 in Go via go-crypto v1.5.2 / gopenpgp v3.5.2 (`profile.RFC9580()`).
- RFC 9980 in Go via go-crypto v1.5.2 / gopenpgp `profile.PQC()`: final IDs, no build tag, CIRCL underneath.
- TLS: X25519MLKEM768 and the SecP* hybrids are default in Go 1.26+ (RFC 10024). Nothing to do beyond staying on
  default `CurvePreferences`.
- HPKE with X-Wing (0x647A) and ML-KEM in Go 1.26+ `crypto/hpke`. Usable for Ky-internal envelope encryption.
- ML-DSA (FIPS 204) in Go 1.27 `crypto/mldsa`, plus X.509 and TLS 1.3 support. Pure ML-DSA JOSE/COSE IDs are final
  (RFC 9964), so Ky tokens or JWS could add `ML-DSA-65`.
- Rust (rpgp `pqc`), Sequoia 2.4+ and Bouncy Castle 1.87 implement RFC 9980, so native clients have options.

**Draft or unreleased (plan for it, don't depend on it)**
- OpenPGP.js PQC (v7 main only), so the KyPost web client cannot do PQC yet.
- Thunderbird PQC (RNP main, opt-in); key replacement (draft-09); HKPv2; Autocrypt v2 (-03); NIST/BP OpenPGP composites (WGLC).
- HPKE-PQ (-05) and X-Wing (-11, ISE): stable codepoints, not yet RFCs.
- MLS PQ suites (IESG LC); composite ML-DSA for JOSE (draft -07); Go composite ML-DSA (#83343).

**Blocked or interop-limited**
- **External OpenPGP interop with v6 or ML-DSA keys.** GnuPG, GPGTools, OpenKeychain, Mailvelope and shipped
  Thunderbird can choke on v6 certs and signatures (summit minutes). Publishing a v6 cert by default would break
  correspondents.
- The interoperable PQ path for email today is **v4 cert + ML-KEM-768+X25519 (ID 35) encryption subkey, keeping
  the classical X25519/Cv25519 subkey**. This is Thunderbird's plan and the only v4-legal PQ algorithm.
- Mixed-recipient messages are not PQ-confidential (RFC 9980 §8.1). Signatures stay classical for v4 keys.
- v6 / ML-DSA identity keys should be kept internal (Proton's approach) until key replacement and HKPv2 land.
  Autocrypt 1.1 cannot carry a v6 ML-DSA cert (10 KiB limit).
- **Passkeys and WebAuthn cannot go PQ** for the user population (only 1Password, partially). KyIdentity should list
  -49 as optional and keep ES256/EdDSA.
- **Publicly trusted TLS certificates cannot be ML-DSA** (SC-106 closed). Only private PKI can.
- **CNSA 2.0** wants level-5 algorithms (ML-KEM-1024, ML-DSA-87), but OpenPGP MUST-level and Autocrypt v2 use level 3.
  Ky needs a policy decision if CNSA-bound customers (Enterprise) matter.
- **FIPS deployments** need Go ≥1.27.5 for the frozen v1.26.0 module that contains ML-DSA (we are on 1.27.4).
  go-crypto's PQ code runs on CIRCL, not the Go FIPS module.
