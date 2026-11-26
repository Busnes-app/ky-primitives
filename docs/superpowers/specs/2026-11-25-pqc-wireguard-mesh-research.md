# Post-quantum WireGuard mesh for Ky hosted cells (research, worker lichen, 2026-11-25)

Answers spec B question 10 (`ky-primitives` branch `docs/pqc-stack-plan` @ `66dcb35`,
`docs/superpowers/specs/2026-11-25-pqc-stack-plan.md:298-300`, which recommends (a) mTLS and says a mesh,
if wanted, must be (b) WireGuard + Rosenpass). Read-only research. Nothing was built or tested.

Short version:
- WireGuard alone is classical (X25519). Its only PQ hook is the optional 32-byte PSK.
- The released Rosenpass (v0.2.3) still uses **Kyber-512 round 3**, not ML-KEM. ML-KEM is merged on
  `main` only (protocol v3), unreleased.
- **NetBird deprecated its Rosenpass support in v0.82.0 (2026-10-29).**
- **Tailscale merged a hybrid ML-KEM-768 WireGuard handshake** (Noise IKhfs+psk2) on 2026-11-17. It is
  not in a stable release yet.
- Ky's cells are not designed around a private network. Hetzner Cloud Networks are not encrypted.
  The plan's mTLS baseline is still right. A mesh adds defence in depth and simpler firewalling, not
  PQ coverage that mTLS can't give.

## Ky context (what the mesh would carry)

- Cells are complete installs: a cell = a finer `home_region` slug, own replicas, PostgreSQL, object
  storage prefix (`KyIdentity-server:docs/superpowers/specs/2026-11-19-tenancy-design.md:938-955 @ 6e7df38`).
  One deployment may serve several cells (C2, `:952`). Max 32 cells per app (`:963`).
- KyPost: "Each region is a complete multi install … Only routing crosses regions", and "Every hop is
  encrypted" (`KyPost-Server:docs/superpowers/specs/2026-11-22-multi-host-replicas-design.md:67-72 @ 928ba0be`).
  Hop table `:599-615`:
  - edge→replica becomes TLS (`:607`);
  - replica→PostgreSQL/PgBouncer becomes `sslmode=verify-full`, and so does primary→standby replication (`:609-610`);
  - MX host→receiving server stays pinned TLS 1.3, also across regions (`:611`);
  - Rspamd stays on loopback (`:612`);
  - Ollama is "TLS, or … loopback" (`:613`).
  - Object storage is one bucket per cell over verified TLS (`:456-457`).
- So the inter-host traffic inside one cell is HTTPS (edge→replica), PostgreSQL wire protocol
  (replica→PG, PgBouncer, streaming replication), Ky↔Ky mTLS (MX↔receiving), plus operator SSH and
  any metrics. Nothing in the specs needs L3 connectivity between cells.
- Hetzner: "Traffic between cloud servers inside a Network is private and isolated, but not
  automatically encrypted. We recommend you use TLS or similar protocols to encrypt sensitive traffic"
  (https://docs.hetzner.com/networking/networks/faq/). Cloud Firewalls cannot filter private Networks:
  "Not yet, because we consider the private networks to be "secure"" (https://docs.hetzner.com/cloud/firewalls/faq/).
- KyQuickStart is frozen: "no new catalog apps, Ky or third-party, and no new standalone orchestration
  features" (`KyQuickStart:AGENTS.md:683-686 @ 950c3f8`; `docs/redirect.md:15-17`). Its targets are
  Docker hosts over SSH and Kubernetes clusters (`AGENTS.md:190,228`). It does not set up networks.
  KyPost, KyDrive, KyDNS and KyMessages are Docker-only (`AGENTS.md:228`). So a mesh "managed by KyQuickStart" needs
  an owner exception to the freeze.
- No repo has WireGuard/Rosenpass today (plan `:59`). In KyQuickStart the only mesh mention is a
  catalog note rejecting the "NetBird reverse proxy (beta)" (`KyQuickStart:docs/superpowers/specs/2026-10-06-third-party-catalog-design.md:290 @ 950c3f8`).

## 1. WireGuard and PQ

Source: WireGuard whitepaper, draft revision e2da747, 2020-06-01 (https://www.wireguard.com/papers/wireguard.pdf).
- Handshake construction: `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"` (§5.4, p. 10).
  Static identities and ephemerals are Curve25519. Secrecy "relies on the security of the Curve25519
  ECDH function" (§5.2, p. 7).
- §5.2 "Optional Pre-shared Symmetric Key Mode": "In order to mitigate any future advances in quantum
  computing, WireGuard also supports a mode in which any pair of peers might additionally pre-share a
  single 256-bit symmetric encryption key". Its attack model is record-now-decrypt-later, and "if the
  pre-shared symmetric key is compromised, the Curve25519 keys still provide more than sufficient
  protection". It "allows for building on top of WireGuard sophisticated key-rotation schemes". That
  is the hook Rosenpass uses.
- §5.4.2 side note: hashing the static key in msg.static "would have some limited degree of non-forward
  secret post-quantum security". Not part of WireGuard.
- Timers (§6.1 table, p. 14): Rekey-After-Time 120 s, Reject-After-Time 180 s. A PSK change takes effect at the
  next handshake.
- Known limitations page: "WireGuard is not, by default, post-quantum secure". It recommends running a
  real PQ handshake on top and loading its key into the PSK slot
  (https://www.wireguard.com/known-limitations/).
- Consequence: a **static** random per-pair PSK, delivered over a PQ channel, already protects recorded
  traffic from a future quantum attacker (§5.2's model). What it lacks is PQ forward secrecy: anyone
  who later steals the PSK and breaks X25519 can decrypt. Rotating the PSK narrows that window. Rosenpass
  automates the rotation every 2 minutes.
- Authentication stays X25519 in every option below. That doesn't matter for harvest-now-decrypt-later
  (HNDL), only against an active quantum attacker.

## 2. Rosenpass

Repo https://github.com/rosenpass/rosenpass. Cited at tag `v0.2.3` (`512fe426b`) unless marked `main` (`ed07bfab9`).

**What it is.** It is a separate UDP key-exchange daemon. Every two minutes it gives WireGuard a new PSK through
`wg set <dev> peer <pk> preshared-key /dev/stdin` (`rosenpass/src/app_server.rs:629-640`). "WireGuard
itself still performs the pre-quantum-secure key exchange and transfers any transport data with no
involvement from Rosenpass" (`papers/whitepaper.md:12`). It is hybrid: "Rosenpass+WireGuard is
cryptographically no less secure than using WireGuard on its own" (`readme.md:28`). It builds on
Post-quantum WireGuard (Hülsing et al., IEEE S&P 2021, https://eprint.iacr.org/2020/379), adding a
"biscuit" cookie against state-disruption attacks (`whitepaper.md:10,52`). The WireGuard side stays
vulnerable to state disruption (`whitepaper.md:54`).

**Algorithms (correction to the task brief):**
- Static KEM: Classic McEliece 460896. The paper gives pk 524,160 B, sk 13,568 B, ct 188 B and calls it "as hard to break
  as 192-bit AES" (`whitepaper.md:95`). It has not been chosen by NIST (same line).
- Ephemeral KEM: **Kyber-512**. pk 800 B, ct 768 B, sk 1,632 B (`whitepaper.md:104`). Protocol label
  `ekem=kyber512 skem=mceliece460896` (`whitepaper.md:184`). The released crate uses liboqs features
  `classic_mceliece` and `kyber`, commented "Kyber-512 (NIST round 3), not to be confused with ML-KEM
  (FIPS 203)" and "McEliece (NIST round 3), not to be confused with McEliece (NIST round 4)"
  (`main:rosenpass/Cargo.toml:217-221`. At `v0.2.3`, `rosenpass/Cargo.toml:22` has the same `oqs-sys` features).
- **ML-KEM is on `main` only.** PR #1148, merged 2026-10-15: "use ML-KEM instead of Kyber (round 3) for
  protocol version 3", ML-KEM-**512** via RustCrypto `ml-kem`. Protocol v2 keeps Kyber
  (https://github.com/rosenpass/rosenpass/pull/1148). ML-KEM-768 is still open as issue #701
  (https://github.com/rosenpass/rosenpass/issues/701). `main` is `version = "0.3.0-dev"` (`main:Cargo.toml:3`).
- Responder authentication rests on McEliece alone (`whitepaper.md:40`). Forward secrecy rests on
  Kyber plus zeroisation (`whitepaper.md:48`). The cookie DoS mechanism is "not yet included in the
  implementation" (`whitepaper.md:169`).

**Releases.** v0.2.3 came out 2026-08-03 as "a backport release with upgraded dependencies … (except
`liboqs`)" (https://github.com/rosenpass/rosenpass/releases/tag/v0.2.3). Before that: v0.2.2 on 2024-06-05
and v0.2.1 on 2023-11-18. Assets: x86_64-linux tarball and OCI image, no `.deb`.

**Proof and audit status.**
- Symbolic ProVerif analysis ships in `analysis/`. "We are working on a cryptographic proof of security"
  (`readme.md:50`). CryptoVerif is "work in progress" (`whitepaper.md:14`). I found no published
  CryptoVerif proof or Rosenpass-specific peer-reviewed paper (unverified beyond a search).
- Penetration test by Radically Open Security, posted 2024-03-01: "one moderate and three low risk
  issues", the moderate one a remote DoS panic (RUSTSEC-2023-0077, fixed in 0.2.1)
  (https://rosenpass.eu/blog/pentest_january/, https://rustsec.org/advisories/RUSTSEC-2023-0077.html).
  Report: https://rosenpass.eu/docs/rosenpass-project/pentest/. The tested version is unverified; it predates 0.2.2.
- Related academic work: "Revisiting PQ WireGuard … Using Reinforced KEMs", IEEE S&P 2026
  (https://eprint.iacr.org/2025/1758), and a preprint on certificate-based PSK provisioning for
  WireGuard via mTLS/DTLS/QUIC (https://eprint.iacr.org/2026/2480). I did not read either in depth.
- The man page says: "This is a research project … If you are not specifically tasked with developing
  post-quantum secure systems, you probably do not need this tool" (`doc/rosenpass.1 @ v0.2.3`).

**License.** `MIT OR Apache-2.0` (`rosenpass/Cargo.toml:6 @ v0.2.3`).

**Packaging.** Not in Debian: `https://sources.debian.org/api/src/rosenpass/` returns 404. Repology
lists Arch, Alpine edge, FreeBSD, NixOS, ALT, crates.io and no Debian or Ubuntu
(https://repology.org/project/rosenpass/versions). On Debian trixie it means a static tarball, the OCI image, or
`cargo install` (crates.io 0.2.3). WireGuard itself is in-kernel on trixie (linux 6.12.x) with
`wireguard` tools 1.0.20210914 (sources.debian.org API, queried 2026-11-25).

**Operational model.**
- **One `rosenpass` process per host**, not per pair. A config has one keypair, one `listen` UDP
  address, and one `[[peers]]` entry per remote host, each naming the WireGuard `device` and `peer`
  (`main:config-examples/peer-a-config.toml`). The `rp` frontend allocates UDP port N for Rosenpass and N+1
  for WireGuard (`readme.md:39`), runs as root and handles exactly one interface (`readme.md:34-35`).
- Public keys (0.5 MB each) travel out of band. The handshake carries only ciphertexts. All messages
  fit in one IPv6 frame (`whitepaper.md:95,111`).
- systemd: units `rosenpass@.service` and `rp@.service` exist on **`main` only** (added/edited
  2026-10-22). They use `DynamicUser=true`, `AmbientCapabilities=CAP_NET_ADMIN`, `LoadCredential=pqsk:…`,
  `LimitMEMLOCK=infinity`, heavy sandboxing, and **no `Restart=`** line (`main:systemd/rosenpass@.service`).
  The template is `BindsTo=sys-devices-virtual-net-%i.device`: one unit per WireGuard interface. v0.2.3
  has no `systemd/` directory.

**Failure behaviour (from the code, untested).**
- Timers: rekey at 120 s (responder) or 130 s (initiator), reject at 180 s (`rosenpass/src/protocol.rs:106-110`).
- If no exchange succeeds before the key expires, the running daemon fires `DeleteKey` and writes a
  **random** PSK into WireGuard: `self.output_key(peer, Stale, &SymKey::random())`
  (`app_server.rs:539-540`), logged as "Erasing outdated key from peer" (`:601`). The two sides then
  hold different PSKs, so WireGuard's next handshake fails and the tunnel drops. That fails closed.
- If the **process dies**, nothing erases the key. WireGuard keeps the last PSK and keeps rekeying
  X25519 sessions with it, so the tunnel stays up. It remains PQ against HNDL, because that PSK
  came from a PQ exchange, but it loses rotation. Inference: the erase lives only in the running loop. If
  only one side dies, the surviving side randomises its PSK after about 180 s and the link drops.
- Before the first exchange the WireGuard peer has whatever PSK it was configured with. A plain
  `wg-quick` peer has none, so it carries **classical** traffic until Rosenpass first succeeds. A strict
  deployment should set a random per-side PSK at interface creation so that no traffic flows before
  Rosenpass succeeds. That is my recommendation; I have not verified whether `rp` does it.

**Scale.** It is pairwise. A full mesh of N hosts runs N(N-1)/2 exchanges every ~2 minutes, and each host
stores N-1 McEliece public keys.
- N=3: 3 pairs, about 1 MB of peer keys per host.
- N=10: 45 pairs, about 4.7 MB of peer keys per host.

Handshake traffic is a few KB per pair per 2 minutes. That is an estimate; I did not measure message sizes.
I found no documented peer limit (unverified).

## 3. Mesh managers today

| Option | PQ status (2026-11-25) | Self-hostable control plane | Sources |
|---|---|---|---|
| **NetBird** v0.83.2 (2026-11-20); v0.84.0-rc.1 | Rosenpass since v0.25.4, via `netbird up --enable-rosenpass`. **Strict is the default**: peers without Rosenpass can't connect. `--rosenpass-permissive` falls back to plain WireGuard without a PSK for those peers. It uses a Go reimplementation, `cunicu.li/go-rosenpass v0.5.42` (2025-10-16, Codeberg), built on a 2023 CIRCL fork for round-3 McEliece. **Deprecated in v0.82.0 (2026-10-29)**: "may be removed in a future release, so avoid making new deployments depend on it". The flags are hidden and print warnings. "An alternative solution is in the works". PR #8372 cites only an internal sync. | Yes: management/signal/relay are AGPLv3, the client is BSD-3 (`LICENSE @ v0.83.2`). The control channel encrypts with NaCl `box` (X25519) inside gRPC/TLS (`encryption/encryption.go:7,18-36 @ v0.83.2`). | https://docs.netbird.io/how-to/enable-post-quantum-cryptography; https://github.com/netbirdio/netbird/releases/tag/v0.82.0; https://github.com/netbirdio/netbird/pull/8372; `go.mod:10 @ v0.83.2`; https://proxy.golang.org/cunicu.li/go-rosenpass/@v/v0.5.42.mod |
| **Tailscale** v1.104.7 (2026-11-12) | Data plane: **hybrid handshake merged, unreleased**. tailscale/wireguard-go PR #98 (merged 2026-10-15) adds `"Noise_IKhfs+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s"` with Go `crypto/mlkem`, "hybrid forward secrecy, protecting past traffic from a future quantum computer" (`device/noise-protocol.go:9,52-53,325 @ 9d8961514`). tailscale PR #22204 (merged 2026-11-17) turns it on per peer when `peer.Cap() >= 152 && !peer.HasCap(DisableHybridHandshakes)` (`ipn/ipnlocal/node_backend.go:299-300 @ ee54083f3`). It is on by default and control can switch it off. It falls back to classical with older peers (PR comments). v1.104.7 is still capver 148 (`tailcfg/tailcfg.go:200 @ v1.104.7`). Control plane: ts2021 is "Noise IK, instantiated with Curve25519" (`control/controlbase/conn.go:7-8 @ v1.104.7`), classical, inside TLS for `/key`. Its TLS is hybrid again since the leaked `tlsmlkem=0` was removed (issue #20067, closed 2026-08-11). | Coordination server is SaaS, or Headscale (below). | https://github.com/tailscale/wireguard-go/pull/98; https://github.com/tailscale/tailscale/pull/22204; https://github.com/tailscale/tailscale/issues/20067 |
| **Headscale** v0.29.7 (2026-10-30) | No PQ of its own. Its maintainer says it is "bound to the protocols used by the Tailscale client" (issue #2317). PR #3724 (merged 2026-11-20, after v0.29.7) sends each peer its own capability version, because old peers "never answer" hybrid handshakes otherwise. So hybrid works through Headscale only from the release after v0.29.7 (unverified). Control-plane Noise is the same X25519 ts2021. | Yes (BSD-3). | https://github.com/juanfont/headscale/issues/2317; https://github.com/juanfont/headscale/pull/3724 |
| **Netmaker** v1.8.0 (2026-11-17) | None found. Issue "Use rosenpass to support post quantum encryption" has been open since 2023-11-09 (#2666). Code search found `PresharedKey` only in `swagger.yaml`. | CE is Apache-2.0 except `pro/` (`LICENSE.md @ v1.8.0`). | https://github.com/gravitl/netmaker/issues/2666 |
| **innernet** v2.0.0 (2026-07-02) | None found. Code search finds PSK fields only in its `wireguard-control` library. Its README says it "has not received an independent security audit, and should be considered experimental". Its server API runs over WireGuard itself (`README.md:14,58 @ v2.0.0`). | Yes (MIT). | https://github.com/tonarino/innernet |
| **Nebula** v1.12.0 (2026-10-29) | Not WireGuard. A Noise variant on Curve25519/P-256 with its own certificates. **No PQ in a release**: v1.12.0 notes don't mention it. Draft PR #1974 by a collaborator (opened 2026-10-19) adds v3 certificates with ML-KEM-1024/ML-DSA-87 and an `ix_hybrid_mlkem1024` handshake. CNSA 2.0 variants are #2001 and #2002, both open. | Yes (MIT). No control plane, only lighthouses plus an offline CA. | https://github.com/slackhq/nebula/pull/1974; https://github.com/slackhq/nebula/issues/1446 |
| **Plain `wg` + `wg-quick` + Rosenpass** | PQ via the Rosenpass PSK (§2). It is Kyber-512 round 3 until Rosenpass ships protocol v3. A simpler variant uses a static per-pair PSK provisioned over a PQ channel (§1). | Nothing to host. Config is hand-made or generated. | §1, §2 |
| **Cilium** v1.20.5 (2026-11-17) | WireGuard mode: each node makes its own keypair and publishes the public key in the `network.cilium.io/wg-pub-key` annotation. The docs mention no PSK and no PQ. CFP #41622 (Rosenpass) was closed by the stale bot as not planned (2025-12-09). IPsec mode uses a **pre-shared symmetric key from a Kubernetes Secret**. Per-tunnel keys are derived from it (`+`), with no IKE. Rotation means patching the Secret. With no public-key exchange on the wire, it resists HNDL if the Secret's path (API server TLS, etcd) is safe. It has no forward secrecy. | Kubernetes only. Ky's Docker-only products (KyPost, KyDrive, KyDNS, KyMessages) can't use it. | https://docs.cilium.io/en/stable/security/network/encryption-wireguard/; https://docs.cilium.io/en/stable/security/network/encryption-ipsec/; https://github.com/cilium/cilium/issues/41622 |

## 4. Without WireGuard: hybrid mTLS everywhere

What already works:
- Go `crypto/tls` enables X25519MLKEM768 by default (`tlsmlkem=0` turns it off). SecP256r1MLKEM768 and
  SecP384r1MLKEM1024 are also on by default (`tlssecpmlkem`).
- Preference order is X25519MLKEM768 first (`src/crypto/tls/defaults.go:16-42 @ go1.27.4`,
  https://github.com/golang/go/blob/go1.27.4/src/crypto/tls/defaults.go).
- Every Go↔Go link (edge→replica if the edge is Go, Ky↔Ky mTLS, Go apps→KyIdentity, Go→S3 if the server
  supports it) is hybrid with no work. The plan already wants tests and hybrid-only `CurvePreferences`
  for Ky↔Ky links (plan Q9, `:296-297`).

What it does **not** cover, or covers only with work:
- **PostgreSQL server side.**
  - PG17's `ssl_ecdh_curve` takes one curve, default `prime256v1` (https://www.postgresql.org/docs/17/runtime-config-connection.html).
    The code passes it to `OBJ_sn2nid` and `SSL_CTX_set_tmp_ecdh`, so a hybrid group can't be set
    (`postgres:src/backend/libpq/be-secure-openssl.c:1413-1438 @ REL_17_STABLE b0000574e4`).
  - PG18's `ssl_groups` takes a colon list, default `X25519:prime256v1`, and goes to
    `SSL_CTX_set1_groups_list` (`:1425-1428 @ REL_18_STABLE d4a8ff2a20`,
    https://www.postgresql.org/docs/18/runtime-config-connection.html).
  - That needs OpenSSL ≥ 3.5. OpenSSL 3.5.0 added X25519MLKEM768 and made it a default keyshare
    (https://github.com/openssl/openssl/blob/openssl-3.5.0/NEWS.md). Debian trixie ships OpenSSL
    3.5.9 and only postgresql-17 (17.12) (sources.debian.org).
  - So hybrid PG on trixie needs PG18 from PGDG or an image with OpenSSL ≥3.5 (unverified which).
  - This covers both client links and streaming replication, because both use the server's TLS config.
- **PgBouncer** (trixie 1.24.1). `*_tls_ecdhcurve` accepts `none`, `auto` or one curve name
  (https://www.pgbouncer.org/config.html). `auto` calls `SSL_CTX_set_ecdh_auto`, and a named curve
  goes to `SSL_CTX_set_tmp_ecdh` (`pgbouncer:lib/usual/tls/tls_server.c:121-131`, `tls_config.c:342-356 @ master 23347f670c`).
  With `auto` on OpenSSL 3.5 the library's default groups, including X25519MLKEM768, probably apply.
  That's an inference, untested. A named curve forces classical.
- **HAProxy/nginx/other OpenSSL daemons** (trixie haproxy 3.0.11): hybrid only with OpenSSL ≥3.5 and
  default or explicit groups. The plan already lists the nginx edge (plan row W0). HAProxy defaults are unverified.
- **Object storage.** The S3 provider's TLS endpoint decides. Hetzner Object Storage PQ support is unverified.
- **SSH admin.** Covered if both ends are new enough. OpenSSH 10.0 uses `mlkem768x25519-sha256` "by default
  for key agreement" (https://www.openssh.com/txt/release-10.0), and trixie ships 10.0p1. Go
  x/crypto/ssh puts it first (plan row 10).
- **Metrics/logs.** Prometheus and exporters are Go, so hybrid when TLS is on. Plain-HTTP scrapes are not covered at all.
- **Non-Go, non-TLS or UDP things.** DNS between hosts, NTP, anything an operator adds later.
- **Metadata.** Ports, peers and traffic shape stay visible on the Hetzner network, which is
  "not automatically encrypted" (§Ky context).

What WireGuard adds:
- One encrypted L3 layer for every protocol, including the PG, PgBouncer and HAProxy gaps above, without per-daemon OpenSSL work.
- Internal ports listen only on `wg0`. Each host's public firewall then becomes "UDP 51820 (+ Rosenpass
  port) from the cell's hosts, 443 from the edge". That matters because Hetzner Cloud Firewalls can't filter
  private Networks.
- Identity by host key. It does **not** replace mTLS: app-level authentication (pins, `verify-full`)
  should stay. And it is only PQ with a PSK scheme (§1, §2) or Tailscale-style hybrid handshakes (§3).

## 5. Recommendation sketch for Ky

Scale: 3-10 hosts per cell, a few cells, no L3 between cells (§Ky context). That is 3-45 links per cell. Any
option below fits; the difference is operations and trust.

| Option | PQ property | Ops cost | Verdict |
|---|---|---|---|
| **A. Hybrid mTLS only** (plan Q10 (a)) | HNDL-safe on Go links. PG needs PG18 + OpenSSL ≥3.5; PgBouncer and HAProxy depend on OpenSSL defaults | No new component. Gaps closed per daemon | **Baseline, do it regardless.** |
| **B. Kernel WireGuard + static per-pair PSK** | HNDL-safe (§1). No PQ forward secrecy between rotations. Authentication X25519 | Generate 32-byte PSKs, push them over SSH (`mlkem768x25519`), rotate on a schedule, for example monthly or on host change. Uses only Debian packages | **Simplest PQ mesh if one is wanted.** |
| **C. Kernel WireGuard + Rosenpass, strict** | HNDL-safe with 2-minute PSK rotation and forward secrecy | One daemon and one UDP port per host. 0.5 MB public keys distributed out of band. Not in Debian. v0.2.3 is Kyber round 3, ML-KEM unreleased. Needs a random initial PSK for strict mode, and `Restart=` plus monitoring | Use after Rosenpass ships protocol v3 (ML-KEM) in a release, or accept Kyber-512 r3 now. |
| **D. Headscale + Tailscale clients, hybrid handshakes** | ML-KEM-768 hybrid forward secrecy per handshake. Classical (X25519 Noise) control plane | Run Headscale yourself. NAT traversal and ACLs included | Watch. Re-check when a stable Tailscale (capver ≥152) and a Headscale release with PR #3724 ship. |
| NetBird + Rosenpass strict | As C, on a Go reimplementation | Self-hosted AGPL control plane | **Don't use: deprecated upstream (v0.82.0).** |
| Nebula, Netmaker, innernet, Cilium WireGuard | Classical today. Cilium IPsec PSK is Kubernetes-only | — | No. |

Recommendation: **A now. If the owner wants a mesh for firewalling and defence in depth, use B**, kernel
WireGuard on the cell's Hetzner private Network or public IPs with per-pair PSKs. Move to C once Rosenpass
releases ML-KEM, or to D once Tailscale hybrid handshakes are stable. Plain WireGuard without a PSK (plan
option (c)) is not acceptable for PQ.

Owner decisions:
1. **Mesh or not.** A only, or A + B/C/D. A mesh is defence in depth; it doesn't replace A.
2. **Strict vs permissive.** In strict mode a link with no PQ secret carries nothing. Rosenpass then needs
   a random initial PSK, and Tailscale-style hybrid must refuse classical peers. That costs availability
   when Rosenpass or a key is broken. In permissive mode the link falls back to classical WireGuard, and
   harvested traffic from that window is exposed. Recommendation: strict inside a cell. Every host is ours.
3. **Who runs the control plane and config.** KyQuickStart is frozen against new orchestration features
   (`KyQuickStart:AGENTS.md:683-686`). So the choice is an exception to the freeze, a private infra repo
   or script, or a self-hosted Headscale/NetBird server (which is itself a PQ-relevant, classical-Noise
   service to protect).
4. **Enrolment and rotation.**
   - How a new host gets its WireGuard key and peers. For C that includes a 0.5 MB McEliece key.
   - For B, the PSK rotation interval.
   - Re-keying when a host is retired or compromised: every pair that host shared.
   - Keys never leave the cell (cells never merge, C4).
5. **Monitoring.**
   - Alert when a peer's `wg show <if> latest-handshakes` is older than about 180 s (Reject-After-Time).
   - For C, alert on Rosenpass "Erasing outdated key" logs (`app_server.rs:601`) and on the unit not
     running. The upstream unit has no `Restart=`, and a dead daemon leaves a stale but working PSK.
   - Alert on any peer whose PSK is unset.
6. **Scope.** Whether operator SSH and metrics ride the mesh only, closing public SSH, and whether
   KyRecovery and object storage stay outside it. They are third-party or other-zone endpoints, reached over TLS.

## Gaps / unverified

- Rosenpass: which version the 2024 ROS pentest covered; whether a CryptoVerif proof has been published
  since 2023; the exact on-wire message sizes; any peer limit; whether `rp` sets a random initial PSK; and
  whether 0.3.0, with protocol v3 and ML-KEM-512, has a release date.
- NetBird's Rosenpass failure behaviour and the "alternative solution in the works" (not public).
- Tailscale: whether an unstable or odd-minor build already ships capver 152. Whether the hybrid handshake
  covers peers reached via DERP: I'd expect so, because the WireGuard handshake is end to end, but that's unverified.
- Headscale: which release first includes PR #3724.
- Whether PgBouncer `auto` on OpenSSL 3.5 actually negotiates X25519MLKEM768 (untested inference). HAProxy 3.0 default groups.
- Which PG18 image or packaging Ky's hosted cells would use, and its OpenSSL version.
- Hetzner Object Storage TLS groups. Whether Hetzner Cloud Networks span locations used by one cell.
- Nebula PR #1974's design document (`docs/pq-handshake.md`) was not read.
- The academic papers eprint 2025/1758 and 2026/2480 were identified only, not reviewed.
- Nothing here was built or run. Every behaviour claim about failure modes comes from reading code.
