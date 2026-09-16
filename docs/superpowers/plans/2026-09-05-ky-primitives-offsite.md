**Repo:** ky-primitives

# ky-primitives/offsite implementation plan

Source: myslop folder `ky-primitives-offsite`, posts 233 and 236.

## Goal

Publish `github.com/Busnes-app/ky-primitives/offsite` as a nested Go module
providing S3, pinned SFTP, signed SMB 2/3, and local `Target` implementations.
Products retain target persistence, credential sealing, scheduling, logging,
and the choice of bytes to replicate.

## Library work

- [x] Isolate transport dependencies in `offsite/go.mod` and teach the root
  dependency guard to skip nested modules.
- [x] Define `Target`, `Config`, `Parse`, credential-free `Key`, strict URL
  parsing, and traversal-safe relative object names.
- [x] Add atomic owner-only local writes, reads, missing-object mapping, and a
  writable-target probe.
- [x] Lift stdlib SigV4 S3 PUT, add signed GET, bound error bodies, refuse HTTP
  redirects, and test through an in-process HTTP server.
- [x] Lift SFTP PUT and its pinned-host/PEM authentication rules, add GET and
  session cleanup, and test through an in-process SFTP server.
- [x] Lift SMB 2/3 with required signing, endpoint parsing, PUT/GET and session
  cleanup. Keep live round-trip coverage opt-in through `KY_OFFSITE_SMB_TEST`.
- [x] Add root and nested-module CI, race tests, vet, formatting, vulnerability
  scanning, usage docs, and the SMB guest-session warning.

## Release and consumers

- [ ] Review and merge the ky-primitives PR, then create tag `offsite/v0.1.0`.
- [ ] Migrate KyRecovery first without changing its target table or stored
  endpoint fields; prove one live dashboard sync.
- [ ] Adopt the tagged module from KyNotes for attachment mirroring.
- [ ] Design KyPost mail-body mirroring separately and reuse only `Target`.

Consumer migrations stay in separate repositories and PRs because they depend
on the nested-module release tag.
