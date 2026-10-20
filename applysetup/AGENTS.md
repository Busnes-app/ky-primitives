# Purpose

Container-local installer envelopes, strict bundle boundaries and credential references.

## Ownership

`setup.go` owns shared CLI flags, capabilities, typed common inputs and safe reports.
`local.go` owns bounded private Unix-socket transport and graceful activation requests.
`stage.go` and platform helpers own immutable secret-free metadata publication;
products supply strictly decoded, validated canonical envelopes and their data directory.
Products own configuration storage, ownership, conflict refusal, runtime activation,
identity grants, transactions, per-change audits and recovery-client wiring.

## Local Contracts

- Read bounded private files through `keyfile.ReadPrivate`; errors never echo JSON or secrets.
- Bundle credentials are target-side file references. Decode with unknown/trailing fields refused.
- Validate exact service, stable setup ID, HTTPS identity/recovery origins, callback path and
  distinct administrator/everyday identities before invoking product mutations.
- `--check` is a product obligation to inspect without writes; advertising it requires tests.
- Created/present/pending reports describe observed state. Pending cannot be counted as ready.
- Socket parents must be private and owned; never replace a live socket or an ordinary file.
- Shared bundle validation returns safe `Refusal` errors; products can opt in for their own fixed messages. Only explicit `Refusal` errors carry fixed public-safe reasons to the CLI (at most 512 bytes, no controls). Arbitrary callback errors stay redacted; never wrap secret-bearing errors as a refusal.
- Products supply the mutation and restart callbacks. No public HTTP setup route is exposed.
- Keep this package standard-library-only beyond imports inside ky-primitives.
- Preparation is explicit: `ParsePreparation` accepts `--stage`; legacy `Parse` refuses it.
  Products validate their extended fields before `Stage`; `ValidatePreparation` checks
  common metadata and distinct clean absolute credential references, without reading secrets.
- Linux staging writes only `<data>/installer/<setup UUID>/setup.json` with protected
  ancestry, private owned directories and no-clobber publication. Check creates nothing;
  changed/unsafe retained input is refused. Other platforms refuse staging.
- `ky.setup-preparation/1` reports metadata creation/presence only, never product readiness.
  Preparation creates no accounts, credentials or configuration.

## Work Guidance

Reuse this boundary rather than copying file/credential readers into product repositories.

## Verification

`go test -race ./applysetup ./keyfile` and root dependency-boundary tests.

## Child DOX Index
