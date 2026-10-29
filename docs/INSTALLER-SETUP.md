# Container-local installer setup

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

## Container-local installer setup

`applysetup` provides strict private-file bundle decoding, file-referenced credentials,
common SSO/identity/backup inputs, capability discovery and bounded report shapes.
`keyfile.ReadPrivate` reads opaque private files through the same verified descriptor as
key loading. Products retain their own transactions, audited grants, conflict handling,
configuration activation and read-only checks; this package never changes a product.
A callback can return `&applysetup.Refusal{Reason: "fixed safe explanation"}` to
show an actionable reason in `CallLocal` CLI errors. Reasons must be fixed safe text,
at most 512 bytes without controls; ordinary errors remain redacted. Never expose
credentials, input values or database errors this way.

Products may opt into `ParsePreparation` to accept `--stage` with bounded secret-free
stdin metadata; legacy `Parse` refuses that flag. Strictly decode and validate the
product envelope (including extensions), use `Common.ValidatePreparation` for common
metadata and distinct clean absolute credential references, then marshal canonical JSON
before `Stage`. The Linux helper publishes only
`<data>/installer/<setup UUID>/setup.json` through protected ancestry and private owned
directories, atomically without replacing retained files. Check creates nothing;
changed or unsafe input is refused. Other platforms refuse staging. `WritePreparation`
emits a fixed `ky.setup-preparation/1` created/present receipt, describing metadata only.
Credentials, accounts and product configuration remain separate native operations.
