## Purpose

Standard-library-only S3-compatible object/version transport for hosted product adapters.

## Ownership

Own signed HTTPS requests, bounded page decoding, typed failures and explicit version/prefix
erasure. Products own authorization, org/key namespaces, sealing, caches, quota ledgers,
writer fences and provider replica/retention policy. `docs/S3.md` is the public contract.

## Local Contracts

- Preserve opaque keys/version IDs and both version-list markers; URL-decode only keys
  when the response declares URL encoding. Validate a whole page before returning it.
- A supplied zero-length PUT reader must prove empty before any request; never silently
  discard it and replace an object. PUT streams a declared length over verified HTTPS, without spooling or replay. GET explicitly requests identity encoding to preserve stored gzip bytes and sizes. Read
  streams sanitize errors. Signed requests follow no redirect, even with a supplied client.
- Errors contain locally selected operation/status data; credentials, provider messages,
  headers, URLs, keys and underlying transport errors stay out of error strings.
- Exact erasure always names a nonempty version ID, delete markers included. Prefix
  erasure requires a nonempty slash-terminated namespace. Callers fence writes first.
  Restart listing after each deletion batch; deleting a cursor can invalidate pagination.
- Retry only bodyless reads/listings and exact-version deletes, with bounded/context-aware
  backoff. Normal DELETE can add a marker; PUT replay can add a retained version.

## Work Guidance

Keep the root dependency budget. Reuse the SigV4 design and independent compatibility
fixtures; do not add a private per-product client or product storage policy here.

## Verification

`go test -race -count=1 ./s3`, again with `GODEBUG=fips140=on`. The optional
`TestS3VersionedIntegration` uses `KY_TEST_S3_*` against a disposable loopback server through
a verified TLS proxy; CI supplies the pinned signature-checking/versioned fixture. It
checks 1,001 versions, markers, exact/prefix purge and wrong credentials. Root CI owns the
full-module build, vet, race/FIPS, vulnerability and REUSE checks.

## Child DOX Index

None.
