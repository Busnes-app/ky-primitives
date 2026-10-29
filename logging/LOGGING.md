# Logging policy

Every Ky product must emit JSON lines on stderr and nothing else. A collector agent ships
them to the central log server. No product may open a socket to ship logs, and no product
may write application logs to a file from inside the process. This package is what makes
the policy enforceable, not evidence that it is followed: migrating the nine products onto
it is separate work, and today none of them have. See the `## logging` section of [docs/AUDIT-AND-LOGGING.md](../docs/AUDIT-AND-LOGGING.md#logging)
for what they do instead.

## What may appear on a line

Only declared keys. The vocabulary lives in `logging/field.go`; a product adds its own
with `DeclareString` and friends at package level. A key that was never declared is
dropped and counted in `dropped_fields`.

Values are sanitized and capped at 256 bytes. Control characters become U+FFFD, which is
what makes it impossible for a field value to forge a line. The one place this does not
hold is an audit line's `fields`, `prev` and `hash`: those ship verbatim from the
`auditchain.Record`, because sanitizing them would change the bytes the chain's digest
covers.

## What must never be logged

Key material, share values, password hashes, session tokens, recovery codes, capsule
keys, and the plaintext of anything a user stored. The vocabulary is the enforcement: none
of these has a declared key, so there is no key a caller can pass one of these under by
name. That does not close every channel:

- **A right key with a wrong argument.** `logging.Action(sessionToken)` needs no `ErrText`
  and no new declaration — the vocabulary bounds which keys exist, not what a caller
  decides to pass as a value under one. A token well under the 256-byte cap ships whole.
- **`Err(err)`.** It unwraps to the deepest error, but a leaf built by `fmt.Errorf` with no
  `%w` carries whatever the caller put in it. `Err` is not `ErrText`, and grepping for
  `ErrText(` will not find it.
- **The free-text message on the `Handler()` path.** A product mid-migration installs
  `lg.Handler()` with `slog.SetDefault`; every raw `slog` call site's message is sanitized
  and capped, but shipped whole. This is the channel most likely to leak, because it is
  the one every pre-migration call site already has open.

## Levels

`KY_LOG_LEVEL` — `debug`, `info`, `warn` or `error`, case-insensitive; unset defaults to
`info`. Go's `slog.Level.UnmarshalText` also accepts a numeric offset such as `error-4`, so
that parses too. Anything else is a startup error, not a silent fallback.

`Audit` ignores this knob. A record dropped for verbosity leaves a gap in the chain that
central verification cannot tell apart from tampering, so every audit line ships
regardless of `KY_LOG_LEVEL`. `Log` and `Security` are the only calls it filters.

## Severity and facility

Every line carries an RFC 5424 `severity` and `facility`. Ordinary lines are facility 16
(`local0`); security and audit lines are facility 10 (`authpriv`), so a collector can
route the security stream to different retention without reading payloads.

## Audit records

Audit lines carry `seq`, `prev`, `hash` and `fields` at the top level, which is what
`cmd/kyauditverify` unmarshals. Pointing it at the collector's export to verify a chain
centrally needs no change to that command — but only once the export is filtered to the
lines carrying `hash`. An ordinary `Log` or `Security` line has none of those four keys; it
decodes into a zero `auditchain.Record` with no JSON error, and `VerifyStream` reports that
as a broken chain, not as a line outside its scope. `Audit` recomputes the flat keys from
the fields it is given and compares them against the record's own `Fields`; a disagreement
withholds the flat keys and sets `audit_fields_mismatch` instead of shipping a flat key
that contradicts what the record digested — the record itself, the part that is
authenticated, still ships either way. The product keeps writing its own local chained file
regardless: a chain that exists only on a machine the attacker may also own is not
evidence.
