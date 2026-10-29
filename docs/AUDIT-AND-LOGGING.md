# Audit chain, logging and health

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

## auditchain

Builds and verifies a tamper-evident hash chain over audit records.

Three implementations existed, with three tuple layouts and three key policies:

| | `kypassword-server` | `kybookmarks-server` | `kyrecovery-server` |
|---|---|---|---|
| Key | generated, ≥32 bytes enforced | **a literal survives on the verify/convert path; the write path has no fallback** | HKDF from the keyring |
| Truncation | anchor beside the key | undetectable | sequence numbers in the DB |
| Fields | joined on bare `\|` | joined on bare `\|` | details pre-hashed |

`kybookmarks-server/internal/audit/audit.go:50` keeps a literal,
`"kybookmarks-default-hmac-secret"`, and its write path no longer reaches it —
`loadOrCreateKey` has no constant fallback. What survives is narrower: the literal is what
`legacyHash` verifies v0 entries against, so it can still *recognise* a log an attacker
authored under it. It can no longer launder one. `converge` re-mints under the real key
only when the high-water mark attests to that exact log — same record count and same tail
hash — so a forged log is either refused by the mark or left in the old format for
`Resume`'s digest check to reject. Only a genuine first boot, with no mark at all and every
entry `v: 0`, converts. The key floor is 32 bytes, and on the write path — the one that
mints and checks new records — there is no fallback at all.

Every field is length-prefixed. Joining on a delimiter lets a field containing it shift
into its neighbour and produce another record's digest, forging a record without the key;
`TestFieldsAreUnambiguousAcrossDelimiters` pins that.

Persistence is a parameter of `Append`, not the caller's next statement. The chain's
in-memory head is a claim about what is on disk: advancing it first meant a failed insert
left the next record chained onto one that never existed, and a record stored without its
anchor left the opposite inconsistency, with no way to roll back either. `persist` runs
under the lock that reserves the sequence number, and the chain advances only if it
returns nil.

`Verify` requires the `Anchor` — a count and head hash kept outside the log. Hashes alone
cannot catch a log with records removed from the end, because what remains still chains
correctly, so the anchor is a parameter rather than an option.

`Resume` requires it too. A valid digest does not make a record the tail — every record in
a healthy chain carries one — so resuming from the middle was accepted and the next append
minted a sequence number that already existed. The anchor is the only thing that knows
where the end is. Sequence 0 and `MaxUint64` are refused: `Append` starts at one, and
minting `count+1` from the top wraps to zero.

`Append` takes a `context.Context`, which bounds the wait for the chain lock, not
`persist`. `persist` still runs under the lock — the record and its anchor have to be written together — so give it its own
timeout, and do not call back into the `Chain` from it: the lock is not reentrant, and the
anchor it would ask for is already one of its arguments.

```go
chain, err := auditchain.New(key)          // or Resume(key, lastRecord, anchor)
rec, err := chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
    return store.WriteRecordAndAnchor(r, a) // one transaction
}, "login", user)
err = auditchain.Verify(key, records, anchor)
err = auditchain.VerifyStream(key, rows, anchor) // same, for a log too large to hold
```

`VerifyRecord` asks whether a record carries its own digest, and nothing about where it
sits. It also refuses a record numbered zero or carrying a malformed hash, because `Append`
mints neither — a legacy log numbered from zero is exactly what a migration probe hands it.
`Resume` answers a different question — is this the tail — and needs the anchor to do
it. A conversion probe wants the first.

`Replay` builds a chain in memory from field tuples and hands back the records with their
final anchor, for a bulk rewrite that writes the log once. `Append`'s persist parameter
means the chain advances only when the store agrees; passing one that does nothing per
record would satisfy the signature and mean the opposite.

Errors worth an `errors.Is` in a caller: `ErrWeakKey`, `ErrBrokenChain`.

Chains in this suite reach six figures, and the bug that follows from paging them is
specific: `kyrecovery-server`'s `VerifyChain` read a fixed 100000 events and then reported a
sequence gap on a perfectly healthy chain. `VerifyStream` removes the reason to page. A
record yielded with a non-nil error fails the verification rather than ending the walk, so a
store that dies mid-read cannot look like a short chain.

`Anchor` is `{Count, Hash}`, which is exactly `kypassword-server`'s `audit.state` and
`kyrecovery-server`'s `ledger.head`. KyPassword has migrated onto this package. It needed no
version field: its legacy format was a *single* keyed HMAC digest, so `converge` verifies
every entry under that digest and re-mints the whole log under `auditchain`'s in one atomic
rewrite, leaving nothing to distinguish afterwards. The unkeyed variant that preceded it was
deleted rather than carried, because a chain under no secret is one anyone who can write the
log can recompute end to end.

`kybookmarks-server` is the one with two legacy versions, `v: 0` and `v: 1`, and it converts
the same way: a log is re-minted only when it verifies whole under one of them *and* the
mark outside the log attests to it.

`Fields` are opaque and storage is not this package's business. The three implementations
logged different things and wrote to JSON lines, a file and a database; forcing one schema
on them is what made them diverge, and where the bytes went was never the part that broke.

## logging

Emits JSON lines on stderr. A collector agent ships them; this package opens no socket,
holds no buffer and rotates no file, because an agent survives the process dying and a
library buffer does not.

The suite ran five logging architectures across nine servers. Seven of them shipped a
`LOGGING.md` promising structured, privacy-safe output and one delivered it. Redaction
existed in two products with opposite strategies: kynotes dropped anything outside a
21-key allowlist, kypost redacted values whose key *name* looked sensitive — a denylist,
which fails silently on a key nobody thought of, and which seventeen of its own call sites
bypassed anyway.

Three things here are why it is in this library rather than fixed per product.

A field value cannot forge a line. Control characters become U+FFFD on the value, before
any renderer sees it, and values cap at 256 bytes. Six products passed values into
`log.Printf` unescaped and one passed a free-form `map[string]any` into `json.Marshal`; a
newline in any of them writes a log line of the attacker's choosing, and a forged line is
indistinguishable from a real one.

A key must be declared. There is no `Field(name, value)`, and values are `string`,
`int64`, `bool` or `time.Time` rather than `any`, so a struct holding a token cannot be
logged whole.

An event has one name. Four products spelled the same audit event four ways — `user_id`
against `actor` against `actorId`, and one with positional arguments and no names at all.

```go
lg, err := logging.New(logging.Config{App: "kypassword", Out: os.Stderr})
lg.Security(ctx, logging.AuthFailed, logging.UserID(id), logging.RemoteIP(ip))
if err := lg.Audit(ctx, logging.ShareRedeemed, rec, logging.UserID(id)); err != nil {
	// The shipped copy did not land; the local chained file still has it.
}
```

`lg.Handler()` is a `slog.Handler` for products mid-migration. Install it with
`slog.SetDefault` and existing call sites keep working; attributes outside the vocabulary
are dropped and counted into `dropped_fields`, so what is lost shows on the line. A
declared key does not save an arbitrary value: `slog.Any("user_id", someStruct)` drops
even though `user_id` is declared, because a struct or a map is `KindAny` or `KindGroup`,
and a declared name vouches for the key, not for whatever Go value showed up under it —
that is the first thing a migrating call site hits.

Audit lines are flat and carry `seq`, `prev`, `hash` and `fields` at the top level, so
`cmd/kyauditverify` needs no code change to verify them — provided the export handed to it
is filtered to the lines that carry `hash` first. An ordinary `Log` or `Security` line has
none of those four keys; it decodes into a zero `auditchain.Record` with no JSON error, and
`VerifyStream` reports that as a broken chain, not as a line outside its scope. `Audit`
recomputes the flat keys from the fields it is given and checks them against the record's
own `Fields`; a disagreement is caught at emission, not assumed away by construction, and
costs the flat keys — replaced with an `audit_fields_mismatch` marker — while the record
itself, the part that is authenticated, ships regardless. The product keeps its own local
chained file: a tamper-evident chain that exists only on a machine the attacker may also
own is not evidence.

There is no syslog renderer. `log/syslog` is frozen, absent on Windows and Plan 9, and
broken on macOS 12 and later. Writing RFC 5424 to stderr instead would double-frame the
line, because the collector already supplies a frame — so severity and facility are
ordinary JSON fields and the frame is the agent's job.

## health

Serves `/healthz` in the suite's one shape, `ky.health/1`, which kyPulse reads. It is here
rather than fixed per product because the shape is a wire contract: before it, the suite's
health routes disagreed on path, field names, status codes and even content type, so a
monitor needed an adapter per product.

```go
var appendDisabled = health.DeclareReason("append_disabled")

mux.Handle("GET /healthz", health.Handler("kyvault", lg,
	health.Check{Name: "database", Run: db.PingContext},
	health.Check{Name: "audit", Run: func(ctx context.Context) error {
		if auditor.Disabled() {
			return health.Degrade(appendDisabled)
		}
		return nil
	}},
))
```

```json
{"schema":"ky.health/1","service":"kyvault","status":"degraded","time":"2026-09-26T10:41:00Z",
 "checks":[{"name":"database","status":"ok"},{"name":"audit","status":"degraded","reason":"append_disabled"}]}
```

The route is public, so the response is built to be safe to show anyone.

- **No error text.** A check's error text never reaches the response: a DSN, a path or a
  hostname in `err.Error()` is the leak this prevents. An ordinary error is `down` with no
  reason. A check shows `degraded` or a reason only by returning `health.Degrade(r)` or
  `health.Fail(r)`, where `r` came from `DeclareReason`, which panics at startup on a code
  outside `[a-z0-9_]{1,64}`. The operator gets the rest on stderr: each non-ok check writes
  a `health_check_failed` line with the check name, reason and `logging.Err` error kind.
- **No version, build or uptime.** On a public route they fingerprint releases and reveal
  restart timing. A monitor gets the version from the container image.
- **Cached and shared.** One evaluation answers every request for `CacheFor` (5 s), and
  concurrent requests share it, so hammering the route cannot hammer the database. The
  evaluation uses its own context, so one client hanging up cannot cancel the result every
  other client sees.
- **Deadlines.** A check has `Timeout` (default 2 s) and must honour its context. A check
  past its deadline is `down` with reason `timeout`, and a check still running from the
  previous evaluation is not started again: it reports `timeout` until it returns. A
  panicking check is `down`.

The service status is the worst check status; no checks is `ok`. `ok` and `degraded`
return 200, `down` returns 503, so a readiness probe or a monitor that reads only the code
keeps working. Liveness should stay on a route that checks nothing: restarting the app does
not fix a dependency, so a liveness probe wired to `/healthz` would restart in a loop while
the dependency is down. `HEAD` returns the code with no body; other methods return 405.
`Response` and `CheckResult` are exported for monitors that decode the body.
