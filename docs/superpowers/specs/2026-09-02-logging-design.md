# A shared logging package for the Busness.app suite

Design, 2026-09-02.

## Goal

One package in `ky-primitives` that every Go product logs through, so that a security
event carries the same name and the same fields in all nine, a secret cannot reach a log
line by accident, and a forged log line cannot be written by anyone who controls a field
value.

Output is JSON lines on stderr, collected by an agent and shipped to whatever central
server the operator runs. Audit records go to that stream *and* stay in each product's
existing local chained file.

## Non-goals

- **Opening sockets.** The library never dials, never spools, never rotates. A collector
  agent moves the bytes. See "Why no forwarder".
- **A Ky log server.** Off-the-shelf collectors already ingest JSON lines. The one thing
  they cannot do — verify an `auditchain` chain — is already `cmd/kyauditverify`.
- **RFC 5424 framing.** Deferred, not rejected. See "Why JSON only".
- **Migrating the nine products.** That is follow-on work sized with the suite migration
  phases; kysignon alone has 63 stdlib `log` calls and 54 audit calls.
- **Log rotation or file sinks.** kypost is the only product writing application logs to
  disk from inside the process, and every `LOGGING.md` in the suite tells operators not to
  build that.

## Decisions taken

| Decision | Consequence |
|---|---|
| JSON lines only, no RFC 5424 renderer | One escaping path, so one place injection can break. Syslog framing is ~60 lines added later if a syslog collector ever exists. |
| stderr only, never stdout, never a file | Ends the six-way disagreement in the fleet. Severity-split streams break ordering between a warning and the error it caused. |
| A collector agent ships; the library formats | No reconnect, TLS, spool or backpressure code to keep true. A crashed product still gets its last lines shipped. |
| Closed field vocabulary, declared in one place | A key that was never declared cannot be emitted. Replaces kypost's denylist, which fails silently on a key nobody thought of. |
| Values are typed and bounded, never `any` | You cannot log a whole request struct and find out later it held a token. |
| Audit lines are flat and carry `seq`/`prev`/`hash`/`fields` | `cmd/kyauditverify` parses them unchanged, once the export is filtered to lines carrying `hash`. |
| Audit storage stays with the product | `auditchain` "deliberately owns no storage" and this does not change that. |
| Both a typed API and a `slog.Handler` | kydns threads `*slog.Logger` through nine components; without a handler it could not adopt. |

## Measured current state

Surveyed 2026-09-02 across the nine Go server repos.

| Repo | Mechanism | Structured | Sink | Redaction | Level knob |
|---|---|---|---|---|---|
| gridlock-server | stdlib `log` | no | stderr | none | none |
| ky_server_base | stdlib `log` | no | stderr | none | none |
| kybookmarks-server | stdlib `log` + `internal/audit` on `auditchain` | audit only | stderr + file | none | none |
| kypassword-server | stdlib `log` + `internal/audit` on `auditchain` | audit only | stderr + file | none | none |
| kydns-server | `log/slog`, `slog.Default()`, never `SetDefault` | no (text) | stderr | query/IP logging opt-in | none |
| kynotes-server | `internal/logging` over slog | **yes, JSON** | stdout | **21-key allowlist** | `KYNOTES_LOG_LEVEL`, `KYNOTES_LOG_FORMAT` |
| kypost-server | `internal/logging` over slog + rotator | no (text) | stdout + file | key-substring denylist | `LogLevel` defined, read by nothing |
| kyrecovery-server | hand-rolled JSON in `internal/audit` | yes | stdout/stderr split | none | none |
| kysignon-server | stdlib `log` + hand-rolled JSON audit | audit only | stdout/stderr split | none | none |

Nothing anywhere uses syslog, journald directly, `/dev/log`, zerolog, zap or logrus.

## Why this clears the bar

The library's rule is that a primitive belongs here when divergence between the suite's
copies silently corrupts data or makes a wrong answer indistinguishable from a right one.
Rendering JSON does not meet that bar; it is per-product configuration, which the README
says to fix in place. Three things here do meet it.

**Log injection.** kysignon passes a free-form `details map[string]any` straight through
to `json.Marshal`; the six plain-text products pass values into `log.Printf` unescaped. A
field value containing a newline forges an entire log line. Forging log lines is how an
attacker hides in a trail, and a forged line is indistinguishable from a real one — the
bar, exactly.

**Silent redaction failure.** kypost redacts values whose *key name* contains `password`,
`token`, `secret` and eleven others. A denylist is a guess about what secrets get named,
and its failure is silent. Its own 17 direct `slog.Error` calls in `internal/state/store.go`
and `internal/config/config.go` bypass it entirely. kynotes drops anything outside a 21-key
allowlist — the right direction, and the only one in the fleet.

**Audit events that do not agree on their own names.** Four products emit audit records
with `user_id` / `actor` / `actorId` and `target_id` / `targetId`, and kybookmarks uses
positional arguments with no names at all. A security event that cannot be searched across
the suite is a security event nobody finds.

Every product but gridlock and ky_server_base ships a `LOGGING.md` promising "structured,
privacy-safe application logs to standard output and standard error". One product delivers
it.

## Why JSON only

The earlier draft of this design had both an RFC 5424 renderer and a JSON one. RFC 5424
on stderr is wrong in combination with the agent-based collection this design chose,
because the agent supplies the frame.

systemd's stderr handling parses a leading `<N>` priority prefix off each line. A full
RFC 5424 line has its `<134>` consumed as the priority, and the remainder — version,
timestamp, hostname, app-name, procid — is recorded as *message text*, duplicating the
`_HOSTNAME`, `_PID` and `SYSLOG_IDENTIFIER` journald already captured. Docker's json-file
driver does not parse the prefix at all, so the whole header becomes message text. Either
way the library hand-builds a header the transport re-derives.

*This framing behaviour is from documentation, not measured here. Confirm it against the
actual collector before it becomes load-bearing; it is the sole justification for dropping
the renderer, and the renderer is cheap to restore.*

Severity and facility survive as ordinary JSON fields, so collector-side routing does not
depend on the frame. rsyslog, syslog-ng, Vector, Fluent Bit, Loki and Elasticsearch all
ingest JSON lines natively.

The deciding argument is not convenience. Syslog structured-data escaping and JSON string
escaping are different rulesets. Injection resistance is the property this package exists
to provide, and two renderers means two places it can break, for a format no product in
the suite currently speaks.

## Why no forwarder

A forwarder inside the library would have to own reconnect, TLS trust, a spool file, spool
rotation and a backpressure policy, all under a stdlib-only budget.

The backpressure policy is the trap. If the central server hangs and the forwarder blocks,
every request path that logs hangs with it — the logging system becomes an availability
failure, which is a worse security outcome than losing log lines. Choosing "drop instead"
means silently losing audit evidence at exactly the moment something is wrong.

An agent is better at this than we would be, and it survives the process dying: a library
buffer is lost in a crash, which is when the logs matter most.

The case that would justify one is a consumer with no agent. There is none. The client
repos — `kypost-Linux`, `kypost-for-Mac`, `kypost-android`, `kyauth-android`, `KyData` —
are Qt, Gradle and JS, and cannot import a Go package.

What we do instead is free: shape the JSON so the standard endpoints ingest it with no
transform. `timestamp`, `level` and `message` at top level, every other field flat.

## Why no log server

Ingest, authentication, storage, retention, query and a UI is a whole product, competing
with Loki plus Grafana and with Graylog. A box holding every product's logs is also a
high-value target, and one built hastily is worse than not having it.

The one capability off-the-shelf cannot provide is chain verification, and it already
exists. `cmd/kyauditverify` reads `auditchain.Record` values one per JSON line, plus an
anchor, and verifies. If audit lines are shaped so that tool parses them, "central audit
verification" is the existing 111-line command pointed at the collector's export, filtered
first to the lines carrying `hash` — an ordinary log line has none of the four audit keys
and would otherwise read to `VerifyStream` as a broken chain, not as data outside the
tool's scope.

A tamper-evident chain nobody checks is decoration. This is the cheapest way to check it.

---

## The package

`github.com/Busnes-app/ky-primitives/logging`. Standard library only — `log/slog`,
`encoding/json`, `context`, `time`, `os`, `strings`. No `log/syslog`: it is frozen, absent
on Windows and Plan 9, and broken on macOS 12 and later since Apple's daemon stopped
listening on the Unix socket.

### Configuration

```go
type Config struct {
    App   string        // required; emitted as "app", identifies the product
    Level slog.Leveler  // default slog.LevelInfo when nil; a *slog.LevelVar works too
    Out   io.Writer     // default os.Stderr
}

func FromEnv() (Config, error)  // reads KY_LOG_LEVEL; App and Out still set by the caller
func New(Config) (*Logger, error)
func (*Logger) Handler() slog.Handler

func (*Logger) Log(ctx context.Context, ev Event, fs ...Field)
func (*Logger) Security(ctx context.Context, ev Event, fs ...Field)
func (*Logger) Audit(ctx context.Context, ev Event, rec auditchain.Record, fs ...Field)
```

`FromEnv` returns an error rather than falling back to a default, because a misspelled
`KY_LOG_LEVEL` that silently means `info` is how a product ends up logging nothing useful
during the incident it was set for.

`KY_LOG_LEVEL` is one name for all nine products, replacing kynotes' `KYNOTES_LOG_LEVEL`
and kypost's `LogLevel` config key that nothing reads. There is no format variable,
because there is one format. `New` fails on an empty `App` — an unattributed log line in a
central store is nearly useless.

The library reads no environment on its own. `FromEnv` is a helper the product calls, so
configuration stays explicit at the call site.

### Fields

`Field` is a struct with unexported members. The only values that exist are ones a
constructor produced, so there is no path for an arbitrary key or an arbitrary type.

```go
lg.Log(ctx, logging.Started, logging.Version(v))
lg.Security(ctx, logging.AuthFailed, logging.UserID(id), logging.RemoteIP(ip))
// logging.Field("argon2_hash", h)   ← no such function; does not compile
```

There is no caller-supplied message string anywhere in the typed API. `message` is a
constant carried by the event, and the level comes from the event too. A free-text message
parameter would be the one remaining channel for an accidental leak — `Log(ctx, AuthFailed,
fmt.Sprintf("user %s failed", email))` defeats every other guarantee in this package — and
carrying the text on the event also means the same event reads the same way in all nine
products.

Value types are `string`, `int64`, `bool` and `time.Time`. Not `any`, so a struct holding
a token cannot be logged whole.

The shared vocabulary starts from kynotes' 21 keys, which are the only field allowlist in
the fleet and were chosen against a real product:

`route`, `method`, `status`, `duration_ms`, `bytes`, `outcome`, `user_id`, `device_id`,
`container_id`, `object_id`, `attachment_id`, `upload_id`, `session_id`, `audit_id`,
`count`, `reason_code`, `retry_after_s`, `version`, `error_kind`

plus `error_text`, and from what the other eight products log today: `remote_ip`,
`user_agent`, `action`, `target_id`, `actor_id`, `capsule_id`, `share_index`, `zone`,
`qname`.

Two of kynotes' keys are reserved here rather than declarable. `event` is set from the
event constant, and `request_id` is set from the context, so each has exactly one source
and cannot be contradicted by a field of the same name.

Products declare their own at package init, one function per value type so the returned
constructor is typed:

```go
var MessageID = logging.DeclareString("message_id")   // kypost
var QueryMS   = logging.DeclareInt("query_ms")        // kydns

// DeclareString(name string) func(string) Field
// DeclareInt(name string)    func(int64) Field
// DeclareBool(name string)   func(bool) Field
// DeclareTime(name string)   func(time.Time) Field
```

All four panic on a reserved key, on a name outside `[a-z][a-z0-9_]*`, or on a name already
declared. Panicking at init is the right failure: it happens at startup, in every
environment, before any line is written.

The guarantee is honest about its limit. It is "every key in the suite is declared in one
greppable place", not "no key is ever wrong" — `DeclareString("password")` would still work.
What it removes is the accidental leak, which is the one that actually happens.

**Reserved keys**, which the `Declare*` functions refuse: `timestamp`, `level`, `message`,
`app`, `event`, `request_id`, `severity`, `facility`, `dropped_fields`,
`truncated_fields`, and — because audit lines are flat — `seq`, `prev`, `hash`, `fields`,
`audit_fields_mismatch`. A declared field colliding with one of the four audit keys would
corrupt a chain record on its way through the log stream; colliding with
`audit_fields_mismatch` could claim a divergent line agrees after all.

The handler drops reserved keys arriving as raw slog attributes and sets them itself, so a
product mid-migration cannot contradict them. The four audit keys and `event` are stronger
than that: they travel as values of unexported types, which code outside this package
cannot construct. Raw slog cannot forge an audit record into the stream.

### Value sanitizing

Applied to every string value before it can reach a line:

- Control characters (`< 0x20`, `0x7f`, and the C1 range `0x80`-`0x9f`) are replaced with
  U+FFFD. This is what makes log injection impossible, and it is applied to the value, not
  to the line, so it cannot be skipped by a later renderer — nor by the fact that a JSON
  string encoder does not escape C1 on its own.
- Values cap at 256 bytes, truncated on a rune boundary with a trailing `…`, and the line
  carries a reserved `truncated_fields` count. The cap bounds the blast radius of any
  single field and keeps a line from growing without limit. The count is a number rather
  than a per-key marker because a marker would need a key outside the vocabulary, which is
  the rule this package exists to hold.
- JSON escaping is `encoding/json`'s, not ours.

### Errors

```go
func Err(error) Field        // emits error_kind: the sentinel or concrete type name
func ErrText(error) Field    // emits error_text: sanitized and capped
```

`Err` deliberately drops the message. Error strings are the most common accidental leak in
a log — wrapped filesystem paths, query text, occasionally a token in a URL. `ErrText`
exists for when the message is needed and the caller has decided it is safe; it greps.

### Two APIs

kydns threads `*slog.Logger` through nine components and has roughly 89 free-form call
sites. A vocabulary reachable only through new function calls would lock it out.

`Logger.Handler()` returns a real `slog.Handler`. A product installs it with
`slog.SetDefault` and adopts in one line. Attributes outside the vocabulary are **dropped
at runtime and counted** into a `dropped_fields` integer on the line, so the loss is
visible rather than silent — kynotes' behaviour, which is the right one.

So: compile-time enforcement where code uses the typed API, visible runtime enforcement
where it uses raw slog. New code and migrated call sites get the strong version; a product
mid-migration is never worse off than it is today.

### Request context

```go
func WithRequestID(ctx context.Context, id string) context.Context
```

The logger reads it and emits `request_id` on every line. kynotes is the only product with
request correlation today; it mints an ID when the header is absent and accepts
`X-Request-Id` only from trusted proxies. This package carries the ID; deciding whether an
inbound header is trusted stays with the product's HTTP layer, which is where the proxy
configuration lives.

### Events and severity

An event is a declared value, not a string. It carries its name, its human-readable
message and its level, so all three agree across the suite and none of them is
caller-supplied. This is what makes a security event searchable everywhere.

Starter set, grounded in what the nine products log today: `started`, `stopped`,
`config_loaded`, `auth_succeeded`, `auth_failed`, `auth_locked`, `session_created`,
`session_revoked`, `mfa_challenged`, `mfa_failed`, `rate_limited`, `admin_action`,
`key_created`, `key_rotated`, `capsule_sealed`, `capsule_opened`, `capsule_open_failed`,
`share_issued`, `share_redeemed`, `recovery_code_redeemed`, `audit_chain_broken`.

Products add their own with `DeclareEvent(name, message string, lvl slog.Level) Event`,
which panics on a duplicate or malformed name for the same reason `Declare*` does.

`level` is the slog level as a word. `severity` is the RFC 5424 number derived from that
level — Debug 7, Info 6, Warn 4, Error 3 — so a collector routes on it without a mapping
table. `facility` is 16
(`local0`) for ordinary lines and 10 (`authpriv`) for security and audit events, so the
security stream can be routed to different retention without inspecting payloads.

### Audit bridge

The record and the log line carry the same values because they are built from the same
fields:

```go
fields := logging.AuditFields(logging.UserID(id), logging.Action("share_redeem"))
rec, err := chain.Append(ctx, persist, fields...)   // product owns chain and local file
lg.Audit(ctx, logging.ShareRedeemed, rec, logging.UserID(id), logging.Action("share_redeem"))
```

`AuditFields` renders declared fields as canonical `key=value` strings for `Chain.Append`,
which length-prefixes each one before digesting.

The emitted line is flat and carries `seq`, `prev`, `hash` and `fields` at top level
alongside the log line's own keys. `auditchain.Record` has exactly those four JSON tags,
and Go's decoder ignores unknown fields — so `cmd/kyauditverify` unmarshals the shipped log
line into a `Record` and verifies it with no change to that command.

The duplication between `fields` and the flat keys is deliberate: `fields` is what the
digest covers, the flat keys are what the collector indexes. A test asserts they agree.

Audit lines are shipped *and* the product keeps writing its existing local chained file. A
tamper-evident chain that exists only on a machine the attacker may also own is not
evidence.

---

## File structure

**Created:**

| File | Responsibility |
|---|---|
| `logging/logging.go` | `Config`, `FromEnv`, `New`, `Logger`, `Handler`, level and severity mapping |
| `logging/field.go` | `Field`, the shared vocabulary, `Declare`, reserved keys, sanitizing and caps |
| `logging/event.go` | `Event`, the starter event set, `DeclareEvent`, default severities |
| `logging/audit.go` | `AuditFields`, `Logger.Audit` |
| `logging/logging_test.go` | Config validation, level filtering, line shape, request ID |
| `logging/field_test.go` | Vocabulary, `Declare` refusals, sanitizing, truncation, dropped counting |
| `logging/audit_test.go` | Field agreement and the `kyauditverify` round-trip |
| `logging/fuzz_test.go` | Injection and line-count invariants |
| `logging/LOGGING.md` | The policy the seven scattered copies state, stated once |

**Modified:**

| File | Change |
|---|---|
| `README.md` | A `logging` section: what it guarantees, and that it opens no sockets |

## Testing

- **Injection.** Every field constructor fed `\n`, `\r`, NUL, `\x1b`, `"`, `\`, `]` and a
  lone surrogate. Assert exactly one line of output per record and no raw control byte in
  it. This is the package's primary security property and gets the most direct test.
- **Golden lines** derived by hand from the field list, never read off the implementation
  — the constraint from the readiness plan that caught the 0x11d/0x11b field split.
- **Truncation** at exactly the cap, one byte under, one byte over, and on a multi-byte
  rune straddling the boundary.
- **Vocabulary.** A declared key passes; an undeclared slog attribute is dropped and
  counted; `Declare` panics on reserved, malformed and conflicting names.
- **`kyauditverify` round trip.** Append records to a real `auditchain.Chain`, emit them
  through `Logger.Audit`, feed the emitted lines back through the same `records` iterator
  and `auditchain.VerifyStream` the command uses, and assert the chain verifies against
  the anchor. Then tamper with one shipped line and assert it fails.
- **`AuditFields` agreement.** The `fields` array and the flat keys on the same line carry
  the same values.
- **Fuzz** on field values: output is always valid JSON, always one line, never contains a
  raw control character.
- **Dependency budget** is covered automatically — `TestOnlyPasswordImportsADependency`
  discovers packages rather than listing them.

## Deferred

| Deferred | Restored when |
|---|---|
| RFC 5424 framing | A syslog collector exists that an agent cannot feed. ~60 lines. |
| A shipping forwarder | A Go consumer exists with no collector agent. None today. |
| A Ky log server | `kyauditverify` over the collector's export proves insufficient. |
| Migrating the nine products | Sized with the suite migration phases. |
