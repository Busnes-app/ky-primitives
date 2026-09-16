package logging

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/Busnes-app/ky-primitives/auditchain"
)

// auditValue carries a chain record to the handler, plus whether the flat field keys
// Audit was about to emit alongside it agree with what the record digested. Its type is
// unexported, so code outside this package cannot forge seq, prev, hash and fields into
// the stream — which matters because cmd/kyauditverify will parse whatever carries them.
type auditValue struct {
	rec      auditchain.Record
	mismatch bool
}

// attrs flattens the record onto the line. Flat, not nested, because kyauditverify
// unmarshals the whole line into an auditchain.Record and Go's decoder ignores the keys
// it does not know. On a mismatch it also sets audit_fields_mismatch, since Audit has
// withheld the flat keys that would otherwise disagree with fields.
func (a auditValue) attrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.Uint64("seq", a.rec.Seq),
		slog.String("prev", a.rec.Prev),
		slog.String("hash", a.rec.Hash),
		slog.Any("fields", a.rec.Fields),
	}
	if a.mismatch {
		attrs = append(attrs, slog.Bool("audit_fields_mismatch", true))
	}
	return attrs
}

// AuditFields renders declared fields as the canonical key=value strings a chain
// digests. Order is the argument order, and the digest depends on it.
//
// Audit recomputes this over the fields it is given and compares the result against the
// record's own Fields, since the two are built at separate call sites — the digest at the
// chain.Append that minted rec, the flat keys at the Audit call that follows — and nothing
// but that comparison stops them silently disagreeing.
func AuditFields(fs ...Field) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		if f.key == "" {
			continue
		}
		out = append(out, f.key+"="+renderValue(f.val.v))
	}
	return out
}

// renderValue is the one spelling of a value for the chain. It has to be, rather than
// slog.Value.String(): String() renders a KindTime as Go's default time.Time format
// (2006-01-02 15:04:05.999999999 -0700 MST), but the flat key for the same value goes
// through slog's JSONHandler, which marshals time.Time as RFC3339Nano — trimming trailing
// zero fractional digits, down to none at whole-second precision. Pinning to
// RFC3339Nano here, on a value already normalised to UTC by DeclareTime, is what keeps
// the digested pair and the flat key textually identical.
func renderValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	case slog.KindInt64:
		return strconv.FormatInt(v.Int64(), 10)
	case slog.KindBool:
		return strconv.FormatBool(v.Bool())
	default:
		return v.String()
	}
}

// Audit records a chain record on the authpriv facility, alongside the same values as
// flat keys — unless fs disagrees with what rec's Fields digested, in which case the flat
// keys are withheld and audit_fields_mismatch marks the line instead of silently shipping
// a flat user_id next to a fields entry that authenticates a different one. The record
// itself — seq, prev, hash, fields — always ships either way: it is what is authenticated,
// and withholding it on a caller's mistake would cost the one thing meant to survive one.
//
// Audit ignores the configured level: it writes the handler directly rather than going
// through LogAttrs, so no KY_LOG_LEVEL can suppress it. An audit record is evidence, not
// verbosity — chain.Append has already advanced the sequence by the time Audit is called,
// and a gap left by a dropped line is indistinguishable from tampering. A verbosity knob
// is not allowed to manufacture a tamper alarm.
//
// The export handed to kyauditverify must be filtered to lines carrying hash: Log and
// Security lines decode into a zero auditchain.Record without a JSON error, which
// VerifyStream cannot tell apart from an attack.
//
// The record's storage stays with the product: auditchain deliberately owns none, and a
// tamper-evident chain that exists only on a machine the attacker may also own is not
// evidence. This ships a copy; the product keeps writing its local chained file.
//
// The write error is returned, not dropped. A closed stderr, a pipe the collector has
// stopped draining, a short write: each loses the shipped line, and a missing line is
// indistinguishable from tampering at central verification. Whoever can stall the
// collector must not be able to suppress evidence with nothing noticing, so the caller
// gets to say what happens -- TestAuditReturnsTheWriteError.
func (l *Logger) Audit(ctx context.Context, ev Event, rec auditchain.Record, fs ...Field) error {
	if ctx == nil {
		// LogAttrs does this for Log and Security; Handle does not, and this bypasses
		// LogAttrs. A nil context is a caller bug, but Audit is the one path this wave
		// hardened against dropping a line, so it does not get to crash on it either.
		ctx = context.Background()
	}
	mismatch := len(fs) > 0 && !slices.Equal(AuditFields(fs...), rec.Fields)
	av := auditValue{rec: rec, mismatch: mismatch}
	if mismatch {
		fs = nil
	}
	attrs := buildAttrs(ev, []slog.Attr{slog.Any("audit", av)}, fs)
	r := slog.NewRecord(time.Now(), ev.level, ev.message, 0)
	r.AddAttrs(attrs...)
	return l.sec.Handler().Handle(ctx, r)
}
