package logging

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/auditchain"
)

// testExpiresAt is a time-valued field declared only for these tests: the vocabulary in
// field.go has no time-typed key, and the renderValue/JSONHandler agreement this file
// checks needs one.
var testExpiresAt = DeclareTime("audit_test_expires_at")

func TestAuditFieldsRendersCanonicalPairs(t *testing.T) {
	ts := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	got := AuditFields(UserID("u_1"), Action("share_redeem"), ShareIndex(7), testExpiresAt(ts))
	want := []string{
		"user_id=u_1", "action=share_redeem", "share_index=7",
		"audit_test_expires_at=2026-09-03T12:00:00Z",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d fields, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAuditFieldsSanitizes(t *testing.T) {
	// AuditFields inherits sanitization from DeclaredString's constructor (this test
	// exercises that, not anything AuditFields itself does): the digest itself needs no
	// defence, since auditchain's digest length-prefixes every field and the field count,
	// so a raw newline cannot shift content into a neighbouring field or forge a record.
	// Sanitizing still matters downstream — a key=value grep over the shipped fields, or
	// any other tool that treats a field as a line, is what a literal newline would break.
	got := AuditFields(UserID("u_1\nuser_id=u_2"))
	if strings.ContainsAny(got[0], "\n\r") {
		t.Errorf("AuditFields kept a control character: %q", got[0])
	}
}

func TestAuditLineAgreesWithTheDigestedFields(t *testing.T) {
	// The two must carry the same values: one is what the digest covers, the
	// other is what the collector indexes. The time field is here because that
	// agreement previously broke specifically for KindTime: AuditFields pinned
	// nine fractional digits while the flat key, going through slog's
	// JSONHandler, trims trailing zeros — same instant, different strings.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	ts := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	fields := AuditFields(UserID("u_1"), Action("share_redeem"), testExpiresAt(ts))
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
	if err != nil {
		t.Fatal(err)
	}
	lg.Audit(context.Background(), ShareRedeemed, rec, UserID("u_1"), Action("share_redeem"), testExpiresAt(ts))

	m := oneLine(t, buf)
	if got := m["facility"]; got != float64(facilityAuthpriv) {
		t.Errorf("facility = %v, want authpriv (%d)", got, facilityAuthpriv)
	}
	if _, present := m["audit_fields_mismatch"]; present {
		t.Errorf("matching fields still set audit_fields_mismatch: %v", m["audit_fields_mismatch"])
	}
	raw, ok := m["fields"].([]any)
	if !ok {
		t.Fatalf("fields is %T, want an array: %v", m["fields"], m)
	}
	want := []string{"user_id=u_1", "action=share_redeem", "audit_test_expires_at=2026-09-03T12:00:00Z"}
	if len(raw) != len(want) {
		t.Fatalf("fields = %v, want %v", raw, want)
	}
	for i, w := range want {
		if raw[i] != w {
			t.Errorf("fields[%d] = %v, want %q", i, raw[i], w)
		}
	}
	if m["user_id"] != "u_1" {
		t.Errorf("flat user_id = %v, does not agree with the digested field", m["user_id"])
	}
	if m["action"] != "share_redeem" {
		t.Errorf("flat action = %v, does not agree with the digested field", m["action"])
	}
	if m["audit_test_expires_at"] != "2026-09-03T12:00:00Z" {
		t.Errorf("flat audit_test_expires_at = %v, does not agree with the digested field", m["audit_test_expires_at"])
	}
}

func TestAuditFieldsMismatchWithholdsFlatKeysAndMarksTheLine(t *testing.T) {
	// A copy-paste slip or a reassigned variable between building fields for
	// chain.Append and the fs passed to Audit must not ship a flat key that
	// disagrees with what the record authenticated.
	lg, buf := newTestLogger(t, slog.LevelInfo)

	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	fields := AuditFields(UserID("u_1"))
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately diverge: the record digested u_1, Audit is handed u_2.
	lg.Audit(context.Background(), ShareRedeemed, rec, UserID("u_2"))

	m := oneLine(t, buf)
	raw, ok := m["fields"].([]any)
	if !ok || len(raw) != 1 || raw[0] != "user_id=u_1" {
		t.Fatalf("fields = %v, want the digested record unchanged: [user_id=u_1]", m["fields"])
	}
	if _, present := m["user_id"]; present {
		t.Errorf("mismatched line still carries the flat key user_id = %v", m["user_id"])
	}
	if mismatch, _ := m["audit_fields_mismatch"].(bool); !mismatch {
		t.Errorf("audit_fields_mismatch = %v, want true", m["audit_fields_mismatch"])
	}
}

func TestAuditWithNoFieldsEmitsNoMismatch(t *testing.T) {
	// The most natural call: the product already holds rec and passes no fs. AuditFields()
	// of nothing is empty, which must not be treated as disagreeing with rec.Fields.
	lg, buf := newTestLogger(t, slog.LevelInfo)

	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	fields := AuditFields(UserID("u_1"))
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
	if err != nil {
		t.Fatal(err)
	}
	lg.Audit(context.Background(), ShareRedeemed, rec)

	m := oneLine(t, buf)
	if _, present := m["audit_fields_mismatch"]; present {
		t.Errorf("Audit with no fs set audit_fields_mismatch: %v", m["audit_fields_mismatch"])
	}
	raw, ok := m["fields"].([]any)
	if !ok || len(raw) != 1 || raw[0] != "user_id=u_1" {
		t.Fatalf("fields = %v, want the digested record unchanged: [user_id=u_1]", m["fields"])
	}
}

func TestAuditBypassesTheLevelGate(t *testing.T) {
	// A verbosity knob must never delete an audit record: chain.Append has already
	// advanced the sequence by the time Audit runs, and a suppressed line here is
	// indistinguishable from tampering. Built at Error, fed a Warn-level audit event —
	// which LogAttrs would normally admit — to isolate the bypass from level filtering.
	lg, buf := newTestLogger(t, slog.LevelError)

	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	fields := AuditFields(UserID("u_1"))
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
	if err != nil {
		t.Fatal(err)
	}
	lg.Audit(context.Background(), ShareRedeemed, rec, UserID("u_1"))

	m := oneLine(t, buf)
	if m["event"] != "share_redeemed" {
		t.Errorf("event = %v, want share_redeemed; the level gate suppressed the audit line", m["event"])
	}
}

// TestAuditToleratesANilContext pins a regression from the level-gate fix: Log and
// Security go through slog.Logger.LogAttrs, which normalises a nil context to
// context.Background() before it reaches requestIDFrom. Audit calls the handler
// directly and must do the same normalisation itself, or a nil context (a caller bug,
// but one Log and Security have always tolerated) panics in exactly the path this wave
// hardened against dropping a line.
func TestAuditToleratesANilContext(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)

	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	fields := AuditFields(UserID("u_1"))
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
	if err != nil {
		t.Fatal(err)
	}

	lg.Audit(nil, ShareRedeemed, rec, UserID("u_1")) //nolint:staticcheck // exercising nil-context tolerance deliberately

	m := oneLine(t, buf)
	if m["event"] != "share_redeemed" {
		t.Errorf("event = %v, want share_redeemed", m["event"])
	}
}

func TestShippedLinesVerifyAsAChainAtWarnLevelWithInfoAuditEvents(t *testing.T) {
	// Reproduces the reviewer's finding directly: a logger built at Warn, fed a mix of
	// Info- and Warn-level audit events, must still ship every line — otherwise
	// VerifyStream reports a sequence gap that reads exactly like tampering.
	lg, buf := newTestLogger(t, slog.LevelWarn)
	key := testKey()

	chain, err := auditchain.New(key)
	if err != nil {
		t.Fatal(err)
	}
	events := []Event{KeyCreated, ShareRedeemed, SessionCreated} // Info, Warn, Info
	for i, ev := range events {
		fields := AuditFields(UserID("u_1"), Count(int64(i)))
		rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
		if err != nil {
			t.Fatal(err)
		}
		lg.Audit(context.Background(), ev, rec, UserID("u_1"), Count(int64(i)))
	}
	anchor := chain.Anchor()

	shipped := buf.String()
	if n := strings.Count(shipped, "\n"); n != len(events) {
		t.Fatalf("shipped %d lines, want %d (one per audit call): %s", n, len(events), shipped)
	}
	if err := auditchain.VerifyStream(key, records(strings.NewReader(shipped)), anchor); err != nil {
		t.Fatalf("shipped lines do not verify: %v\n%s", err, shipped)
	}
}

// testKey is a fixed 32-byte chain key. Test data, never a real key.
func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// records mirrors the iterator in cmd/kyauditverify: one record per line,
// reporting a malformed line rather than ending the walk early.
func records(r *strings.Reader) iter.Seq2[auditchain.Record, error] {
	return func(yield func(auditchain.Record, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec auditchain.Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				yield(auditchain.Record{}, err)
				return
			}
			if !yield(rec, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(auditchain.Record{}, err)
		}
	}
}

func TestShippedLinesVerifyAsAChain(t *testing.T) {
	// The whole point of the flat shape: cmd/kyauditverify reads the collector's
	// export with no change to that command.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	key := testKey()

	chain, err := auditchain.New(key)
	if err != nil {
		t.Fatal(err)
	}
	for i, user := range []string{"u_1", "u_2", "u_3"} {
		fields := AuditFields(UserID(user), Count(int64(i)))
		rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
		if err != nil {
			t.Fatal(err)
		}
		lg.Audit(context.Background(), ShareRedeemed, rec, UserID(user), Count(int64(i)))
	}
	anchor := chain.Anchor()

	shipped := buf.String()
	if err := auditchain.VerifyStream(key, records(strings.NewReader(shipped)), anchor); err != nil {
		t.Fatalf("shipped lines do not verify: %v\n%s", err, shipped)
	}
}

func TestATamperedShippedLineFailsVerification(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	key := testKey()

	chain, err := auditchain.New(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"u_1", "u_2"} {
		fields := AuditFields(UserID(user))
		rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
		if err != nil {
			t.Fatal(err)
		}
		lg.Audit(context.Background(), ShareRedeemed, rec, UserID(user))
	}
	anchor := chain.Anchor()

	untampered := buf.String()
	if err := auditchain.VerifyStream(key, records(strings.NewReader(untampered)), anchor); err != nil {
		// If this fails, the assertion below would pass vacuously for the wrong
		// reason — a broken anchor or a shape regression, not the tamper.
		t.Fatalf("untampered shipped lines do not verify: %v\n%s", err, untampered)
	}

	tampered := strings.Replace(untampered, "user_id=u_2", "user_id=u_9", 1)
	if tampered == untampered {
		t.Fatal("the test did not actually change a digested field")
	}
	err = auditchain.VerifyStream(key, records(strings.NewReader(tampered)), anchor)
	if !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Errorf("tampered stream error = %v, want auditchain.ErrBrokenChain", err)
	}
}

// failingWriter is a sink the collector has stopped draining.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

// A dropped audit line is indistinguishable from tampering at central verification, so
// the write failure has to reach the caller rather than the floor.
//
// Written first against the discarded handler error, where Audit had nothing to return.
func TestAuditReturnsTheWriteError(t *testing.T) {
	lg, err := New(Config{App: "test", Out: failingWriter{}})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, AuditFields(UserID("u_1"))...)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Audit(context.Background(), ShareRedeemed, rec, UserID("u_1")); err == nil {
		t.Fatal("Audit reported success for a line the writer refused")
	}
}
