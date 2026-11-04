package auditchain

import (
	"context"
	"crypto/hmac"
	"fmt"
)

// VerifyRecord reports whether a record carries its own digest under this key.
//
// It also refuses a record whose Seq is 0, or whose Hash or Prev is not 64 lowercase hex
// characters: neither shape was ever minted by Append, so there is nothing authentic to
// compare against. A legacy log numbered from zero will fail here with that sequence-0
// error, not a digest mismatch — expect it when converting one.
//
// It says nothing about where the record sits. Resume answers a different question — is
// this the tail — and answering it requires the anchor, because every record in a healthy
// chain carries a valid digest. Callers converting a log from an older format want this
// one: they are asking whether a record is already in the shared shape, not whether it is
// the end.
func VerifyRecord(key []byte, r Record) error {
	if len(key) < minKeyBytes {
		return fmt.Errorf("%w, got %d", ErrWeakKey, len(key))
	}
	if !validHash(r.Hash) || !validHash(r.Prev) {
		return fmt.Errorf("%w: record %d carries a hash that is not 64 lowercase hex characters", ErrBrokenChain, r.Seq)
	}
	// Append starts at one, so no record legitimately carries sequence 0.
	if r.Seq == 0 {
		return fmt.Errorf("%w: record carries sequence 0, which no append mints", ErrBrokenChain)
	}
	if !hmac.Equal([]byte(digest(key, r.Seq, r.Prev, r.Fields)), []byte(r.Hash)) {
		return fmt.Errorf("%w: record %d does not carry its own digest", ErrBrokenChain, r.Seq)
	}
	return nil
}

// Replay builds a whole chain in memory from field tuples and returns its records with the
// anchor they end at. It writes nothing.
//
// Append takes a persist function because the chain's head is a claim about what is on
// disk, and advancing it before the store agrees leaves the next record chained onto one
// that never existed. A bulk conversion inverts that: it rebuilds every record, writes the
// log once atomically, and saves one anchor. Passing a persist that does nothing per record
// would satisfy the signature and mean nothing — do not copy that pattern outside this
// function. This is the shape that fits: the caller still owes one transaction over the
// returned records and anchor together.
//
// Every field must be valid UTF-8; otherwise Replay returns an error wrapping
// ErrInvalidUTF8 that names the tuple, and no records.
func Replay(key []byte, tuples [][]string) ([]Record, Anchor, error) {
	c, err := New(key)
	if err != nil {
		return nil, Anchor{}, err
	}
	records := make([]Record, 0, len(tuples))
	noop := func(Record, Anchor) error { return nil }
	for _, fields := range tuples {
		rec, err := c.Append(context.Background(), noop, fields...)
		if err != nil {
			return nil, Anchor{}, fmt.Errorf("auditchain: tuple %d: %w", len(records), err)
		}
		records = append(records, rec)
	}
	return records, c.Anchor(), nil
}
