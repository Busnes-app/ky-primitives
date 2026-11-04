// Package auditchain builds and verifies a tamper-evident hash chain over audit records.
//
// The suite carried three of these. kybookmarks-server fell back to a key committed in
// its own source when none was configured, so anyone who could write the log could
// recompute the chain and verification still passed. Two of the three joined fields with
// a bare "|", so a field carrying the delimiter could be shifted into its neighbour
// without changing the digest — a forged record without the key. And only one kept a
// count and hash outside the log, which is the only thing that catches a log with
// records removed from the end: what remains still chains correctly.
//
// This package fixes the key floor, length-prefixes every field, and makes the anchor
// part of verification rather than an option.
//
// It deliberately owns no storage. The three implementations wrote to JSON lines, to a
// file and to a database, and the divergence that mattered was never where the bytes
// went.
package auditchain

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"math"
	"unicode/utf8"
)

// genesis is the predecessor hash of the first record.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// minKeyBytes is the floor for the chain key. A weak key here is worse than a loud
// failure: the chain would still verify, against a value an attacker can search.
const minKeyBytes = 32

var (
	// ErrWeakKey reports a chain key under 32 bytes.
	ErrWeakKey = errors.New("auditchain: key must be at least 32 bytes")
	// ErrBrokenChain reports a record whose digest, predecessor or sequence does not
	// match the chain.
	ErrBrokenChain = errors.New("auditchain: chain does not verify")
	// ErrTruncated reports a log holding fewer records than the anchor counted.
	ErrTruncated = errors.New("auditchain: log is shorter than its anchor")
	// ErrInvalidUTF8 reports a field that is not valid UTF-8. Append and Replay refuse it:
	// encoding/json writes such bytes as U+FFFD, so a record stored or exported as JSON
	// would no longer carry its own digest and would verify as altered forever. Pass
	// request-derived text through logging.AuditFields, which replaces invalid bytes.
	ErrInvalidUTF8 = errors.New("auditchain: field is not valid UTF-8")
)

// Record is one link. Fields are opaque to this package; products log different things
// and forcing one schema on them is what made the three implementations diverge.
type Record struct {
	Seq    uint64   `json:"seq"`
	Prev   string   `json:"prev"`
	Hash   string   `json:"hash"`
	Fields []string `json:"fields"`
}

// Anchor is the chain's length and head, kept outside the log. Without it a log
// truncated at the end verifies perfectly.
type Anchor struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash"`
}

// Chain appends records. It is safe for concurrent use; two racing appends would
// otherwise mint the same sequence number and the same predecessor.
//
// The lock is a channel rather than a sync.Mutex because persist runs while it is held,
// and a sync.Mutex cannot be waited on with a deadline. A store that hangs therefore owned
// the chain outright: every later append, and every Anchor(), blocked on it forever with
// no way to shed. Append takes a context.Context so a waiter can give up.
type Chain struct {
	lock  chan struct{}
	key   []byte
	count uint64
	head  string
}

// New starts a chain at the genesis hash.
func New(key []byte) (*Chain, error) {
	if len(key) < minKeyBytes {
		return nil, fmt.Errorf("%w, got %d", ErrWeakKey, len(key))
	}
	return &Chain{lock: make(chan struct{}, 1), key: append([]byte(nil), key...), head: genesis}, nil
}

// acquire takes the chain lock, honouring ctx.
func (c *Chain) acquire(ctx context.Context) error {
	// Checked first because select chooses at random between ready cases, so an already
	// cancelled caller would otherwise be admitted whenever the lock happened to be free.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Chain) releaseLock() { <-c.lock }

// Resume continues a chain after its last record, given the anchor that record produced.
//
// The anchor is required because a valid digest does not make a record the tail. Every
// record in a healthy chain carries its own digest, so resuming from one in the middle was
// accepted, and the next append minted a sequence number that already existed: a fork,
// persisted successfully, that Verify then rejects forever. The anchor is the only thing
// kept outside the log that knows where the end is, so it is what says which record the
// tail is — and a caller who cannot produce a matching one does not know either.
//
// This does not verify the prefix. A chain resumed here is consistent with its anchor,
// which is what the next append needs; call Verify or VerifyStream over the stored log to
// establish that everything behind the anchor is intact.
func Resume(key []byte, last Record, anchor Anchor) (*Chain, error) {
	c, err := New(key)
	if err != nil {
		return nil, err
	}
	if err := VerifyRecord(c.key, last); err != nil {
		return nil, err
	}
	// Append mints count+1, so the top of the range wraps the next record to zero — which
	// persists cleanly and can never verify. VerifyRecord already refused the other end,
	// sequence 0, since no append mints it either.
	if last.Seq == math.MaxUint64 {
		return nil, fmt.Errorf("%w: record %d leaves no room for another append", ErrBrokenChain, last.Seq)
	}
	if anchor.Count != last.Seq || !hmac.Equal([]byte(anchor.Hash), []byte(last.Hash)) {
		return nil, fmt.Errorf("%w: anchor is %d/%s but the record is %d/%s, so this is not the tail",
			ErrBrokenChain, anchor.Count, anchor.Hash, last.Seq, last.Hash)
	}
	c.count, c.head = last.Seq, last.Hash
	return c, nil
}

// Append builds the next record, hands it and the anchor it produces to persist, and
// advances the chain only if persist succeeds.
//
// Persistence is a parameter rather than the caller's next statement because the chain's
// in-memory head is a claim about what is on disk. Advancing it first meant a failed
// insert left the following record chained onto one that does not exist, and a record
// stored without its anchor left the opposite inconsistency — with no way to roll either
// back. persist runs under the same lock that reserves the sequence number, so it should
// write the record and the anchor together and return.
// ctx bounds the wait for the chain lock, not persist. Once persist is running it holds
// the sequence number it reserved and cannot be abandoned without leaving the chain unsure
// whether the record was stored — which is the whole reason persist runs under the lock.
// Give persist its own timeout, and do not call back into the Chain from it: the lock is
// not reentrant, and the anchor it would ask for is already one of its arguments.
//
// Every field must be valid UTF-8; otherwise Append returns an error wrapping
// ErrInvalidUTF8 and persists nothing.
func (c *Chain) Append(ctx context.Context, persist func(Record, Anchor) error, fields ...string) (Record, error) {
	if persist == nil {
		return Record{}, errors.New("auditchain: a persist function is required; the chain cannot advance without knowing the record is stored")
	}
	for i, f := range fields {
		if !utf8.ValidString(f) {
			return Record{}, fmt.Errorf("%w: field %d", ErrInvalidUTF8, i)
		}
	}
	if err := c.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer c.releaseLock()

	rec := Record{
		Seq:    c.count + 1,
		Prev:   c.head,
		Fields: append([]string(nil), fields...),
	}
	rec.Hash = digest(c.key, rec.Seq, rec.Prev, rec.Fields)

	if err := persist(rec, Anchor{Count: rec.Seq, Hash: rec.Hash}); err != nil {
		// Nothing has been mutated, so the next append reuses this sequence number and
		// chains onto the last record that was actually stored.
		return Record{}, err
	}

	c.count, c.head = rec.Seq, rec.Hash
	return rec, nil
}

// Anchor returns the state to persist outside the log, after every append.
func (c *Chain) Anchor() Anchor {
	c.lock <- struct{}{}
	defer c.releaseLock()
	return Anchor{Count: c.count, Hash: c.head}
}

// Verify walks a complete chain, starting at sequence 1, and checks it against the
// anchor. records must be the whole log: this package does not carry a rotation scheme,
// and accepting a partial one would defeat the anchor.
func Verify(key []byte, records []Record, anchor Anchor) error {
	return VerifyStream(key, func(yield func(Record, error) bool) {
		for _, rec := range records {
			if !yield(rec, nil) {
				return
			}
		}
	}, anchor)
}

// VerifyStream is Verify over an iterator, for a log too large to materialise.
//
// Audit chains reach six figures in this suite, and the shape of the bug that follows
// from paging them is specific: kyrecovery-server's VerifyChain read a fixed 100000
// events and then reported a sequence gap on a perfectly healthy chain. Streaming removes
// the reason to page. A record yielded with a non-nil error fails the verification rather
// than ending the walk, so a store that dies mid-read cannot look like a short chain.
func VerifyStream(key []byte, records iter.Seq2[Record, error], anchor Anchor) error {
	if len(key) < minKeyBytes {
		return fmt.Errorf("%w, got %d", ErrWeakKey, len(key))
	}
	if !validHash(anchor.Hash) {
		return fmt.Errorf("%w: anchor hash %q is not 64 lowercase hex characters", ErrBrokenChain, anchor.Hash)
	}
	prev := genesis
	var count uint64
	for rec, err := range records {
		if err != nil {
			return fmt.Errorf("auditchain: reading record %d: %w", count+1, err)
		}
		count++
		if !validHash(rec.Hash) || !validHash(rec.Prev) {
			return fmt.Errorf("%w: record %d carries a hash that is not 64 lowercase hex characters", ErrBrokenChain, count)
		}
		if rec.Seq != count {
			return fmt.Errorf("%w: record %d carries sequence %d", ErrBrokenChain, count, rec.Seq)
		}
		if rec.Prev != prev {
			return fmt.Errorf("%w: record %d does not follow its predecessor", ErrBrokenChain, rec.Seq)
		}
		if !hmac.Equal([]byte(digest(key, rec.Seq, rec.Prev, rec.Fields)), []byte(rec.Hash)) {
			return fmt.Errorf("%w: record %d has been altered", ErrBrokenChain, rec.Seq)
		}
		prev = rec.Hash
	}

	switch {
	case count < anchor.Count:
		return fmt.Errorf("%w: %d records, anchor counted %d", ErrTruncated, count, anchor.Count)
	case count > anchor.Count:
		return fmt.Errorf("%w: %d records past an anchor counting %d", ErrBrokenChain, count, anchor.Count)
	case prev != anchor.Hash:
		// Unconditional. An empty log leaves prev at the genesis hash, so an anchor
		// claiming anything else is inconsistent with the log it anchors — and skipping
		// the comparison there meant a corrupt zero-count anchor verified clean.
		return fmt.Errorf("%w: head does not match the anchor", ErrBrokenChain)
	}
	return nil
}

// validHash reports whether s is the form this package emits: 64 lowercase hex
// characters. Anything else came from somewhere other than digest, so comparing against
// it compares against a value a caller or a corrupt store invented.
func validHash(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// digest length-prefixes every part, so no field content can be shifted into its
// neighbour to produce another record's digest.
func digest(key []byte, seq uint64, prev string, fields []string) string {
	mac := hmac.New(sha256.New, key)
	var n [8]byte
	write := func(v uint64) {
		binary.BigEndian.PutUint64(n[:], v)
		mac.Write(n[:])
	}
	writeString := func(s string) {
		write(uint64(len(s)))
		mac.Write([]byte(s))
	}
	write(seq)
	writeString(prev)
	write(uint64(len(fields)))
	for _, f := range fields {
		writeString(f)
	}
	return hex.EncodeToString(mac.Sum(nil))
}
