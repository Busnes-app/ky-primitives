package auditchain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Finding 2.2: an empty log skipped the head comparison entirely, so any anchor hash
// verified. The anchor is authenticated external state; accepting a corrupt one and
// reporting success is the exact failure the anchor exists to prevent.
func TestVerifyRejectsABadAnchorOnAnEmptyLog(t *testing.T) {
	for _, hash := range []string{"corrupt-not-even-hex", strings.Repeat("a", 64), ""} {
		err := Verify(key, nil, Anchor{Count: 0, Hash: hash})
		if !errors.Is(err, ErrBrokenChain) {
			t.Errorf("empty log with anchor hash %q: got %v, want ErrBrokenChain", hash, err)
		}
	}
	if err := Verify(key, nil, Anchor{Count: 0, Hash: genesis}); err != nil {
		t.Fatalf("empty log with the genesis anchor was rejected: %v", err)
	}
}

// A hash is 64 lowercase hex characters. Anything else is not a value this package ever
// produced, so accepting it means comparing against something a caller invented.
func TestVerifyRejectsMalformedHashes(t *testing.T) {
	records := build(t, []string{"a"})
	anchor := Anchor{Count: 1, Hash: records[0].Hash}

	for _, bad := range []string{"", "zz", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		broken := []Record{{Seq: 1, Prev: genesis, Hash: bad, Fields: []string{"a"}}}
		if err := Verify(key, broken, Anchor{Count: 1, Hash: bad}); !errors.Is(err, ErrBrokenChain) {
			t.Errorf("record hash %q: got %v, want ErrBrokenChain", bad, err)
		}
		broken = []Record{{Seq: 1, Prev: bad, Hash: records[0].Hash, Fields: []string{"a"}}}
		if err := Verify(key, broken, anchor); !errors.Is(err, ErrBrokenChain) {
			t.Errorf("record prev %q: got %v, want ErrBrokenChain", bad, err)
		}
	}
}

func TestResumeRejectsAMalformedHash(t *testing.T) {
	bad := Record{Seq: 1, Prev: genesis, Hash: "nothex", Fields: []string{"a"}}
	if _, err := Resume(key, bad, Anchor{Count: 1, Hash: bad.Hash}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

// Finding 2.1: Append advanced the chain in memory before the caller had persisted
// anything, and there was no rollback. A failed insert left the next record chained onto
// one that does not exist, and a record persisted without its anchor left the opposite
// inconsistency. Persistence is now part of the append, under the same lock.
func TestAppendDoesNotAdvanceWhenPersistFails(t *testing.T) {
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Append(context.Background(), func(Record, Anchor) error { return nil }, "a")
	if err != nil {
		t.Fatal(err)
	}

	boom := errors.New("insert failed")
	if _, err := c.Append(context.Background(), func(Record, Anchor) error { return boom }, "b"); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the persist error", err)
	}
	if got := c.Anchor(); got.Count != 1 || got.Hash != first.Hash {
		t.Fatalf("anchor advanced past a failed persist: %+v", got)
	}

	// The next successful append must continue from the first record, not from the one
	// that was never stored.
	second, err := c.Append(context.Background(), func(Record, Anchor) error { return nil }, "c")
	if err != nil {
		t.Fatal(err)
	}
	if second.Seq != 2 {
		t.Fatalf("next record has sequence %d, want 2", second.Seq)
	}
	if second.Prev != first.Hash {
		t.Fatal("next record does not chain onto the last persisted one")
	}
	if err := Verify(key, []Record{first, second}, c.Anchor()); err != nil {
		t.Fatalf("the surviving chain does not verify: %v", err)
	}
}

// The callback receives the anchor that results from this record, so a caller can write
// the record and the anchor in one transaction rather than guessing.
func TestAppendHandsThePersisterTheResultingAnchor(t *testing.T) {
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	var seen []Anchor
	for i := 0; i < 3; i++ {
		rec, err := c.Append(context.Background(), func(r Record, a Anchor) error {
			seen = append(seen, a)
			if a.Hash != r.Hash {
				t.Fatalf("anchor hash %q does not match record hash %q", a.Hash, r.Hash)
			}
			return nil
		}, "e")
		if err != nil {
			t.Fatal(err)
		}
		if seen[i].Count != uint64(i+1) || seen[i].Hash != rec.Hash {
			t.Fatalf("append %d saw anchor %+v", i, seen[i])
		}
	}
}

func TestAppendRequiresAPersister(t *testing.T) {
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(context.Background(), nil, "a"); err == nil {
		t.Fatal("a nil persister was accepted")
	}
	if got := c.Anchor(); got.Count != 0 {
		t.Fatalf("chain advanced on a rejected append: %+v", got)
	}
}

// encoding/json writes invalid UTF-8 as U+FFFD, so a record carrying such a field would
// fail its own digest after a JSON round trip: a permanent false tamper alarm.
func TestAppendAndReplayRefuseInvalidUTF8(t *testing.T) {
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	persisted := 0
	persist := func(Record, Anchor) error { persisted++; return nil }
	if _, err := c.Append(context.Background(), persist, "login", "/u/\xff"); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("invalid UTF-8 field: got %v, want ErrInvalidUTF8", err)
	}
	if persisted != 0 || c.Anchor().Count != 0 {
		t.Fatalf("refused append persisted %d records, anchor %+v", persisted, c.Anchor())
	}
	if _, err := c.Append(context.Background(), persist, "login", "/u/é"); err != nil {
		t.Fatalf("valid UTF-8 refused: %v", err)
	}
	if _, _, err := Replay(key, [][]string{{"ok"}, {"\xc3"}}); !errors.Is(err, ErrInvalidUTF8) || !strings.Contains(err.Error(), "tuple 1") {
		t.Fatalf("Replay: got %v, want ErrInvalidUTF8 naming tuple 1", err)
	}
}
