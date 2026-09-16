package auditchain_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/auditchain"
)

func appendOne(t *testing.T, key []byte, fields ...string) auditchain.Record {
	t.Helper()
	c, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec, err := c.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error {
		return nil
	}, fields...)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return rec
}

func TestVerifyRecordAcceptsAnAuthenticRecord(t *testing.T) {
	key := make([]byte, 32)
	rec := appendOne(t, key, "login", "alice")
	if err := auditchain.VerifyRecord(key, rec); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
}

func TestVerifyRecordRefusesAForgedField(t *testing.T) {
	key := make([]byte, 32)
	rec := appendOne(t, key, "login", "alice")
	rec.Fields = []string{"login", "mallory"}
	if err := auditchain.VerifyRecord(key, rec); err == nil {
		t.Fatal("VerifyRecord accepted a rewritten field")
	}
}

func TestVerifyRecordRefusesAnotherKey(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	other[0] = 1
	rec := appendOne(t, key, "login", "alice")
	if err := auditchain.VerifyRecord(other, rec); err == nil {
		t.Fatal("VerifyRecord accepted a record under a different key")
	}
}

// The whole point: unlike Resume, this asks nothing about where the record sits.
func TestVerifyRecordSaysNothingAboutTailness(t *testing.T) {
	key := make([]byte, 32)
	c, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	persist := func(auditchain.Record, auditchain.Anchor) error { return nil }
	first, err := c.Append(context.Background(), persist, "login", "alice")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := c.Append(context.Background(), persist, "logout", "alice"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// first is now in the middle. VerifyRecord still accepts it.
	if err := auditchain.VerifyRecord(key, first); err != nil {
		t.Fatalf("VerifyRecord on a mid-chain record: %v", err)
	}
	// Resume, given the same record and the chain's real anchor, refuses it.
	if _, err := auditchain.Resume(key, first, c.Anchor()); err == nil {
		t.Fatal("Resume accepted a mid-chain record as the tail")
	}
}

func TestVerifyRecordRefusesAShortKey(t *testing.T) {
	rec := appendOne(t, make([]byte, 32), "login", "alice")
	if err := auditchain.VerifyRecord(make([]byte, 31), rec); err == nil {
		t.Fatal("VerifyRecord accepted a 31-byte key")
	}
	if err := auditchain.VerifyRecord(nil, rec); !errors.Is(err, auditchain.ErrWeakKey) {
		t.Errorf("nil key gave %v, want ErrWeakKey", err)
	}
}

func TestReplayBuildsAChainVerifyAccepts(t *testing.T) {
	key := make([]byte, 32)
	tuples := [][]string{
		{"login", "alice"},
		{"logout", "alice"},
		{"login", "bob"},
	}
	records, anchor, err := auditchain.Replay(key, tuples)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("Replay returned %d records, want 3", len(records))
	}
	if anchor.Count != 3 {
		t.Errorf("anchor.Count = %d, want 3", anchor.Count)
	}
	if anchor.Hash != records[2].Hash {
		t.Errorf("anchor.Hash = %q, want the last record's %q", anchor.Hash, records[2].Hash)
	}
	if err := auditchain.Verify(key, records, anchor); err != nil {
		t.Fatalf("Verify on a replayed chain: %v", err)
	}
}

func TestReplayNumbersFromOne(t *testing.T) {
	key := make([]byte, 32)
	records, _, err := auditchain.Replay(key, [][]string{{"a"}, {"b"}})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if records[0].Seq != 1 || records[1].Seq != 2 {
		t.Errorf("Seq = %d, %d; want 1, 2", records[0].Seq, records[1].Seq)
	}
}

func TestReplayOfNothingIsTheGenesisAnchor(t *testing.T) {
	key := make([]byte, 32)
	records, anchor, err := auditchain.Replay(key, nil)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
	if anchor.Count != 0 {
		t.Errorf("anchor.Count = %d, want 0", anchor.Count)
	}
	const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if anchor.Hash != genesisHash {
		t.Errorf("anchor.Hash = %q, want the genesis hash %q", anchor.Hash, genesisHash)
	}
}

func TestReplayRefusesAShortKey(t *testing.T) {
	if _, _, err := auditchain.Replay(make([]byte, 31), [][]string{{"a"}}); err == nil {
		t.Fatal("Replay accepted a 31-byte key")
	}
}
