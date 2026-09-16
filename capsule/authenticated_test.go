package capsule_test

import (
	"bytes"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
)

// A capsule's manifest states who it belongs to and how many shares recover it. None of
// that is secret, but all of it is load-bearing during a recovery, and kycap/1 left every
// field of it outside the AEAD: an attacker who never learns the key could still rewrite
// the service identity, or restate a 2-of-3 kit as 1-of-1, and the capsule still opened.
//
// Each edit below is byte-for-byte the same length as what it replaces, so the only thing
// that changes is manifest content. A capsule that opens after one of these is a capsule
// whose manifest is decoration.
func TestOpenRejectsATamperedManifest(t *testing.T) {
	edits := map[string]struct{ from, to string }{
		"service name": {`"fixture"`, `"fixtur3"`},
		"threshold":    {`"threshold":2`, `"threshold":1`},
		"total shares": {`"total_shares":3`, `"total_shares":1`},
		"app version":  {`"0.0.0"`, `"9.9.9"`},
	}

	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			priv := testRecoveryKey(t)
			raw, _, err := capsule.Seal("fixture", "0.0.0",
				[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte(edit.from)) {
				t.Fatalf("cannot tamper: %q is not in the container", edit.from)
			}
			if len(edit.from) != len(edit.to) {
				t.Fatalf("edit changes length, which would prove nothing about authentication")
			}
			tampered := bytes.Replace(raw, []byte(edit.from), []byte(edit.to), 1)

			if _, _, err := capsule.Open(tampered, priv, ""); err == nil {
				t.Fatalf("a capsule opened after its %s was rewritten without the key", name)
			}
		})
	}
}

// The manifest is authenticated, so an untouched capsule must still open. Without this
// the test above passes for a Seal that produces nothing openable at all.
func TestOpenAcceptsAnUntamperedManifest(t *testing.T) {
	priv := testRecoveryKey(t)
	raw, _, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := capsule.Open(raw, priv, ""); err != nil {
		t.Fatalf("a capsule this package just sealed did not open: %v", err)
	}
}

// Recovery topology that cannot be satisfied is worse than none: a polished encrypted
// backup that documents a 5-of-3 kit sends a custodian looking for shares that were never
// issued.
func TestSealRefusesImpossibleShareParameters(t *testing.T) {
	priv := testRecoveryKey(t)
	files := []capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}
	for name, tc := range map[string]struct{ threshold, total int }{
		"threshold above total": {5, 3},
		"zero threshold":        {0, 3},
		"negative threshold":    {-1, 3},
		"threshold of one":      {1, 3},
		"zero total":            {2, 0},
		"total past the field":  {2, 256},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := capsule.Seal("x", "0", files, nil, nil, tc.threshold, tc.total, priv.Public()); err == nil {
				t.Fatalf("sealed a capsule advertising %d-of-%d", tc.threshold, tc.total)
			}
		})
	}
}
