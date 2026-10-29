package password

import (
	"errors"
	"testing"
	"time"
)

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	DummyVerify()
}

// docs/CREDENTIALS.md's timing claim — a missing account does not answer faster than a wrong
// password — is a structural property, not something a wall-clock test can safely pin: on
// a loaded CI box a timing assertion flakes, and a flaky test guarding a security property
// gets muted, which is worse than no test. So this checks the two facts that make the
// property true instead of measuring it: the memoised dummy hash is minted at
// DefaultParams(), the same band Hash uses, and DummyVerify runs it through the real
// Verify path rather than a shortcut. Same parameters through the same code implies same
// cost.
func TestDummyVerifyUsesRealParametersAndVerification(t *testing.T) {
	dummyHashMu.Lock()
	dummyHashValue = ""
	dummyHashMu.Unlock()

	DummyVerify()

	dummyHashMu.Lock()
	encoded := dummyHashValue
	dummyHashMu.Unlock()
	if encoded == "" {
		t.Fatal("DummyVerify did not mint a dummy hash")
	}

	p, _, _, err := parse(encoded)
	if err != nil {
		t.Fatalf("parse(dummy hash): %v", err)
	}
	if p != DefaultParams() {
		t.Fatalf("dummy hash uses %+v, want DefaultParams() %+v", p, DefaultParams())
	}

	ok, err := Verify(dummyPlaintext, encoded)
	if err != nil {
		t.Fatalf("Verify(dummyPlaintext, dummy hash): %v", err)
	}
	if !ok {
		t.Fatal("the dummy hash does not verify against dummyPlaintext: DummyVerify would not be running a real check")
	}
}

func TestNeedsRehashIsFalseForAForeignFormat(t *testing.T) {
	cases := []string{
		"scrypt$131072$8$1$c2FsdA$aGFzaA",
		"$2b$12$abcdefghijklmnopqrstuv",
		"239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
		"",
	}
	for _, encoded := range cases {
		stale, err := NeedsRehash(encoded)
		if err != nil {
			t.Errorf("NeedsRehash(%q) = error %v, want (false, nil)", encoded, err)
		}
		if stale {
			t.Errorf("NeedsRehash(%q) = true, want false", encoded)
		}
	}
}

func TestNeedsRehashStillFlagsAWeakOwnHash(t *testing.T) {
	weak, err := HashWith("hunter2", Params{Memory: 8 * 1024, Time: 1, Threads: 1})
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	stale, err := NeedsRehash(weak)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if !stale {
		t.Error("NeedsRehash did not flag a hash below the current parameters")
	}
}

func TestNeedsRehashIsFalseForACurrentHash(t *testing.T) {
	current, err := Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	stale, err := NeedsRehash(current)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if stale {
		t.Error("NeedsRehash flagged a hash minted at the current parameters")
	}
}

// Verify must still refuse a malformed stored hash outright. A fallback there is the
// bug this package exists to remove, and relaxing NeedsRehash must not relax Verify.
func TestVerifyStillErrorsOnAForeignFormat(t *testing.T) {
	if _, err := Verify("hunter2", "scrypt$131072$8$1$c2FsdA$aGFzaA"); !errors.Is(err, ErrMalformed) {
		t.Errorf("Verify on a foreign format gave %v, want ErrMalformed", err)
	}
}

// TestDummyVerifySurvivesAFullyHeldBudget is a permanent regression guard for the fix that
// made dummyMint bypass withBudget. Before that fix, dummyHash minted through Hash, which
// acquires the budget; holding the entire budget here reproduced a panic that a later call
// could never recover from, because sync.OnceValue re-raises a cached panic forever.
//
// The check is behavioural, not timing-based: with the budget fully held, a mint that still
// went through withBudget would block for the full maxWait and then return ErrBusy, which
// dummyHash's only handling for a dummyMint failure is to propagate as a panic — so a
// regression here surfaces as this test's recover() catching a panic and failing, not as a
// slow pass. The correct, bypassing implementation returns almost immediately regardless of
// what the budget is doing.
func TestDummyVerifySurvivesAFullyHeldBudget(t *testing.T) {
	acquired := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withBudget(budgetKiB, budgetLanes, func() {
			close(acquired)
			<-release
		})
	}()
	// Always let the holder go and collect its result, even if this test fails early —
	// a held budget left behind poisons every test that runs after it.
	t.Cleanup(func() {
		close(release)
		if err := <-done; err != nil {
			t.Errorf("holder: withBudget: %v", err)
		}
	})
	<-acquired

	// Force a fresh mint regardless of test execution order: an earlier test in this
	// binary may already have memoised the dummy hash, and a cache hit here would not
	// exercise the path this guard exists to test.
	dummyHashMu.Lock()
	dummyHashValue = ""
	dummyHashMu.Unlock()

	call := func(which string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s DummyVerify call panicked with the budget fully held: %v "+
					"(dummyMint appears to be acquiring the budget again)", which, r)
			}
		}()
		start := time.Now()
		DummyVerify()
		t.Logf("%s DummyVerify call returned in %v", which, time.Since(start))
	}

	call("first")
	first := dummyHashValue
	if first == "" {
		t.Fatal("dummyHashValue was not set after the first call")
	}

	call("second")
	if second := dummyHashValue; second != first {
		t.Error("dummy hash changed between calls: minted twice instead of memoised")
	}
}
