package recoverykey_test

import (
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky-primitives/shamir"
)

// Indices {1,3,5}, never {1,2,3}: consecutive indices make every Lagrange coefficient 1,
// the combine degenerates to XOR, and it agrees in any field. That is how the suite's
// 0x11d/0x11b split hid.
func TestNonConsecutiveSharesRebuildTheKey(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(k, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares, want 5", len(shares))
	}
	got, err := recoverykey.Combine([]shamir.Share{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if got.Public().ID() != k.Public().ID() {
		t.Fatal("combined key has a different ID from the one that was split")
	}
}

// Shares from two different splits must be refused, not combined into a plausible key.
func TestSharesFromTwoSplitsAreRefused(t *testing.T) {
	a, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := recoverykey.Split(a, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := recoverykey.Split(b, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverykey.Combine([]shamir.Share{sa[0], sb[2]}); !errors.Is(err, shamir.ErrShareSet) {
		t.Fatalf("got %v, want ErrShareSet", err)
	}
}

// A share set that reconstructs something other than 32 bytes was never a recovery seed.
func TestCombineRefusesASecretThatIsNotASeed(t *testing.T) {
	shares, err := shamir.Split(make([]byte, 16), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverykey.Combine([]shamir.Share{shares[0], shares[2]}); !errors.Is(err, recoverykey.ErrSeedLength) {
		t.Fatalf("got %v, want ErrSeedLength", err)
	}
}

func TestSplitRefusesAnImpossibleKit(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverykey.Split(k, 1, 3); err == nil {
		t.Fatal("Split accepted threshold 1")
	}
	if _, err := recoverykey.Split(k, 4, 3); err == nil {
		t.Fatal("Split accepted threshold above total")
	}
}
