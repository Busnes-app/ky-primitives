package shamir

import (
	"bytes"
	"errors"
	"testing"
)

const secret = "MASTER-KEY-0123456789abcdef01234"

// pick returns the shares at the given 1-based indices.
func pick(t *testing.T, shares []Share, want ...byte) []Share {
	t.Helper()
	var out []Share
	for _, idx := range want {
		for _, s := range shares {
			if s.Index == idx {
				out = append(out, s)
			}
		}
	}
	if len(out) != len(want) {
		t.Fatalf("wanted indices %v, found %d shares", want, len(out))
	}
	return out
}

// TestRoundTripEveryIndexSubset is the test the suite's implementations never had. A
// share set combines correctly for every subset, not just the consecutive one that makes
// every Lagrange coefficient 1 and hides a wrong field.
func TestRoundTripEveryIndexSubset(t *testing.T) {
	shares, err := Split([]byte(secret), 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	subsets := [][]byte{
		{1, 2, 3}, {1, 2, 4}, {1, 3, 5}, {2, 3, 4}, {3, 4, 5},
		{1, 4, 5}, {2, 4, 5}, {1, 2, 5}, {1, 3, 4}, {2, 3, 5},
	}
	for _, sub := range subsets {
		got, err := Combine(pick(t, shares, sub...))
		if err != nil {
			t.Errorf("indices %v: %v", sub, err)
			continue
		}
		if !bytes.Equal(got, []byte(secret)) {
			t.Errorf("indices %v: got %q, want %q", sub, got, secret)
		}
	}
}

func TestCombineAcceptsMoreSharesThanThreshold(t *testing.T) {
	shares, err := Split([]byte(secret), 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(shares)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(secret)) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestSplitRejectsBadParameters(t *testing.T) {
	for _, tc := range []struct {
		name             string
		secret           string
		threshold, total int
	}{
		{"threshold below two", secret, 1, 5},
		{"threshold above total", secret, 6, 5},
		{"total above 255", secret, 2, 256},
		{"empty secret", "", 2, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Split([]byte(tc.secret), tc.threshold, tc.total); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestRejectsOversizedSecretsAndShares(t *testing.T) {
	tooLarge := make([]byte, MaxSecretBytes+1)
	if _, err := Split(tooLarge, 2, 2); err == nil {
		t.Fatal("oversized secret was accepted")
	}
	shares := []Share{
		{Threshold: 2, Index: 1, Value: tooLarge},
		{Threshold: 2, Index: 2, Value: tooLarge},
	}
	if _, err := Combine(shares); !errors.Is(err, ErrShareLength) {
		t.Fatalf("oversized shares: got %v, want ErrShareLength", err)
	}
}

// The three 0x11d implementations panic here. A custodian retrying a shard mid-disaster
// must get an error, never a stack trace.
func TestCombineRejectsDuplicateIndex(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Combine([]Share{shares[0], shares[0]})
	if !errors.Is(err, ErrDuplicateIndex) {
		t.Fatalf("got %v, want ErrDuplicateIndex", err)
	}
}

func TestCombineRejectsMismatchedLengths(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	short := shares[1]
	short.Value = short.Value[:4]
	_, err = Combine([]Share{shares[0], short})
	if !errors.Is(err, ErrShareLength) {
		t.Fatalf("got %v, want ErrShareLength", err)
	}
}

// Index 0 is where the secret itself sits. The 0x11d implementations accept it and
// return an all-zero secret with a nil error.
func TestCombineRejectsZeroIndex(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	zero := shares[1]
	zero.Index = 0
	_, err = Combine([]Share{zero, shares[0]})
	if !errors.Is(err, ErrShareIndex) {
		t.Fatalf("got %v, want ErrShareIndex", err)
	}
}

func TestCombineRejectsTooFewShares(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Combine(shares[:1]); !errors.Is(err, ErrNotEnoughShares) {
		t.Fatalf("got %v, want ErrNotEnoughShares", err)
	}
	if _, err := Combine(nil); !errors.Is(err, ErrNotEnoughShares) {
		t.Fatalf("got %v, want ErrNotEnoughShares", err)
	}
}

// Fewer than threshold shares must leave every value of a secret byte possible. Split
// once resampled a zero leading coefficient, so threshold-1 shares never interpolated to
// the true secret byte at x=0 and ruled that value out. Interpolating threshold-1 shares
// gives secret - c*prod(x_i) for leading coefficient c, so it must hit all 256 values,
// the secret included.
func TestBelowThresholdSharesExcludeNoSecretValue(t *testing.T) {
	const secretByte = 0x42
	for _, threshold := range []int{2, 3} {
		shares, err := Split(bytes.Repeat([]byte{secretByte}, 1<<16), threshold, threshold)
		if err != nil {
			t.Fatal(err)
		}
		guess := shares[0].Value
		if threshold > 2 {
			// Combine refuses a set below its declared threshold, so declare it lower.
			below := make([]Share, threshold-1)
			for i := range below {
				below[i] = shares[i]
				below[i].Threshold = threshold - 1
			}
			if guess, err = Combine(below); err != nil {
				t.Fatal(err)
			}
		}
		var seen [256]bool
		for _, b := range guess {
			seen[b] = true
		}
		for v, ok := range seen {
			if !ok {
				// 2^16 uniform draws miss a value with probability about 256*e^-256.
				t.Fatalf("threshold %d: %d-share interpolation never yields %#x", threshold, threshold-1, v)
			}
		}
	}
}

// Shares from the Split that resampled leading coefficients. The format is unchanged,
// so they must still combine.
func TestCombinesSharesFromResamplingSplit(t *testing.T) {
	cards := []string{
		"ky2-3-137ae1b44e57c89d38dc887bf832efeb-1-f6cb04aa3d943ac63ffeb6ab830c3998b58c4710eb4170eb710e82ead9972257-a674",
		"ky2-3-137ae1b44e57c89d38dc887bf832efeb-2-9470417ab13f8266e3ce624d71f494fae9c5467809858011481ee9e6cbb3b02c-ae31",
		"ky2-3-137ae1b44e57c89d38dc887bf832efeb-3-2ffa1684c9f995eb9969f9d6c3ca9e56697f3650dba592995d750d3c2316a14f-d858",
		"ky2-3-137ae1b44e57c89d38dc887bf832efeb-4-02dbb101a64d5aa1414920914d7b9cb1a78da7f853148878241108781a469c51-f99f",
		"ky2-3-137ae1b44e57c89d38dc887bf832efeb-5-b951e6ffde8b4d2c3beebb0aff45961d2737d7d081349af0317aeca2f2e38d32-c863",
	}
	var all []Share
	for _, c := range cards {
		s, err := ParseShare(c)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, s)
	}
	for _, sub := range [][]byte{{1, 2, 3}, {1, 3, 5}, {2, 4, 5}, {3, 4, 5}, {1, 2, 3, 4, 5}} {
		got, err := Combine(pick(t, all, sub...))
		if err != nil {
			t.Fatalf("%v: %v", sub, err)
		}
		if string(got) != secret {
			t.Fatalf("%v: got %q, want %q", sub, got, secret)
		}
	}
}

func TestShareStringRoundTrip(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range shares {
		got, err := ParseShare(want.String())
		if err != nil {
			t.Fatalf("%q: %v", want.String(), err)
		}
		if got.Index != want.Index || !bytes.Equal(got.Value, want.Value) {
			t.Fatalf("round trip changed share %d", want.Index)
		}
	}
}

func TestParseShareRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"", "1", "1-", "-ff", "0-ffff", "zz-ffff", "1-fff", "1-zzzz", "256-ffff", "1-ffff-2",
		"ky1-2-a1b2c3d4-0-ffff-0000", "ky1-2-a1b2c3d4-1-zz-0000", "ky1-1-a1b2c3d4-1-ffff-0000",
	} {
		if _, err := ParseShare(in); err == nil {
			t.Errorf("ParseShare(%q) = nil error, want one", in)
		}
	}
}

// Surrounding space is forgiven because a custodian types this off a card. Case is not:
// the checksum covers the exact bytes, so folding case would mean either ignoring the
// checksum or recomputing it over something the card does not say.
func TestParseShareAcceptsSurroundingSpace(t *testing.T) {
	want := Share{Threshold: 2, SetID: [16]byte{12: 0xa1, 13: 0xb2, 14: 0xc3, 15: 0xd4}, Index: 2, Value: []byte{0xa1, 0xb2}}
	got, err := ParseShare("  " + want.String() + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Split must not hand back aliased buffers; a caller zeroing one share must not blank
// the others.
func TestSplitSharesDoNotAlias(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := range shares[0].Value {
		shares[0].Value[i] = 0
	}
	if bytes.Equal(shares[1].Value, shares[2].Value) {
		t.Fatal("shares alias one another")
	}
}

func TestGoldenVectors(t *testing.T) {
	// Derived by hand, not read off this implementation. f(x) = 0x01 + 0xb2*x over
	// GF(2^8) mod 0x11b:
	//   f(1) = 0x01 ^ 0xb2                  = 0xb3
	//   f(2) = 0x01 ^ (0xb2*2 = 0x7f)       = 0x7e
	//   f(3) = 0x01 ^ (0x7f ^ 0xb2 = 0xcd)  = 0xcc
	// Pins the reduction polynomial. Change the field and this fails, which is the
	// point: every custodian card already printed would become unreadable.
	// Threshold is declared because Combine requires every share to carry one; the
	// polynomial above is degree 1, so two shares reconstruct it.
	full := []Share{
		{Threshold: 2, Index: 1, Value: []byte{0xb3}},
		{Threshold: 2, Index: 2, Value: []byte{0x7e}},
		{Threshold: 2, Index: 3, Value: []byte{0xcc}},
	}
	for _, sub := range [][]int{{0, 1}, {0, 2}, {1, 2}, {0, 1, 2}} {
		var shares []Share
		for _, i := range sub {
			shares = append(shares, full[i])
		}
		got, err := Combine(shares)
		if err != nil {
			t.Fatalf("%v: %v", sub, err)
		}
		if want := []byte{0x01}; !bytes.Equal(got, want) {
			t.Fatalf("%v: got %x, want %x", sub, got, want)
		}
	}
}
