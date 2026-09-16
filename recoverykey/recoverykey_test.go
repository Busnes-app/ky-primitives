package recoverykey_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func loadVector(t *testing.T) (seed, pub []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/xwing-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ SkRm, PkRm string }
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, err = hex.DecodeString(v.SkRm)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = hex.DecodeString(v.PkRm)
	if err != nil {
		t.Fatal(err)
	}
	return seed, pub
}

// The draft's vector: this seed must produce exactly this public key. If it does not, the
// KEM is not X-Wing as published, whatever the constant is called.
func TestSeedDerivesThePublishedPublicKey(t *testing.T) {
	seed, wantPub := loadVector(t)
	k, err := recoverykey.FromSeed(seed)
	if err != nil {
		t.Fatalf("FromSeed: %v", err)
	}
	if got := k.Public().Bytes(); !bytes.Equal(got, wantPub) {
		t.Fatalf("public key differs from the published vector (%d bytes)", len(got))
	}
	if got := k.Seed(); !bytes.Equal(got, seed) {
		t.Fatal("Seed() does not round-trip the seed it was built from")
	}
}

// Computed in Step 2 from the vector's bytes with sha256sum, not by this package.
func TestIDIsTheHexSHA256OfThePublicKey(t *testing.T) {
	seed, _ := loadVector(t)
	k, err := recoverykey.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	const want = "120b60e0ae3c00c1c9def1c61aeb12de710bfa49646ae6f99a7e564b25ace493"
	if got := k.Public().ID(); got != want {
		t.Fatalf("ID = %s, want %s", got, want)
	}
}

func TestParsePublicKeyRoundTrips(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p, err := recoverykey.ParsePublicKey(k.Public().Bytes())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if p.ID() != k.Public().ID() {
		t.Fatal("parsed public key has a different ID")
	}
}

func TestGenerateIsNotDeterministic(t *testing.T) {
	a, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Public().ID() == b.Public().ID() {
		t.Fatal("two Generate calls produced the same key")
	}
}

func TestFromSeedRefusesEveryLengthButThirtyTwo(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := recoverykey.FromSeed(make([]byte, n)); !errors.Is(err, recoverykey.ErrSeedLength) {
			t.Errorf("FromSeed(%d bytes) = %v, want ErrSeedLength", n, err)
		}
	}
}

func TestParsePublicKeyRefusesEveryLengthButTwelveSixteen(t *testing.T) {
	for _, n := range []int{0, 32, 1215, 1217} {
		if _, err := recoverykey.ParsePublicKey(make([]byte, n)); !errors.Is(err, recoverykey.ErrPublicKeyLength) {
			t.Errorf("ParsePublicKey(%d bytes) = %v, want ErrPublicKeyLength", n, err)
		}
	}
}

// Bytes and Seed return copies. A caller zeroing its copy must not zero the key.
func TestAccessorsReturnCopies(t *testing.T) {
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := k.Seed()
	for i := range s {
		s[i] = 0
	}
	if bytes.Equal(k.Seed(), s) {
		t.Fatal("Seed() returned the internal buffer")
	}
	b := k.Public().Bytes()
	for i := range b {
		b[i] = 0
	}
	if bytes.Equal(k.Public().Bytes(), b) {
		t.Fatal("Bytes() returned the internal buffer")
	}
}

func TestZeroValueKeysAreRefusedNotSplit(t *testing.T) {
	var priv recoverykey.PrivateKey
	var pub recoverykey.PublicKey
	if !priv.IsZero() || !pub.IsZero() {
		t.Fatal("zero values report IsZero() == false")
	}
	if _, err := recoverykey.Split(priv, 2, 3); !errors.Is(err, recoverykey.ErrUninitializedKey) {
		t.Fatalf("Split of a zero key gave %v, want ErrUninitializedKey", err)
	}
	// Accessors on a zero value must not panic.
	if priv.Public().ID() != "" || pub.ID() != "" || pub.Bytes() != nil || priv.HPKE() != nil || pub.HPKE() != nil {
		t.Fatal("zero-value accessors returned non-empty results")
	}
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if k.IsZero() || k.Public().IsZero() {
		t.Fatal("a generated key reports IsZero() == true")
	}
}
