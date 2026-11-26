package xwing_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky-primitives/xwing"
)

var (
	info = []byte("ky-primitives/xwing-test/1")
	aad  = []byte("record 42")
	msg  = []byte("a 32-byte data encryption key...")
)

func newKey(t *testing.T) xwing.PrivateKey {
	t.Helper()
	k, err := xwing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, k xwing.PrivateKey) []byte {
	t.Helper()
	ct, err := xwing.Seal(k.Public(), info, aad, msg)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := newKey(t)
	ct := seal(t, k)
	if len(ct) != xwing.Overhead+len(msg) || ct[0] != xwing.Version {
		t.Fatalf("sealed length %d, version %d", len(ct), ct[0])
	}
	got, err := xwing.Open(k, info, aad, ct)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// nil and empty aad/msg are the same thing.
	ct, err = xwing.Seal(k.Public(), info, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := xwing.Open(k, info, []byte{}, ct); err != nil || len(got) != 0 {
		t.Fatalf("empty Open = %q, %v", got, err)
	}
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 0x01
	return c
}

// Each part of the message, and each input the sender bound, must be needed to open it.
func TestOpenRefusesAnyChange(t *testing.T) {
	k := newKey(t)
	ct := seal(t, k)
	cases := map[string]struct {
		info, aad, ct []byte
		want          error
	}{
		"enc first byte": {info, aad, flip(ct, 1), xwing.ErrOpen},
		"enc last byte":  {info, aad, flip(ct, xwing.EncapsulationBytes), xwing.ErrOpen},
		"ct first byte":  {info, aad, flip(ct, 1+xwing.EncapsulationBytes), xwing.ErrOpen},
		"ct tag":         {info, aad, flip(ct, len(ct)-1), xwing.ErrOpen},
		"info":           {flip(info, len(info)-1), aad, ct, xwing.ErrOpen},
		"info context":   {append(bytes.Clone(info), 0, 'x'), aad, ct, xwing.ErrOpen},
		"aad":            {info, flip(aad, 0), ct, xwing.ErrOpen},
		"aad dropped":    {info, nil, ct, xwing.ErrOpen},
		"version 0":      {info, aad, append([]byte{0}, ct[1:]...), xwing.ErrVersion},
		"version 2":      {info, aad, append([]byte{2}, ct[1:]...), xwing.ErrVersion},
		"truncated":      {info, aad, ct[:xwing.Overhead-1], xwing.ErrOpen},
		"empty":          {info, aad, nil, xwing.ErrVersion},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := xwing.Open(k, c.info, c.aad, c.ct)
			if !errors.Is(err, c.want) || got != nil {
				t.Fatalf("Open = %q, %v; want %v", got, err, c.want)
			}
		})
	}
	other := newKey(t)
	if _, err := xwing.Open(other, info, aad, ct); !errors.Is(err, xwing.ErrOpen) {
		t.Fatalf("other key: %v", err)
	}
}

func TestEmptyLabelIsRefused(t *testing.T) {
	k := newKey(t)
	ct := seal(t, k)
	for _, bad := range [][]byte{nil, {}, {0}, []byte("\x00context")} {
		if _, err := xwing.Seal(k.Public(), bad, aad, msg); !errors.Is(err, xwing.ErrLabel) {
			t.Errorf("Seal(info=%q) = %v", bad, err)
		}
		if _, err := xwing.Open(k, bad, aad, ct); !errors.Is(err, xwing.ErrLabel) {
			t.Errorf("Open(info=%q) = %v", bad, err)
		}
	}
}

func TestZeroKeysAreRefused(t *testing.T) {
	if _, err := xwing.Seal(xwing.PublicKey{}, info, aad, msg); !errors.Is(err, xwing.ErrUninitializedKey) {
		t.Fatal(err)
	}
	if _, err := xwing.Open(xwing.PrivateKey{}, info, aad, []byte{1}); !errors.Is(err, xwing.ErrUninitializedKey) {
		t.Fatal(err)
	}
	var z xwing.PrivateKey
	if z.Public().Bytes() != nil || z.Public().ID() != "" {
		t.Fatal("zero key has bytes or an ID")
	}
}

func TestKeyEncodings(t *testing.T) {
	if _, err := xwing.FromSeed(make([]byte, 31)); !errors.Is(err, xwing.ErrSeedLength) {
		t.Fatal(err)
	}
	if _, err := xwing.ParsePublicKey(make([]byte, 1215)); !errors.Is(err, xwing.ErrPublicKeyLength) {
		t.Fatal(err)
	}
	k := newKey(t)
	k2, err := xwing.FromSeed(k.Seed())
	if err != nil || !bytes.Equal(k2.Public().Bytes(), k.Public().Bytes()) {
		t.Fatalf("FromSeed(Seed()) differs: %v", err)
	}
	p, err := xwing.ParsePublicKey(k.Public().Bytes())
	if err != nil || p.ID() != k.Public().ID() {
		t.Fatalf("ParsePublicKey round trip: %v", err)
	}
}

// The keypair is recoverykey's: the draft vector's seed gives the draft's public key, and a
// message sealed to a recoverykey public key opens with the same seed here. Only the ID
// differs, by its domain label, so an xwing ID never collides with a capsule's key name.
func TestSameKeypairAsRecoverykey(t *testing.T) {
	raw, err := os.ReadFile("../recoverykey/testdata/xwing-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ SkRm, PkRm string }
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.SkRm)
	k, err := xwing.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k.Public().Bytes()) != v.PkRm {
		t.Fatal("seed does not derive the draft vector's public key")
	}
	rk, err := recoverykey.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := xwing.ParsePublicKey(rk.Public().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ct, err := xwing.Seal(pub, info, aad, msg)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := xwing.Open(k, info, aad, ct); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if k.Public().ID() == rk.Public().ID() {
		t.Fatal("xwing ID is not domain-separated from recoverykey's")
	}
	// Computed outside Go: python3 hashlib.sha256(b"ky/xwing/1/key-id\0" + pk).
	const wantID = "4df307c512cf9401df76b9158f66bf6ae9091144ac2003ae92ae207241d08cce"
	if got := k.Public().ID(); got != wantID {
		t.Fatalf("ID = %s, want %s", got, wantID)
	}
}
