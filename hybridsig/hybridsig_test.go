//go:build go1.27

package hybridsig_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/hybridsig"
)

const label = "ky-primitives/hybridsig-test/1"

var msg = []byte(`{"op":"grant","to":"alice"}`)

func newKey(t *testing.T) *hybridsig.PrivateKey {
	t.Helper()
	k, err := hybridsig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, k *hybridsig.PrivateKey) []byte {
	t.Helper()
	s, err := k.Sign(label, msg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 0x01
	return c
}

// tagLen is len("mldsa65+ed25519\x00"), where both halves start.
const tagLen = len(hybridsig.Alg) + 1

func TestSignVerify(t *testing.T) {
	k := newKey(t)
	s := sign(t, k)
	if len(s) != hybridsig.SignatureBytes || len(k.Public().Bytes()) != hybridsig.PublicKeyBytes {
		t.Fatalf("sizes %d, %d", len(s), len(k.Public().Bytes()))
	}
	if err := k.Public().Verify(label, msg, s); err != nil {
		t.Fatal(err)
	}
}

// Each half alone is not enough: a signature with a valid ML-DSA half and a broken Ed25519
// half fails, and the other way round.
func TestBothHalvesMustVerify(t *testing.T) {
	k := newKey(t)
	s := sign(t, k)
	other := sign(t, newKey(t))
	mlEnd := tagLen + mldsa.MLDSA65SignatureSize
	cases := map[string][]byte{
		"ml-dsa byte flipped":  flip(s, tagLen+100),
		"ml-dsa from another":  append(bytes.Clone(other[:mlEnd]), s[mlEnd:]...),
		"ed25519 byte flipped": flip(s, len(s)-1),
		"ed25519 from another": append(bytes.Clone(s[:mlEnd]), other[mlEnd:]...),
		"truncated":            s[:len(s)-1],
	}
	for name, sig := range cases {
		if err := k.Public().Verify(label, msg, sig); !errors.Is(err, hybridsig.ErrSignature) {
			t.Errorf("%s: Verify = %v", name, err)
		}
	}
}

func TestVerifyRefusesAnotherAlgorithmTag(t *testing.T) {
	k := newKey(t)
	s := sign(t, k)
	for _, alg := range []string{"mldsa87+ed25519", "ed25519+mldsa65", "MLDSA65+ED25519"} {
		sig := append([]byte(alg+"\x00"), s[tagLen:]...)
		if err := k.Public().Verify(label, msg, sig); !errors.Is(err, hybridsig.ErrAlg) {
			t.Errorf("signature tag %q: Verify = %v", alg, err)
		}
		pub := append([]byte(alg+"\x00"), k.Public().Bytes()[tagLen:]...)
		if _, err := hybridsig.ParsePublicKey(pub); !errors.Is(err, hybridsig.ErrAlg) {
			t.Errorf("public key tag %q: ParsePublicKey = %v", alg, err)
		}
	}
}

func TestLabelAndMessageAreBound(t *testing.T) {
	k := newKey(t)
	s := sign(t, k)
	if err := k.Public().Verify(label+"x", msg, s); !errors.Is(err, hybridsig.ErrSignature) {
		t.Errorf("other label: %v", err)
	}
	if err := k.Public().Verify(label, flip(msg, 0), s); !errors.Is(err, hybridsig.ErrSignature) {
		t.Errorf("other message: %v", err)
	}
	if err := newKey(t).Public().Verify(label, msg, s); !errors.Is(err, hybridsig.ErrSignature) {
		t.Errorf("other key: %v", err)
	}
	for _, bad := range []string{"", "a\x00b"} {
		if _, err := k.Sign(bad, msg); !errors.Is(err, hybridsig.ErrLabel) {
			t.Errorf("Sign(%q) = %v", bad, err)
		}
		if err := k.Public().Verify(bad, msg, s); !errors.Is(err, hybridsig.ErrLabel) {
			t.Errorf("Verify(%q) = %v", bad, err)
		}
	}
}

func TestKeyEncodings(t *testing.T) {
	k := newKey(t)
	ms, es := k.Seeds()
	k2, err := hybridsig.FromSeeds(ms, es)
	if err != nil || !bytes.Equal(k2.Public().Bytes(), k.Public().Bytes()) {
		t.Fatalf("FromSeeds(Seeds()) differs: %v", err)
	}
	p, err := hybridsig.ParsePublicKey(k.Public().Bytes())
	if err != nil || p.ID() != k.Public().ID() {
		t.Fatalf("ParsePublicKey round trip: %v", err)
	}
	if err := p.Verify(label, msg, sign(t, k2)); err != nil {
		t.Fatal(err)
	}
	if _, err := hybridsig.FromSeeds(ms[:31], es); !errors.Is(err, hybridsig.ErrLength) {
		t.Fatal(err)
	}
	if _, err := hybridsig.ParsePublicKey(k.Public().Bytes()[1:]); !errors.Is(err, hybridsig.ErrAlg) {
		t.Fatal(err)
	}
	if _, err := hybridsig.ParsePublicKey(k.Public().Bytes()[:hybridsig.PublicKeyBytes-1]); !errors.Is(err, hybridsig.ErrLength) {
		t.Fatal(err)
	}
	var zero *hybridsig.PublicKey
	if zero.Bytes() != nil || zero.ID() != "" || !errors.Is(zero.Verify(label, msg, nil), hybridsig.ErrUninitializedKey) {
		t.Fatal("nil public key is usable")
	}
	if _, err := (&hybridsig.PrivateKey{}).Sign(label, msg); !errors.Is(err, hybridsig.ErrUninitializedKey) {
		t.Fatal(err)
	}
}

// kyguard-server internal/pqcrypto (sig.go @ 37b302b) signs D = SHA-256("kyguard/1/<type>"
// ‖ 0x00 ‖ JCS) with ML-DSA-65 (empty context) and Ed25519. Its halves, built here the way
// kyguard builds them, verify through this package, so kyguard can import it unchanged.
func TestKyguardConstructionVerifies(t *testing.T) {
	k := newKey(t)
	ms, es := k.Seeds()
	m, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), ms)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("kyguard/1/tx"))
	h.Write([]byte{0})
	h.Write(msg)
	d := h.Sum(nil)
	mSig, err := m.Sign(nil, d, &mldsa.Options{Context: ""})
	if err != nil {
		t.Fatal(err)
	}
	sig := append(append([]byte(hybridsig.Alg+"\x00"), mSig...), ed25519.Sign(ed25519.NewKeyFromSeed(es), d)...)
	if err := k.Public().Verify("kyguard/1/tx", msg, sig); err != nil {
		t.Fatalf("kyguard-built signature: %v", err)
	}
}
