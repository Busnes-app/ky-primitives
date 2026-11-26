//go:build go1.27

package hybridsig_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/Busnes-app/ky-primitives/hybridsig"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorFile = "testdata/vectors.json"

type vectorCase struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Msg   string `json:"msg"`
	Sig   string `json:"sig"`
	Error string `json:"error,omitempty"`
}

type vectors struct {
	Comment     string       `json:"comment"`
	Alg         string       `json:"alg"`
	MLDSASeed   string       `json:"mldsa65_seed"`
	Ed25519Seed string       `json:"ed25519_seed"`
	PublicKey   string       `json:"public_key"`
	ID          string       `json:"id"`
	Valid       []vectorCase `json:"valid"`
	Invalid     []vectorCase `json:"invalid"`
}

var errNames = map[string]error{"signature": hybridsig.ErrSignature, "alg": hybridsig.ErrAlg, "label": hybridsig.ErrLabel}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// generate signs with the production (hedged) Sign; testing/cryptotest fixes its
// randomness, so a rerun on the same Go version writes the same file. Ed25519 is
// deterministic anyway. Seeds are fixed bytes, not random.
func generate(t *testing.T) vectors {
	cryptotest.SetGlobalRandom(t, 0x6d6c)
	ms, es := make([]byte, 32), make([]byte, 32)
	for i := range ms {
		ms[i], es[i] = byte(i), byte(0x80+i)
	}
	k, err := hybridsig.FromSeeds(ms, es)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public().Bytes()
	v := vectors{
		Comment: "hybridsig: tag \"mldsa65+ed25519\\x00\" || ML-DSA-65 (empty context) || Ed25519, both over " +
			"SHA-256(label || 0x00 || msg). Label is UTF-8 text, everything else hex. " +
			"Regenerate: go test ./hybridsig -run TestVectors -update",
		Alg: hybridsig.Alg, MLDSASeed: hex.EncodeToString(ms), Ed25519Seed: hex.EncodeToString(es),
		PublicKey: hex.EncodeToString(pub), ID: k.Public().ID(),
	}
	add := func(name, label string, msg []byte) []byte {
		s, err := k.Sign(label, msg)
		if err != nil {
			t.Fatal(err)
		}
		v.Valid = append(v.Valid, vectorCase{Name: name, Label: label, Msg: hex.EncodeToString(msg), Sig: hex.EncodeToString(s)})
		return s
	}
	s := add("basic", label, msg)
	add("empty message", label, nil)
	add("kyguard label", "kyguard/1/tx", msg)
	bad := func(name, label string, msg, sig []byte, e string) {
		v.Invalid = append(v.Invalid, vectorCase{Name: name, Label: label, Msg: hex.EncodeToString(msg), Sig: hex.EncodeToString(sig), Error: e})
	}
	bad("ml-dsa half flipped", label, msg, flip(s, tagLen+100), "signature")
	bad("ed25519 half flipped", label, msg, flip(s, len(s)-1), "signature")
	bad("other label", label+"x", msg, s, "signature")
	bad("other message", label, flip(msg, 0), s, "signature")
	bad("other tag", label, msg, append([]byte("mldsa87+ed25519\x00"), s[tagLen:]...), "alg")
	bad("truncated", label, msg, s[:len(s)-1], "signature")
	bad("empty label", "", msg, s, "label")
	return v
}

func TestVectors(t *testing.T) {
	if *update {
		b, err := json.MarshalIndent(generate(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	k, err := hybridsig.FromSeeds(unhex(t, v.MLDSASeed), unhex(t, v.Ed25519Seed))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k.Public().Bytes()) != v.PublicKey || k.Public().ID() != v.ID || v.Alg != hybridsig.Alg {
		t.Fatal("seeds do not derive the vector's public key and ID")
	}
	pub, err := hybridsig.ParsePublicKey(unhex(t, v.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("vector file has no cases")
	}
	for _, c := range v.Valid {
		if err := pub.Verify(c.Label, unhex(t, c.Msg), unhex(t, c.Sig)); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
	for _, c := range v.Invalid {
		want := errNames[c.Error]
		if want == nil {
			t.Fatalf("%s: unknown error %q", c.Name, c.Error)
		}
		if err := pub.Verify(c.Label, unhex(t, c.Msg), unhex(t, c.Sig)); !errors.Is(err, want) {
			t.Errorf("%s: Verify = %v, want %v", c.Name, err, want)
		}
	}
}
