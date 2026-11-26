package xwing_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/Busnes-app/ky-primitives/xwing"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorFile = "testdata/vectors.json"

type vectorCase struct {
	Name   string `json:"name"`
	Info   string `json:"info"`
	AAD    string `json:"aad"`
	Msg    string `json:"msg"`
	Sealed string `json:"sealed"`
	Error  string `json:"error,omitempty"`
}

type vectors struct {
	Comment   string       `json:"comment"`
	Seed      string       `json:"seed"`
	PublicKey string       `json:"public_key"`
	ID        string       `json:"id"`
	Valid     []vectorCase `json:"valid"`
	Invalid   []vectorCase `json:"invalid"`
}

var errNames = map[string]error{"open": xwing.ErrOpen, "version": xwing.ErrVersion, "label": xwing.ErrLabel}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// generate builds the vectors from the draft's seed, with crypto randomness fixed by
// testing/cryptotest so a rerun on the same Go version writes the same file.
func generate(t *testing.T) vectors {
	cryptotest.SetGlobalRandom(t, 0x647a)
	raw, err := os.ReadFile("../recoverykey/testdata/xwing-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var dv struct{ SkRm string }
	if err := json.Unmarshal(raw, &dv); err != nil {
		t.Fatal(err)
	}
	k, err := xwing.FromSeed(unhex(t, dv.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	v := vectors{
		Comment: "xwing.Seal: version 0x01 || enc (1120) || HPKE base ciphertext; KEM 0x647A, " +
			"HKDF-SHA256, AES-256-GCM. All fields hex. Regenerate: go test ./xwing -run TestVectors -update",
		Seed: dv.SkRm, PublicKey: hexOf(k.Public().Bytes()), ID: k.Public().ID(),
	}
	add := func(name string, info, aad, msg []byte) []byte {
		ct, err := xwing.Seal(k.Public(), info, aad, msg)
		if err != nil {
			t.Fatal(err)
		}
		v.Valid = append(v.Valid, vectorCase{name, hexOf(info), hexOf(aad), hexOf(msg), hexOf(ct), ""})
		return ct
	}
	ct := add("basic", info, aad, msg)
	add("empty aad and message", info, nil, nil)
	add("label with context", []byte("ky-primitives/xwing-test/1\x00device-7"), aad, []byte("hello"))
	bad := func(name string, info, aad, sealed []byte, e string) {
		v.Invalid = append(v.Invalid, vectorCase{Name: name, Info: hexOf(info), AAD: hexOf(aad), Sealed: hexOf(sealed), Error: e})
	}
	bad("enc byte flipped", info, aad, flip(ct, 1), "open")
	bad("ciphertext byte flipped", info, aad, flip(ct, len(ct)-1), "open")
	bad("info changed", flip(info, 0), aad, ct, "open")
	bad("aad changed", info, flip(aad, 0), ct, "open")
	bad("version 2", info, aad, append([]byte{2}, ct[1:]...), "version")
	bad("empty label", []byte("\x00ky-primitives/xwing-test/1"), aad, ct, "label")
	bad("truncated", info, aad, ct[:xwing.Overhead-1], "open")
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
	k, err := xwing.FromSeed(unhex(t, v.Seed))
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(k.Public().Bytes()) != v.PublicKey || k.Public().ID() != v.ID {
		t.Fatal("seed does not derive the vector's public key and ID")
	}
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("vector file has no cases")
	}
	for _, c := range v.Valid {
		got, err := xwing.Open(k, unhex(t, c.Info), unhex(t, c.AAD), unhex(t, c.Sealed))
		if err != nil || !bytes.Equal(got, unhex(t, c.Msg)) {
			t.Errorf("%s: Open = %x, %v", c.Name, got, err)
		}
	}
	for _, c := range v.Invalid {
		want := errNames[c.Error]
		if want == nil {
			t.Fatalf("%s: unknown error %q", c.Name, c.Error)
		}
		if _, err := xwing.Open(k, unhex(t, c.Info), unhex(t, c.AAD), unhex(t, c.Sealed)); !errors.Is(err, want) {
			t.Errorf("%s: Open err = %v, want %v", c.Name, err, want)
		}
	}
}
