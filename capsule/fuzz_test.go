package capsule

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// Open is the one function in this module that parses bytes an attacker chooses in full:
// a capsule arrives from a backup store, and the container is parsed before anything
// authenticates. It must fail, never panic, on any input at all.
func FuzzOpenNeverPanics(f *testing.F) {
	if raw, err := os.ReadFile("../testdata/capsules/kycap3.kycap"); err == nil {
		f.Add(raw)
	}
	f.Add([]byte(`{"format":"kycap/3","manifest":{},"ciphertext":"AAAA"}`))
	f.Add([]byte(`{"format":"kycap/3","manifest":{"payload_hash":"00"},"ciphertext":""}`))
	f.Add([]byte(`{"format":"kycap/1","manifest":{},"ciphertext":"AAAA"}`))
	f.Add([]byte{})

	// The fixture's key, not a random one: the seed corpus capsule was sealed to it, so it
	// and every mutation that preserves recovery_key_id walk the whole decrypt path —
	// decapsulation, the AEAD, the payload hash, extraction. A random key would stop every
	// input at the key-ID compare and fuzz only the JSON parser.
	seedHex, err := os.ReadFile("../testdata/capsules/kycap3.seed")
	if err != nil {
		f.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil {
		f.Fatal(err)
	}
	priv, err := recoverykey.FromSeed(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// No target directory: this is about the parser, and writing to disk under fuzz
		// would measure the filesystem instead.
		_, _, _ = Open(raw, priv, "")
	})
}
