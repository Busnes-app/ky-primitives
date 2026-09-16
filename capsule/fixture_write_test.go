package capsule_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// TestWriteFixture writes testdata/capsules/kycap3.kycap and its seed. It is a no-op
// unless KY_WRITE_FIXTURE=1, because a fixture that rewrites itself proves nothing.
//
// Run it once when the container format changes deliberately, and commit the result. The
// seed is committed on purpose: a golden capsule whose key is withheld cannot prove that a
// capsule written before a change still opens after it.
func TestWriteFixture(t *testing.T) {
	if os.Getenv("KY_WRITE_FIXTURE") != "1" {
		t.Skip("set KY_WRITE_FIXTURE=1 to rewrite the golden capsule")
	}
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	files := []capsule.File{
		{Path: "config.json", Content: []byte(`{"service":"fixture","version":3}` + "\n"), Mode: 0600},
		{Path: "keys/signing.key", Content: []byte("not a real key, a fixture\n"), Mode: 0600},
	}
	raw, _, err := capsule.Seal("fixture", "0.0.0", files, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "testdata", "capsules")
	if err := os.WriteFile(filepath.Join(dir, "kycap3.kycap"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kycap3.seed"), []byte(hex.EncodeToString(priv.Seed())+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
}
