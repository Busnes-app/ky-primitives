package capsule_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
)

func TestSealOpenRoundTrip(t *testing.T) {
	want := []capsule.File{
		{Path: "config.json", Content: []byte(`{"a":1}`), Mode: 0600},
		{Path: "keys/signing.pem", Content: bytes.Repeat([]byte("k"), 4096), Mode: 0600},
	}

	priv := testRecoveryKey(t)
	raw, _, err := capsule.Seal("fixture", "0.0.0", want, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "restore")
	_, got, err := capsule.Open(raw, priv, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Path != want[i].Path {
			t.Errorf("file %d: path %q, want %q", i, got[i].Path, want[i].Path)
		}
		if !bytes.Equal(got[i].Content, want[i].Content) {
			t.Errorf("file %d (%s): content differs", i, want[i].Path)
		}
		onDisk, err := os.ReadFile(filepath.Join(dir, want[i].Path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(onDisk, want[i].Content) {
			t.Errorf("file %d (%s): on-disk content differs", i, want[i].Path)
		}
	}
}

// kycap/3 binds the manifest into the AEAD, and is the only container this package knows.
func TestSealWritesKycap3(t *testing.T) {
	priv := testRecoveryKey(t)
	raw, _, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Format     string `json:"format"`
		Ciphertext string `json:"ciphertext"`
		Manifest   struct {
			PayloadHash string `json:"payload_hash"`
			Threshold   int    `json:"threshold"`
			TotalShares int    `json:"total_shares"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Seal did not write JSON: %v", err)
	}
	if got.Format != capsule.KycapFileFormat {
		t.Errorf("format %q, want %q", got.Format, capsule.KycapFileFormat)
	}
	if got.Manifest.PayloadHash == "" {
		t.Error("manifest carries no payload hash")
	}
	if got.Manifest.Threshold != 2 || got.Manifest.TotalShares != 3 {
		t.Errorf("threshold/shares %d/%d, want 2/3", got.Manifest.Threshold, got.Manifest.TotalShares)
	}
	// Standard base64 is padded to a multiple of four and never contains '-' or '_'.
	if len(got.Ciphertext)%4 != 0 {
		t.Errorf("ciphertext is not padded standard base64: len %d", len(got.Ciphertext))
	}
}

func TestSealRefusesEmptyCapsule(t *testing.T) {
	priv := testRecoveryKey(t)
	if _, _, err := capsule.Seal("x", "0", nil, nil, nil, 2, 3, priv.Public()); err == nil {
		t.Fatal("sealed a capsule with no files")
	}
}

// Seal enforces the same containment Open does, so it can never write a capsule this
// package would then refuse to extract.
func TestSealRefusesUnsafePaths(t *testing.T) {
	priv := testRecoveryKey(t)
	for _, p := range []string{"../escape.txt", "/etc/passwd", ".."} {
		if _, _, err := capsule.Seal("x", "0",
			[]capsule.File{{Path: p, Content: []byte("x"), Mode: 0600}}, nil, nil, 2, 3, priv.Public()); err == nil {
			t.Errorf("sealed a capsule containing %q", p)
		}
	}
}

// Seal's third return is the manifest that went into the AEAD, not a second construction
// of it: re-encoding it reproduces the container's manifest bytes exactly, and those bytes
// are the AAD. gridlock-server used to read CapsuleID, CreatedAt and PayloadHash back out
// of its own output through ReadUnverifiedManifest — the keyless reader whose doc comment
// says not to decide on what it returns — because Seal did not hand them back.
func TestSealReturnsTheManifestItSealed(t *testing.T) {
	files := []capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}
	priv := testRecoveryKey(t)

	raw, m, err := capsule.Seal("fixture", "0.0.0", files, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	var container struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(m.UnverifiedManifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, container.Manifest) {
		t.Fatalf("Seal returned a manifest that is not the sealed one:\n got %s\nwant %s", got, container.Manifest)
	}

	// And Open, the only other producer of a Manifest, agrees on the fields Seal alone
	// mints. A caller has no other source for these.
	opened, _, err := capsule.Open(raw, priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if opened.CapsuleID != m.CapsuleID || opened.PayloadHash != m.PayloadHash || !opened.CreatedAt.Equal(m.CreatedAt) {
		t.Fatalf("Open disagrees with Seal: %+v vs %+v", opened.UnverifiedManifest, m.UnverifiedManifest)
	}
	if opened.Threshold != m.Threshold || opened.TotalShares != m.TotalShares {
		t.Fatalf("Open reports %d-of-%d, Seal returned %d-of-%d",
			opened.Threshold, opened.TotalShares, m.Threshold, m.TotalShares)
	}
}
