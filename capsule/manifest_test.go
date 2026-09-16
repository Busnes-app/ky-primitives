package capsule_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
)

func TestReadUnverifiedManifestNeedsNoKey(t *testing.T) {
	priv := testRecoveryKey(t)
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, _, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5, priv.Public())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatalf("ReadUnverifiedManifest: %v", err)
	}
	if got.ServiceName != "kyrecovery" {
		t.Errorf("ServiceName = %q, want %q", got.ServiceName, "kyrecovery")
	}
	if got.AppVersion != "2.1" {
		t.Errorf("AppVersion = %q, want %q", got.AppVersion, "2.1")
	}
	if got.Threshold != 3 || got.TotalShares != 5 {
		t.Errorf("kit = %d-of-%d, want 3-of-5", got.Threshold, got.TotalShares)
	}
	if got.CapsuleID == "" {
		t.Error("CapsuleID is empty")
	}
}

// The emptiness check lived in decryptPayload, so a container with a manifest and no
// ciphertext parsed cleanly on the keyless path: a caller displaying only the manifest saw
// a valid-looking capsule Open would refuse.
func TestBothPathsRefuseACiphertextLessContainer(t *testing.T) {
	priv := testRecoveryKey(t)
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, _, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5, priv.Public())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var cf map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	cf["ciphertext"] = json.RawMessage(`""`)
	stripped, err := json.Marshal(cf)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := capsule.ReadUnverifiedManifest(stripped); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Errorf("ReadUnverifiedManifest got %v, want ErrCorruptCapsule", err)
	}
	if _, _, err := capsule.Open(stripped, priv, ""); !errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Errorf("Open got %v, want ErrCorruptCapsule", err)
	}
}

// The manifest read without a key is unauthenticated: anyone who can reach the file can
// rewrite it. This test is the reason the two types are distinct — it demonstrates the
// rewrite, so the type boundary is not merely decorative.
func TestUnverifiedManifestIsRewritableWithoutTheKey(t *testing.T) {
	priv := testRecoveryKey(t)
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, _, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5, priv.Public())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal container: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc["manifest"], &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	m["threshold"] = 1
	m["total_shares"] = 1
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	doc["manifest"] = tampered
	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("remarshal container: %v", err)
	}

	// The unverified read believes the forgery. That is its nature.
	got, err := capsule.ReadUnverifiedManifest(forged)
	if err != nil {
		t.Fatalf("ReadUnverifiedManifest: %v", err)
	}
	if got.Threshold != 1 {
		t.Fatalf("Threshold = %d, want the forged 1", got.Threshold)
	}

	// Open does not. This is the line that makes the type split worth having.
	if _, _, err := capsule.Open(forged, priv, ""); err == nil {
		t.Fatal("Open accepted a rewritten manifest")
	}
}

func TestManifestRecordsEveryFile(t *testing.T) {
	files := []capsule.File{
		{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600},
		{Path: "keys/signing.key", Content: []byte("secret"), Mode: 0o400},
	}
	priv := testRecoveryKey(t)
	raw, _, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	m, _, err := capsule.Open(raw, priv, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(m.Files) != 2 {
		t.Fatalf("Files = %d entries, want 2", len(m.Files))
	}

	// sha256("payload"), computed independently of this package.
	const wantSum = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	byPath := map[string]capsule.FileEntry{}
	for _, e := range m.Files {
		byPath[e.Path] = e
	}
	got := byPath["db.sqlite"]
	if got.Sum != wantSum {
		t.Errorf("db.sqlite Sum = %q, want %q", got.Sum, wantSum)
	}
	if got.Size != 7 {
		t.Errorf("db.sqlite Size = %d, want 7", got.Size)
	}
	if byPath["keys/signing.key"].Mode != 0o400 {
		t.Errorf("signing.key Mode = %v, want 0400", byPath["keys/signing.key"].Mode)
	}
}
