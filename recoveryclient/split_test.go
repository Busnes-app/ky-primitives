package recoveryclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func lowerSplit(t *testing.T, n int) {
	old := splitPartBytes
	splitPartBytes = n
	t.Cleanup(func() { splitPartBytes = old })
}

// bigPayload is testPayload with a database that needs three parts at 8-byte parts.
func bigPayload() (Payload, []byte) {
	db := []byte("SQLite format 3\x00 a database past one member")[:20]
	p := testPayload()
	p.Files = append(SplitFile(File{Path: "data/app.db", Data: db, Mode: 0600}), p.Files[1:]...)
	return p, db
}

func TestSplitFileLeavesAFileThatFitsAlone(t *testing.T) {
	f := File{Path: "data/app.db", Data: []byte("small"), Mode: 0600}
	if got := SplitFile(f); len(got) != 1 || got[0].Path != f.Path || !bytes.Equal(got[0].Data, f.Data) {
		t.Fatalf("%+v", got)
	}
}

func TestSplitFileNamesOrderedParts(t *testing.T) {
	lowerSplit(t, 8)
	p, db := bigPayload()
	want := []string{"data/app.db.000-of-003", "data/app.db.001-of-003", "data/app.db.002-of-003"}
	var joined []byte
	for i, w := range want {
		if p.Files[i].Path != w || p.Files[i].Mode != 0600 || len(p.Files[i].Data) > 8 {
			t.Fatalf("part %d: %+v", i, p.Files[i])
		}
		joined = append(joined, p.Files[i].Data...)
	}
	if !bytes.Equal(joined, db) {
		t.Fatalf("parts do not add up: %q", joined)
	}
}

func TestSplitDatabaseRestoresAndJoins(t *testing.T) {
	lowerSplit(t, 8)
	p, db := bigPayload()
	priv, k := testKey(t)
	shares, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := Seal(p, k)
	if err != nil {
		t.Fatal(err)
	}
	capsulePath := filepath.Join(t.TempDir(), "x.kycap")
	if err := os.WriteFile(capsulePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "out")
	if err := Restore(capsulePath, target, "Svc", []string{shares[0].String(), shares[2].String()}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(target, "data", "app.db"))
	if err != nil || !bytes.Equal(got, db) {
		t.Fatalf("joined database %q, %v", got, err)
	}
	if info, _ := os.Stat(filepath.Join(target, "data", "app.db")); info.Mode().Perm() != 0600 {
		t.Errorf("mode %v", info.Mode())
	}
	entries, _ := os.ReadDir(filepath.Join(target, "data"))
	if len(entries) != 2 {
		t.Errorf("parts or scratch left behind: %v", entries)
	}
}

func TestSplitDatabaseDrills(t *testing.T) {
	lowerSplit(t, 8)
	p, db := bigPayload()
	res, err := Drill(context.Background(), t.TempDir(), p, func(dir string, _ capsule.Manifest) []Check {
		got, err := os.ReadFile(filepath.Join(dir, "data", "app.db"))
		_, part := os.Stat(filepath.Join(dir, "data", "app.db.000-of-003"))
		return []Check{{Name: "db", Passed: err == nil && bytes.Equal(got, db) && os.IsNotExist(part)}}
	})
	if err != nil || !res.Passed {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestJoinWithoutPartsChangesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app.db", "app.db.bak", "app.db.000", "notes.sqlite.001", "archive.000-of-001"} {
		if err := os.WriteFile(filepath.Join(dir, "data", name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := joinSplitFiles(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "data"))
	if got, _ := os.ReadFile(filepath.Join(dir, "data", "app.db")); string(got) != "app.db" || len(entries) != 5 {
		t.Fatalf("directory changed: %q %v", got, entries)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "archive.000-of-001")); err != nil {
		t.Fatalf("a lone one-part name was treated as a split: %v", err)
	}
}

func TestJoinRefusesPartsThatDoNotAddUp(t *testing.T) {
	for name, files := range map[string][]string{
		"missing part":      {"app.db.000-of-003", "app.db.002-of-003"},
		"missing last part": {"app.db.000-of-003", "app.db.001-of-003"},
		"mixed counts":      {"app.db.000-of-002", "app.db.001-of-003"},
		"beside whole":      {"app.db", "app.db.000-of-002", "app.db.001-of-002"},
		"renumbered":        {"app.db.001-of-002", "app.db.002-of-002"},
		"extra part":        {"app.db.000-of-002", "app.db.001-of-002", "app.db.002-of-002"},
	} {
		dir := t.TempDir()
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := joinSplitFiles(dir); !errors.Is(err, ErrSplitParts) {
			t.Errorf("%s: want ErrSplitParts, got %v", name, err)
		}
		if name != "beside whole" {
			if _, err := os.Stat(filepath.Join(dir, "app.db")); !os.IsNotExist(err) {
				t.Errorf("%s: a partial database was written", name)
			}
		}
	}
}

// Any valid path splits and joins, including one with a newline or a name near the
// filesystem's component limit.
func TestJoinHandlesUnusualNames(t *testing.T) {
	lowerSplit(t, 4)
	for _, name := range []string{"data/a\nb.db", "data/" + strings.Repeat("n", 230)} {
		dir := t.TempDir()
		want := []byte("0123456789")
		for _, f := range SplitFile(File{Path: name, Data: want, Mode: 0600}) {
			p := filepath.Join(dir, filepath.FromSlash(f.Path))
			if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, f.Data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := joinSplitFiles(dir); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name))); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%q: %q %v", name, got, err)
		}
	}
}
