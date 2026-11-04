package recoveryclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteLocalCopyPrunesOwnPrefixOnly(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"foreign.kycap", "Other-cap-Other-1.kycap"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("not ours"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var last string
	for i := 0; i < 3; i++ {
		p, err := WriteLocalCopy(dir, "Svc", "cap-Svc-"+strings.Repeat("1", i+1), []byte("sealed"), 2)
		if err != nil {
			t.Fatal(err)
		}
		last = p
		time.Sleep(15 * time.Millisecond)
	}
	copies, err := ListLocalCopies(dir, "Svc")
	if err != nil || len(copies) != 2 || copies[0].Name != filepath.Base(last) {
		t.Fatalf("%+v %v", copies, err)
	}
	for _, c := range copies {
		if !strings.HasPrefix(c.Name, "Svc.") {
			t.Errorf("listed %s", c.Name)
		}
	}
	for _, f := range []string{"foreign.kycap", "Other-cap-Other-1.kycap"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err != nil || string(b) != "not ours" {
			t.Errorf("%s touched: %v", f, err)
		}
	}
	if info, _ := os.Stat(last); info.Mode().Perm() != 0600 {
		t.Errorf("mode %v", info.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Errorf("%d entries; a temp file leaked?", len(entries))
	}
}

func TestListLocalCopiesMissingDirIsEmpty(t *testing.T) {
	copies, err := ListLocalCopies(filepath.Join(t.TempDir(), "nope"), "Svc")
	if err != nil || len(copies) != 0 {
		t.Fatalf("%v %v", copies, err)
	}
	if copies, err := ListLocalCopies("", "Svc"); err != nil || copies != nil {
		t.Fatalf("empty dir arg: %v %v", copies, err)
	}
}

func TestWriteLocalCopyRetention(t *testing.T) {
	dir := t.TempDir()
	for _, keep := range []int{0, -1} {
		if _, err := WriteLocalCopy(dir, "Svc", "cap-1", []byte("sealed"), keep); err != ErrBadKeep {
			t.Errorf("keep %d: %v", keep, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote with a bad keep: %d entries", len(entries))
	}
	p, err := WriteLocalCopy(dir, "Svc", "cap-1", []byte("sealed"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("keep=1 pruned the copy just written")
	}
}

func TestWriteLocalCopySweepsStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, tempPrefix+"dead")
	_ = os.WriteFile(stale, []byte("half"), 0600)
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(stale, old, old)
	fresh := filepath.Join(dir, tempPrefix+"live")
	_ = os.WriteFile(fresh, []byte("half"), 0600)
	if _, err := WriteLocalCopy(dir, "Svc", "cap-1", []byte("sealed"), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale temp file survived")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a temp file still being written was removed")
	}
}

// One app name being a prefix of another must not let the shorter one see, or prune, the
// longer one's capsules when they share a directory.
func TestLocalCopiesOfAPrefixedAppNameAreInvisibleToTheShorterName(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := WriteLocalCopy(dir, "app-staging", "cap-"+strings.Repeat("s", i+1), []byte("sealed"), 5); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := WriteLocalCopy(dir, "app", "cap-p", []byte("sealed"), 1); err != nil {
		t.Fatal(err)
	}
	mine, _ := ListLocalCopies(dir, "app")
	theirs, _ := ListLocalCopies(dir, "app-staging")
	if len(mine) != 1 || len(theirs) != 3 {
		t.Fatalf("app sees %d, app-staging sees %d", len(mine), len(theirs))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Fatalf("%d files; a neighbour's capsule was pruned", len(entries))
	}
	// A name with characters outside the safe set still cannot forge the delimiter.
	if _, err := WriteLocalCopy(dir, "evil.app", "cap-e", []byte("sealed"), 1); err != nil {
		t.Fatal(err)
	}
	if mine, _ = ListLocalCopies(dir, "app"); len(mine) != 1 {
		t.Fatalf("app sees %d after evil.app wrote", len(mine))
	}
}

// Names that differ only in a character outside the safe set must not share a prefix, and a
// name made only of such characters must not collide with a literal one.
func TestLocalCopiesOfCollidingNamesStaySeparate(t *testing.T) {
	dir := t.TempDir()
	pairs := [][2]string{{"a.b", "a-b"}, {"a_b", "a-b"}, {"...", "_"}, {"x_2e", "x."}, {"", "_"}}
	for _, p := range pairs {
		if appNameSafe(p[0]) == appNameSafe(p[1]) {
			t.Errorf("%q and %q collide as %q", p[0], p[1], appNameSafe(p[0]))
		}
	}
	names := []string{"a.b", "a-b", "a_b", "...", "app", "_"}
	for _, n := range names {
		for i := 0; i < 3; i++ {
			if _, err := WriteLocalCopy(dir, n, "cap-"+strings.Repeat("x", i+1), []byte("sealed"), 10); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, n := range names {
		copies, err := ListLocalCopies(dir, n)
		if err != nil || len(copies) != 3 {
			t.Errorf("%q sees %d copies: %v", n, len(copies), err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3*len(names) {
		t.Fatalf("%d files; a neighbour's capsule was pruned", len(entries))
	}
}

// A host whose clock ran ahead left copies dated in the future; the new copy has the
// oldest mtime and used to be the one pruned, while its path was returned as the backup.
func TestWriteLocalCopyNeverPrunesTheCopyItWrote(t *testing.T) {
	dir := t.TempDir()
	future := time.Now().Add(24 * time.Hour)
	for i, id := range []string{"cap-a", "cap-b"} {
		p, err := WriteLocalCopy(dir, "Svc", id, []byte("sealed"), 2)
		if err != nil {
			t.Fatal(err)
		}
		at := future.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	p, err := WriteLocalCopy(dir, "Svc", "cap-c", []byte("sealed"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the copy just written was pruned: %v", err)
	}
	copies, err := ListLocalCopies(dir, "Svc")
	if err != nil || len(copies) != 2 {
		t.Fatalf("want 2 copies kept, got %d (%v)", len(copies), err)
	}
	if !strings.Contains(copies[0].Name, "cap-b") {
		t.Fatalf("the newer existing copy should survive, kept %v", copies)
	}
}
