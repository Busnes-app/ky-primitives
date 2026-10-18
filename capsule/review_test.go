package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// payloadFailingPartway builds the plaintext both containers hold: a valid first member,
// then one Open must reject. Extraction gets far enough to write the first before failing.
func payloadFailingPartway(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	good := []byte("first member, written before the failure")
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0600, Size: int64(len(good)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(good); err != nil {
		t.Fatal(err)
	}
	// A symlink member: refused by the entry-type check, after a.txt is already on disk.
	if err := tw.WriteHeader(&tar.Header{Name: "b.txt", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Finding 3.1: Seal enforced safeRelPath and nothing else, so it happily wrote capsules
// Open then refused. A backup that cannot be restored is the worst failure this package
// has, and it was reachable by sealing one file too many.
func TestSealRefusesWhatOpenWouldRefuse(t *testing.T) {
	t.Run("more files than Open permits", func(t *testing.T) {
		priv := testRecoveryKey(t)
		files := make([]File, MaxFiles+1)
		for i := range files {
			files[i] = File{Path: fmt.Sprintf("f%05d", i), Content: []byte("x"), Mode: 0600}
		}
		if _, _, err := Seal("t", "1", files, nil, nil, 2, 3, priv.Public()); !errors.Is(err, ErrCapsuleTooLarge) {
			t.Fatalf("got %v, want ErrCapsuleTooLarge", err)
		}
	})

	// Under the file count and under every size limit, but the manifest is past
	// maxManifestBytes. Seal used to return a key for this container and both readers then
	// refused it forever. Nothing bounds the recipe, so it is the growth path that stays
	// once the file list has moved into the payload.
	t.Run("manifest past what parseContainer permits", func(t *testing.T) {
		priv := testRecoveryKey(t)
		recipe := map[string]any{"steps": strings.Repeat("s", maxManifestBytes)}
		files := []File{{Path: "a.txt", Content: []byte("x"), Mode: 0600}}
		_, _, err := Seal("t", "1", files, nil, recipe, 2, 3, priv.Public())
		if !errors.Is(err, ErrCapsuleTooLarge) {
			t.Fatalf("got %v, want ErrCapsuleTooLarge", err)
		}
		if !strings.Contains(err.Error(), "manifest") {
			t.Fatalf("got %v, want the manifest bound", err)
		}
	})

	// The same growth, now in the file list: nothing bounds a caller's path lengths, and
	// the list is the payload member Open reads under maxFileListBytes. Seal must refuse
	// what Open would refuse here too.
	t.Run("file list past what Open permits", func(t *testing.T) {
		priv := testRecoveryKey(t)
		files := make([]File, MaxFiles)
		for i := range files {
			files[i] = File{Path: fmt.Sprintf("%04d", i) + strings.Repeat("p", 196), Content: []byte("x"), Mode: 0600}
		}
		_, _, err := Seal("t", "1", files, nil, nil, 2, 3, priv.Public())
		if !errors.Is(err, ErrCapsuleTooLarge) {
			t.Fatalf("got %v, want ErrCapsuleTooLarge", err)
		}
		if !strings.Contains(err.Error(), "file list") {
			t.Fatalf("got %v, want the file-list bound", err)
		}
	})

	t.Run("exactly the limit still seals", func(t *testing.T) {
		priv := testRecoveryKey(t)
		files := make([]File, MaxFiles)
		for i := range files {
			files[i] = File{Path: fmt.Sprintf("f%05d", i), Content: []byte("x"), Mode: 0600}
		}
		raw, _, err := Seal("t", "1", files, nil, nil, 2, 3, priv.Public())
		if err != nil {
			t.Fatalf("the limit itself was refused: %v", err)
		}
		_, got, err := Open(raw, priv, "")
		if err != nil {
			t.Fatalf("Open refused a capsule Seal wrote: %v", err)
		}
		if len(got) != MaxFiles {
			t.Fatalf("round tripped %d files, want %d", len(got), MaxFiles)
		}
	})
}

// The manifest used to record the caller's raw path and mode while buildPayload wrote the
// normalised name and the owner-only clamp. A per-file digest check keyed on the manifest
// path then matched no file, and the published mode was one extraction deliberately
// refuses to apply.
func TestManifestEntriesDescribeWhatExtractionProduces(t *testing.T) {
	priv := testRecoveryKey(t)
	files := []File{
		{Path: "./a.txt", Content: []byte("a"), Mode: 0o644},
		{Path: "d//e/../e/f.txt", Content: []byte("f"), Mode: 0o777},
	}
	raw, m, err := Seal("t", "1", files, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Files[0].Path; got != "a.txt" {
		t.Errorf("manifest path %q, want %q", got, "a.txt")
	}
	if got := m.Files[0].Mode; got != 0o600 {
		t.Errorf("manifest mode %04o, want 0600", got)
	}
	if got := m.Files[1].Path; got != "d/e/f.txt" {
		t.Errorf("manifest path %q, want %q", got, "d/e/f.txt")
	}
	if got := m.Files[1].Mode; got != 0o700 {
		t.Errorf("manifest mode %04o, want 0700", got)
	}

	_, opened, err := Open(raw, priv, "")
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]File, len(opened))
	for _, f := range opened {
		byPath[f.Path] = f
	}
	for _, e := range m.Files {
		f, ok := byPath[e.Path]
		if !ok {
			t.Fatalf("manifest names %q, Open returned no such file", e.Path)
		}
		if sum := sha256.Sum256(f.Content); hex.EncodeToString(sum[:]) != e.Sum {
			t.Errorf("%q: digest does not match the file Open returned", e.Path)
		}
		if f.Mode != e.Mode {
			t.Errorf("%q: manifest mode %04o, extracted mode %04o", e.Path, e.Mode, f.Mode)
		}
	}
}

// Two paths that normalise to one destination produced a capsule whose second member
// collided on extraction. With no target directory it was worse: Open returned two Files
// at the same path and no error at all.
func TestSealRefusesPathsThatCollideAfterNormalisation(t *testing.T) {
	for _, paths := range [][2]string{
		{"a/../b", "b"},
		{"b", "a/../b"},
		{"./x", "x"},
		{"d/e", "d/../d/e"},
	} {
		t.Run(paths[0]+" vs "+paths[1], func(t *testing.T) {
			priv := testRecoveryKey(t)
			_, _, err := Seal("t", "1", []File{
				{Path: paths[0], Content: []byte("first"), Mode: 0600},
				{Path: paths[1], Content: []byte("second"), Mode: 0600},
			}, nil, nil, 2, 3, priv.Public())
			if !errors.Is(err, ErrDuplicatePath) {
				t.Fatalf("got %v, want ErrDuplicatePath", err)
			}
		})
	}
}

func TestSealRefusesAnOversizedMember(t *testing.T) {
	// buildPayload measures int64(len(f.Content)) directly, so unlike extraction -- which
	// bounds a declared hdr.Size from an attacker-controlled tar header -- there is no
	// declared length to lie about here. Exercising the check needs a real allocation over
	// MaxFileBytes.
	priv := testRecoveryKey(t)
	content := make([]byte, MaxFileBytes+1)
	_, _, err := Seal("t", "1", []File{{Path: "big", Content: content, Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	content = nil
	if !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("got %v, want ErrCapsuleTooLarge", err)
	}
}

// Finding 1.3: members were written into the target one at a time, so a failure partway
// through left the earlier ones on disk. The target must be empty, so the failed attempt
// also poisoned every retry — and an operator's scripts could consume half a keyset.
func TestAFailedExtractionLeavesNothingBehind(t *testing.T) {
	target := filepath.Join(t.TempDir(), "restore")
	payload := payloadFailingPartway(t)

	if _, _, err := extractPayload(payload, target); !errors.Is(err, ErrCapsuleEntryType) {
		t.Fatalf("got %v, want ErrCapsuleEntryType", err)
	}

	entries, err := os.ReadDir(target)
	if err == nil && len(entries) > 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("partial restore left %v in the target", names)
	}

	// A retry must succeed rather than hit ErrTargetNotEmpty.
	priv := testRecoveryKey(t)
	raw, _, err := Seal("t", "1", []File{{Path: "a.txt", Content: []byte("ok"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(raw, priv, target); err != nil {
		t.Fatalf("retry after a failed restore: %v", err)
	}
}

// Finding 1.1: containment was enforced by pathname, with Lstat on each parent and
// O_NOFOLLOW only on the final component, so a symlinked parent planted between the check
// and the open escaped it. Extraction runs through an os.Root handle now, which resolves
// every component against a directory descriptor and cannot name a location outside it.
func TestExtractionCannotEscapeThroughASymlinkedParent(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(t.TempDir(), "restore")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "sub")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	priv := testRecoveryKey(t)
	raw, _, err := Seal("t", "1", []File{
		{Path: "sub/stolen.txt", Content: []byte("secret"), Mode: 0600},
	}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(raw, priv, target); err == nil {
		t.Fatal("extracted into a target holding a symlinked parent")
	}
	if _, err := os.Stat(filepath.Join(outside, "stolen.txt")); err == nil {
		t.Fatal("a member was written outside the target through a symlink")
	}
}

// Seal refuses to write colliding paths, but a capsule from any other writer still reaches
// extraction. With a target directory the collision surfaced as a bare EEXIST from O_EXCL;
// with none it did not surface at all, and Open handed back two Files at one Path.
func TestExtractRejectsPathsThatCollideAfterNormalisation(t *testing.T) {
	payload := hostilePayload(t,
		[]*tar.Header{
			{Name: "a/../b", Mode: 0600, Size: 5, Typeflag: tar.TypeReg},
			{Name: "b", Mode: 0600, Size: 6, Typeflag: tar.TypeReg},
		},
		[][]byte{[]byte("first"), []byte("second")})

	for _, target := range []string{"", filepath.Join(t.TempDir(), "restore")} {
		name := "no target directory"
		if target != "" {
			name = "into a target directory"
		}
		t.Run(name, func(t *testing.T) {
			if _, _, err := extractPayload(payload, target); !errors.Is(err, ErrDuplicatePath) {
				t.Fatalf("got %v, want ErrDuplicatePath", err)
			}
		})
	}
}

// Issue #20: Seal counted member content against MaxExpandedBytes while Open counts the
// whole tar stream, so many small members near the limit sealed and then never restored.
// This builds a payload whose tar stream is exactly MaxExpandedBytes, then one content
// byte more, which the old content-only count would also have sealed.
func TestSealCountsTarFramingLikeOpen(t *testing.T) {
	const n, size = 4000, 64 << 10 // framing is ~2 MiB of the stream here
	block := func(x int64) int64 { return (x + 511) / 512 * 512 }

	// Every member but the last shares one buffer, so the test holds one payload's worth
	// of memory rather than two.
	build := func(last int64) []File {
		buf := make([]byte, max(last, size))
		files := make([]File, n)
		for i := range files {
			files[i] = File{Path: fmt.Sprintf("f%05d", i), Content: buf[:size], Mode: 0600}
		}
		files[n-1].Content = buf[:last]
		return files
	}
	// The tar stream: a header and padded content per member, the same for the reserved
	// file list, then the two-block trailer.
	streamSize := func(files []File) int64 {
		entries := make([]FileEntry, len(files))
		sums := map[int]string{} // members share content, so hash each length once
		var s int64
		for i, f := range files {
			if _, ok := sums[len(f.Content)]; !ok {
				sum := sha256.Sum256(f.Content)
				sums[len(f.Content)] = hex.EncodeToString(sum[:])
			}
			entries[i] = FileEntry{Path: f.Path, Size: int64(len(f.Content)), Sum: sums[len(f.Content)], Mode: 0600}
			s += 512 + block(int64(len(f.Content)))
		}
		list, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		return s + 512 + block(int64(len(list))) + 1024
	}

	// Grow the last member until the stream lands on the limit. Its size changes the list
	// length too, so iterate to a fixed point rather than solve once.
	last := int64(size)
	for range 4 {
		last += MaxExpandedBytes - streamSize(build(last))
	}
	atLimit := build(last)
	if got := streamSize(atLimit); got != MaxExpandedBytes || last > MaxFileBytes {
		t.Fatalf("fixture stream is %d bytes with a %d-byte last member, want exactly %d", got, last, MaxExpandedBytes)
	}

	priv := testRecoveryKey(t)
	raw, _, err := Seal("t", "1", atLimit, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatalf("a stream of exactly MaxExpandedBytes was refused: %v", err)
	}
	if _, got, err := Open(raw, priv, ""); err != nil || len(got) != n {
		t.Fatalf("Open of a capsule Seal wrote: %d files, %v", len(got), err)
	}

	_, _, err = Seal("t", "1", build(last+1), nil, nil, 2, 3, priv.Public())
	if !errors.Is(err, ErrCapsuleTooLarge) || !strings.Contains(err.Error(), "tar headers and padding") {
		t.Fatalf("one byte over: got %v, want ErrCapsuleTooLarge naming the tar framing", err)
	}
}
