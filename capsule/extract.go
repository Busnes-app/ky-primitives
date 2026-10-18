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
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extraction budgets. A capsule is written by this suite, so these bound what a hostile
// or corrupt archive can do rather than what a legitimate one needs.
//
// They are memory budgets, not archive sizes: Open holds the raw container, the decrypted
// payload and every expanded member at once, so the real ceiling is a few times the number
// below. The previous 4 GiB member and 8 GiB total were larger than the machines this runs
// on, which meant a hostile capsule OOM-killed the process instead of receiving
// ErrCapsuleTooLarge. A capsule holds keys and configuration; it is kilobytes in practice.
//
// Exported so a consumer can map ErrCapsuleTooLarge to a message naming the limit without
// mirroring the numbers.
//
// ponytail: raise these only alongside a streaming Open that does not materialise every
// member, because that is the thing the numbers are really standing in for.
const (
	MaxFiles         = 4096
	MaxFileBytes     = int64(64 << 20)  // 64 MiB for any single member
	MaxExpandedBytes = int64(256 << 20) // 256 MiB of tar stream: members plus headers, padding, list and trailer
)

// reservedFileList is the payload member carrying the encoded []FileEntry. It is metadata,
// not a member of the backup: it is never returned in the []File and never written to
// targetDir. TestReservedMemberIsNeitherReturnedNorWritten holds that.
//
// The name cannot collide with a caller's file. Every caller member is named by
// safeRelPath, whose result is always filepath.Clean output, and Clean never returns a
// path with a "./" prefix: it drops "." elements, and the only "." it can return is the
// whole result, which safeRelPath rejects outright. So no input a caller can supply
// produces this name — a caller asking for "./.kycap-files.json" gets ".kycap-files.json",
// a different member that round-trips normally.
// TestReservedNameIsUnreachableThroughSafeRelPath holds that, over the fuzz corpus too.
const reservedFileList = "./.kycap-files.json"

// extractPayload unpacks the decrypted gzipped tar into files, and onto disk when
// targetDir is set. It also returns the file list carried in reservedFileList, empty for a
// payload that has none.
//
// This is ported from kysignon-server, which carries the strongest extraction hardening
// in the suite. Applying it to every container means a kyrecovery capsule opened here
// gets path, type and size checks that its own Unpack never applied.
func extractPayload(payload []byte, targetDir string) ([]File, []FileEntry, error) {
	gr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	defer gr.Close()

	// The gzip stream is the only place total expansion can be bounded once and for all;
	// per-entry caps alone still allow an unbounded number of entries.
	budget := &countingReader{r: io.LimitReader(gr, MaxExpandedBytes+1), limit: MaxExpandedBytes}
	tr := tar.NewReader(budget)

	root, created, err := prepareTargetDir(targetDir)
	if err != nil {
		return nil, nil, err
	}
	if root != nil {
		defer root.Close()
	}
	// Anything written before a failure is rolled back. The target has to be empty to
	// begin with, so emptying it again restores exactly what was there — and without this
	// a half-restored keyset stayed on disk and poisoned every retry with
	// ErrTargetNotEmpty.
	ok := false
	defer func() {
		if !ok {
			rollback(root, targetDir, created)
		}
	}()

	var files []File
	var entries []FileEntry
	haveList := false
	// Two members that normalise to one destination are a collision whether or not there is
	// a target directory. On disk O_EXCL caught it as a bare EEXIST; with no target it was
	// not caught at all, and Open returned two Files at the same Path for the caller to
	// resolve however it happened to iterate.
	seen := make(map[string]struct{})
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		// Only regular files are ever written into a capsule. Symlinks, hardlinks, device
		// nodes and directories have no legitimate use here and each is a way to write
		// somewhere the restore was not asked to touch.
		if hdr.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("%w: %s (type %q)", ErrCapsuleEntryType, hdr.Name, string(hdr.Typeflag))
		}

		// Before the file count, because the list is not one of the files: a capsule
		// holding exactly MaxFiles members plus its list is one Seal writes.
		// A second member under this name is refused rather than allowed to shadow the
		// first — no caller can produce the name, so two of them is a crafted payload.
		if hdr.Name == reservedFileList {
			if haveList {
				return nil, nil, fmt.Errorf("%w: %q", ErrDuplicatePath, reservedFileList)
			}
			entries, err = readFileList(tr)
			if err != nil {
				return nil, nil, err
			}
			haveList = true
			continue
		}

		if len(files) >= MaxFiles {
			return nil, nil, fmt.Errorf("%w: more than %d files", ErrCapsuleTooLarge, MaxFiles)
		}
		if hdr.Size < 0 || hdr.Size > MaxFileBytes {
			return nil, nil, fmt.Errorf("%w: %s declares %d bytes", ErrCapsuleTooLarge, hdr.Name, hdr.Size)
		}

		cleanName, err := safeRelPath(hdr.Name)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := seen[cleanName]; dup {
			return nil, nil, fmt.Errorf("%w: %q", ErrDuplicatePath, cleanName)
		}
		seen[cleanName] = struct{}{}

		// LimitReader caps what a lying header can actually deliver; the +1 byte is how an
		// over-long entry is detected rather than silently truncated.
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileBytes+1))
		if err != nil {
			return nil, nil, err
		}
		if int64(len(data)) > MaxFileBytes {
			return nil, nil, fmt.Errorf("%w: %s", ErrCapsuleTooLarge, hdr.Name)
		}

		// Clamp to owner-only. A restored capsule carries signing and encryption keys, and
		// an archive header is the attacker's field to fill: nothing in it should be able
		// to land a group- or world-readable key on disk.
		mode := os.FileMode(hdr.Mode).Perm() & 0700
		if mode == 0 {
			mode = 0600
		}
		files = append(files, File{Path: cleanName, Content: data, Mode: mode})

		if root != nil {
			if err := writeInto(root, cleanName, data, mode); err != nil {
				return nil, nil, err
			}
		}
	}

	// The list is decoded from the payload, not derived from it, so until this point it
	// can say anything: a path no member has, a digest for bytes that were not extracted,
	// more entries than the file cap. Callers verify restores per-file against it, and the
	// FileEntry doc promises them the normalised path and clamped mode extraction
	// produced. TestFileListMustDescribeTheExtractedMembers holds that.
	if haveList {
		if err := reconcileFileList(entries, files); err != nil {
			return nil, nil, err
		}
	}

	ok = true
	return files, entries, nil
}

// reconcileFileList refuses a decoded list that does not describe the extracted files
// exactly: one entry per file, in extraction order, every field equal. Seal writes the
// list in member order from the same normalisation, so a capsule it sealed always passes.
func reconcileFileList(entries []FileEntry, files []File) error {
	if len(entries) != len(files) {
		return fmt.Errorf("%w: file list has %d entries for %d members", ErrCorruptCapsule, len(entries), len(files))
	}
	for i, f := range files {
		sum := sha256.Sum256(f.Content)
		want := FileEntry{Path: f.Path, Size: int64(len(f.Content)), Sum: hex.EncodeToString(sum[:]), Mode: f.Mode}
		if entries[i] != want {
			return fmt.Errorf("%w: file list entry %d is %+v, member is %+v", ErrCorruptCapsule, i, entries[i], want)
		}
	}
	return nil
}

// readFileList decodes the reserved member. The bound is the one the list had as a
// manifest field, applied before json.Unmarshal can allocate against it; the +1 byte is
// how an over-long list is detected rather than silently truncated.
func readFileList(tr io.Reader) ([]FileEntry, error) {
	data, err := io.ReadAll(io.LimitReader(tr, maxFileListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileListBytes {
		return nil, fmt.Errorf("%w: file list exceeds %d bytes", ErrCapsuleTooLarge, maxFileListBytes)
	}
	var entries []FileEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("%w: unreadable file list: %v", ErrCorruptCapsule, err)
	}
	return entries, nil
}

// rollback removes whatever a failed extraction wrote, returning the target to the empty
// or absent state it had to be in for extraction to start.
func rollback(root *os.Root, targetDir string, created bool) {
	if root == nil {
		return
	}
	if created {
		root.Close()
		_ = os.RemoveAll(targetDir)
		return
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = root.RemoveAll(e.Name())
	}
}

// countingReader fails the whole extraction once the archive has expanded past its budget,
// instead of letting io.LimitReader report a silent early EOF that looks like a short archive.
type countingReader struct {
	r     io.Reader
	limit int64
	seen  int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.seen += int64(n)
	if c.seen > c.limit {
		return n, fmt.Errorf("%w: expanded past %d bytes", ErrCapsuleTooLarge, c.limit)
	}
	return n, err
}

// safeRelPath rejects any archive member name that does not stay inside the target.
func safeRelPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, name)
	}
	// Windows-style separators and drive letters are traversal on the platforms that honour
	// them and meaningless noise on the ones that do not.
	if strings.ContainsRune(name, '\\') || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: %s", ErrPathTraversal, name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: %s", ErrPathTraversal, name)
	}
	return clean, nil
}

// prepareTargetDir returns a directory handle to unpack into, creating the directory if
// needed, and reports whether this call created it. An existing
// non-empty directory is refused: extracting over unknown contents is how a pre-planted
// symlink gets a chance to redirect a write.
func prepareTargetDir(targetDir string) (*os.Root, bool, error) {
	if targetDir == "" {
		return nil, false, nil
	}
	created := false
	if _, err := os.Stat(targetDir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(targetDir, 0700); err != nil {
			return nil, false, err
		}
		created = true
	} else if err != nil {
		return nil, false, err
	}

	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return nil, false, err
	}
	if len(entries) > 0 {
		return nil, false, fmt.Errorf("%w: %s", ErrTargetNotEmpty, targetDir)
	}

	// os.Root resolves every component against a directory descriptor, so no member can
	// name a location outside it. The previous version checked parents by pathname with
	// Lstat and reopened the final path afterwards, which a process able to swap a
	// checked parent for a symlink could step through: O_NOFOLLOW only guards the last
	// component. Go selects openat2 where the kernel has it and a checked openat walk
	// where it does not, so this needs no minimum kernel of our own.
	root, err := os.OpenRoot(targetDir)
	if err != nil {
		return nil, false, err
	}
	return root, created, nil
}

// writeInto creates one archive member beneath root, refusing to overwrite an existing
// name. Containment is the root handle's job, not a string comparison's.
func writeInto(root *os.Root, relPath string, data []byte, mode os.FileMode) error {
	if dir := filepath.Dir(relPath); dir != "." && dir != "" {
		if err := root.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Close()
}
