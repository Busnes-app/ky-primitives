package recoveryclient

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

// A file larger than one capsule member (MaxCapsuleFileBytes), in practice a SQLite snapshot
// of a large database, is sealed as ordered parts named <path>.000-of-003, <path>.001-of-003,
// and so on. SplitFile makes the parts when collecting; JoinSplitFiles puts the file back
// together after Restore, and inside a Drill's checks, before anything opens it. A capsule
// without parts is left as it was by both, so older capsules restore unchanged. The whole
// capsule is still bounded by MaxCapsuleTotalBytes.

// splitPartBytes is the largest part; a test lowers it.
var splitPartBytes = int(MaxCapsuleFileBytes)

// ErrSplitParts means the parts of a split file are incomplete, out of order, or sit beside a
// whole file of the same name.
var ErrSplitParts = errors.New("recoveryclient: split file parts do not add up")

func partName(p string, i, n int) string { return fmt.Sprintf("%s.%03d-of-%03d", p, i, n) }

// SplitFile returns f alone when it fits in one capsule member, else its ordered parts, each
// at most MaxCapsuleFileBytes, with f's mode.
func SplitFile(f File) []File {
	if len(f.Data) <= splitPartBytes {
		return []File{f}
	}
	n := (len(f.Data) + splitPartBytes - 1) / splitPartBytes
	parts := make([]File, 0, n)
	for i := range n {
		parts = append(parts, File{Path: partName(f.Path, i, n), Data: f.Data[i*splitPartBytes : min((i+1)*splitPartBytes, len(f.Data))], Mode: f.Mode})
	}
	return parts
}

// JoinSplitFiles reassembles the file sealed as parts of name (a slash-separated path relative
// to dir, as given to SplitFile) into dir/name, with the first part's mode, and removes the
// parts. Without parts it does nothing. It refuses a missing, extra or renumbered part, and
// parts beside a whole file, with ErrSplitParts.
func JoinSplitFiles(dir, name string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, base := path.Split(name)
	parent = strings.TrimSuffix(parent, "/")
	if parent == "" {
		parent = "."
	}
	d, err := root.Open(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return err
	}
	n, found := 0, 0
	for _, entry := range names {
		rest, ok := strings.CutPrefix(entry, base+".")
		if !ok || len(rest) != 10 || rest[3:7] != "-of-" {
			continue
		}
		total, err := strconv.Atoi(rest[7:])
		if _, err2 := strconv.Atoi(rest[:3]); err != nil || err2 != nil {
			continue
		}
		if n != 0 && total != n {
			return fmt.Errorf("%w: %s does not belong with parts of %d", ErrSplitParts, entry, n)
		}
		n = total
		found++
	}
	if found == 0 {
		return nil
	}
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s and its parts are both present", ErrSplitParts, name)
	}
	if found != n {
		return fmt.Errorf("%w: %d of %d parts of %s present", ErrSplitParts, found, n, name)
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = partName(name, i, n)
		if _, err := root.Lstat(parts[i]); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrSplitParts, parts[i], err)
		}
	}
	info, err := root.Lstat(parts[0])
	if err != nil {
		return err
	}
	tmp := name + ".joining"
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	err = appendParts(root, out, parts)
	if err == nil {
		err = out.Sync()
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return err
	}
	for _, p := range parts {
		if err := root.Remove(p); err != nil {
			return err
		}
	}
	return nil
}

func appendParts(root *os.Root, out io.Writer, parts []string) error {
	for _, p := range parts {
		in, err := root.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		in.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
