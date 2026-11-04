package recoveryclient

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
)

// A file larger than one capsule member (MaxCapsuleFileBytes), in practice a SQLite snapshot
// of a large database, goes into the payload through SplitFile as ordered parts named
// <path>.000-of-003, <path>.001-of-003, and so on (the names kydrive-server already uses).
// Restore and Drill put every such file back together before anyone opens it, so the restored
// directory and a drill's checks see <path> itself. A capsule without parts is left as it was.
// The whole capsule is still bounded by MaxCapsuleTotalBytes.

// splitPartBytes is the largest part; a test lowers it.
var splitPartBytes = int(MaxCapsuleFileBytes)

// ErrSplitParts means the parts of a split file are incomplete, out of order, or sit beside a
// whole file of the same name.
var ErrSplitParts = errors.New("recoveryclient: split file parts do not add up")

var partPattern = regexp.MustCompile(`(?s)^(.+)\.([0-9]{3})-of-([0-9]{3})$`)

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

// joinSplitFiles reassembles every split file under dir, a directory capsule.Open just
// filled, into its own name with the first part's mode, and removes the parts. It refuses a
// missing, extra or renumbered part, and parts beside a whole file, with ErrSplitParts. It is
// not resumable; neither is the restore it finishes, which needs an empty target.
func joinSplitFiles(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	sets := map[string][]string{} // whole file -> part names found, in walk (lexical) order
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if m := partPattern.FindStringSubmatch(p); m != nil {
			sets[m[1]] = append(sets[m[1]], p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for whole, found := range sets {
		n, _ := strconv.Atoi(partPattern.FindStringSubmatch(found[0])[3])
		if n < 2 && len(found) == 1 {
			continue // SplitFile never makes one part: an ordinary file that happens to look like one
		}
		if len(found) != n {
			return fmt.Errorf("%w: %d parts of %s present, the first says %d", ErrSplitParts, len(found), whole, n)
		}
		for i, p := range found {
			if p != partName(whole, i, n) {
				return fmt.Errorf("%w: found %s where %s belongs", ErrSplitParts, p, partName(whole, i, n))
			}
		}
		if _, err := root.Lstat(whole); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s and its parts are both present", ErrSplitParts, whole)
		}
		if err := joinParts(root, whole, found); err != nil {
			return fmt.Errorf("reassembling %s: %w", whole, err)
		}
	}
	return nil
}

func joinParts(root *os.Root, whole string, parts []string) error {
	info, err := root.Lstat(parts[0])
	if err != nil {
		return err
	}
	tmp := path.Join(path.Dir(whole), ".join-"+rand.Text())
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	for _, p := range parts {
		if err == nil {
			err = appendFile(root, out, p)
		}
	}
	if err == nil {
		err = out.Sync()
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = root.Rename(tmp, whole)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return err
	}
	// Last part first, so an interrupted cleanup leaves the whole file and a leading run of
	// parts, the state kydrive-server's own JoinDatabase knows how to finish.
	for i := len(parts) - 1; i >= 0; i-- {
		if err := root.Remove(parts[i]); err != nil {
			return err
		}
	}
	return nil
}

func appendFile(root *os.Root, out io.Writer, name string) error {
	in, err := root.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(out, in)
	return err
}
