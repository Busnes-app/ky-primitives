package recoveryclient

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrBadKeep is returned when the retention count is below one. The zero value must never
// mean "delete everything": an adapter that forgets to set Keep would otherwise prune the
// capsule it just wrote and report success.
var ErrBadKeep = errors.New("recoveryclient: keep must be at least 1")

// tempPrefix marks in-progress writes. A temp file older than staleTemp was left by a
// process that died mid-write and is removed on the next write.
const (
	tempPrefix = ".kycap-"
	staleTemp  = time.Hour
)

func sweepStaleTemp(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > staleTemp {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// LocalCopy is one sealed capsule in the local backup directory.
type LocalCopy struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

// localPrefix scopes this instance's files in the backup directory: only names carrying it
// are listed or pruned, so capsules the operator put there by hand, or another service's,
// are never touched. The app name is escaped reversibly into [A-Za-z0-9-_] and joined with
// ".", a character the escaping can never produce, so two properties hold: no app name is a
// prefix of another's plus the delimiter ("app" cannot see "app-staging"), and two distinct
// names never share a prefix ("a.b" and "a-b" escape differently). Files are
// <escaped-app>.<capsule-id>.kycap.
func localPrefix(appName string) string {
	return appNameSafe(appName) + "."
}

// LocalPrefix is the filename prefix this package gives appName's local copies, exported so
// a product can migrate files written under an earlier scheme into it.
func LocalPrefix(appName string) string { return localPrefix(appName) }

// appNameSafe escapes every byte outside [A-Za-z0-9-] as _XX (two hex digits), including a
// literal underscore, so the mapping is injective and its output never contains ".".
func appNameSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "_%02x", c)
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// WriteLocalCopy stores a sealed capsule as <app>.<capsule-id>.kycap in dir and prunes this
// instance's oldest beyond keep. The bytes are sealed to the suite key, so the directory
// needs no more protection than any other file the operator keeps; 0600 anyway. The write
// goes through a temp file and rename so a crash never leaves a truncated .kycap that looks
// like a backup.
func WriteLocalCopy(dir, appName, capsuleID string, raw []byte, keep int) (string, error) {
	if keep < 1 {
		return "", ErrBadKeep
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	sweepStaleTemp(dir)
	final := filepath.Join(dir, localPrefix(appName)+FilenameSafe(capsuleID)+".kycap")
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Rename(tmpName, final); err != nil {
		cleanup()
		return "", err
	}
	copies, err := ListLocalCopies(dir, appName)
	if err != nil {
		return final, err
	}
	// The copy just written always survives: ordering is by mtime, and a clock that ran
	// ahead before (or a copied-in file) would otherwise sort it last and prune it.
	// A copy at least as new as ours (and not far ahead of it) was written by a run racing
	// this one; pruning it too would let two runs with keep=1 delete each other's. If ours
	// is already gone, such a run pruned it, and pruning here could leave nothing.
	var mine time.Time
	for _, c := range copies {
		if c.Name == filepath.Base(final) {
			mine = c.CreatedAt
		}
	}
	if mine.IsZero() {
		return final, fmt.Errorf("prune: %s was removed by a concurrent run", filepath.Base(final))
	}
	kept := 1
	for _, c := range copies {
		if c.Name == filepath.Base(final) {
			continue
		}
		if !c.CreatedAt.Before(mine) && !c.CreatedAt.After(mine.Add(time.Minute)) {
			kept++
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		if err := os.Remove(filepath.Join(dir, c.Name)); err != nil && !os.IsNotExist(err) {
			return final, fmt.Errorf("prune %s: %w", c.Name, err)
		}
	}
	return final, nil
}

// ListLocalCopies returns this instance's .kycap files in dir, newest first. A missing
// directory is an empty list: nothing has been written yet.
func ListLocalCopies(dir, appName string) ([]LocalCopy, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []LocalCopy
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), localPrefix(appName)) || !strings.HasSuffix(e.Name(), ".kycap") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, LocalCopy{Name: e.Name(), SizeBytes: info.Size(), CreatedAt: info.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
