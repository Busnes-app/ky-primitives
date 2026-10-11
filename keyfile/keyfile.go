// Package keyfile loads a long-lived key from disk, creating it on first use or storing one it was handed.
//
// Seven products in the suite did this seven ways, and the disagreements were not
// stylistic. kynotes-server continued past a key file it could not decode and left the
// secret an empty string, so the server ran with no pairing secret and no error.
// kypassword-server's audit store regenerated on an empty file, which silently orphans
// every record written under the old key. Five of the seven read and then wrote with no
// exclusion, so two starting processes each minted a key and one won after the other had
// already sealed data. Only one fsynced, so a crash just after first boot left a
// zero-length file for the next boot to misread.
//
// This package refuses rather than guesses: an existing file that does not decode to
// exactly the expected size is an error, never something to replace.
package keyfile

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	// ErrUnreadable reports an existing key file that does not decode to the expected
	// size. The file is left exactly as it was found.
	ErrUnreadable = errors.New("keyfile: existing key file is unreadable and will not be replaced")
	// ErrPermissive reports a key file that some account other than its owner can read.
	ErrPermissive = errors.New("keyfile: key file is readable beyond its owner")
	// ErrUnsafe reports a key path that is not a regular file owned by this process's user.
	ErrUnsafe = errors.New("keyfile: key path is not a regular file owned by the current user")
)

// minSize is the floor for a secret worth persisting. A shorter one is a mistake in the
// caller, and a weak key is worse than a loud failure.
const minSize = 16

// mu serialises callers in this process. create's os.Link handles the cross-process race —
// link fails with EEXIST when the name is taken, and unlike O_EXCL on the final path it
// cannot leave a partial file there. This mutex stops the common in-process race without
// paying for a lock file.
var mu sync.Mutex

// LoadOrCreate returns the size-byte secret stored at path as lowercase hex, creating it
// if the file does not exist. See LoadOrCreateEncoded for other spellings.
func LoadOrCreate(path string, size int) ([]byte, error) {
	return LoadOrCreateEncoded(path, size, Hex)
}

// LoadOrCreateEncoded returns the size-byte secret stored at path in the given encoding,
// creating it if the file does not exist.
//
// Hex is this package's default and the suite's preference: an operator can read it, copy
// it and diff it, with no ambiguity about whether the bytes are raw, hex or base64 — which
// three of the seven original implementations disagreed about. Raw and Base64 exist
// because other products already wrote their key files that way.
func LoadOrCreateEncoded(path string, size int, enc Encoding) ([]byte, error) {
	if size < minSize {
		return nil, fmt.Errorf("keyfile: size %d is below the %d-byte floor", size, minSize)
	}
	if !enc.valid() {
		return nil, fmt.Errorf("keyfile: unknown encoding %d", int(enc))
	}

	mu.Lock()
	defer mu.Unlock()

	if key, err := read(path, size, enc); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}

	key, err := create(path, size, enc)
	if errors.Is(err, os.ErrExist) {
		// Another process won the race between the read above and the create. Its key is
		// the real one; ours was never written and nothing has used it.
		return read(path, size, enc)
	}
	return key, err
}

// Load returns the size-byte secret stored at path as lowercase hex, and never creates
// one. See LoadEncoded for other spellings.
//
// A process that reads a key another process minted must not be able to mint its own. When
// both can, a restart in the wrong order leaves half the data under a key that no longer
// exists, and nothing reports it — every write succeeds, and every old read fails as
// though the data were corrupt.
func Load(path string, size int) ([]byte, error) {
	return LoadEncoded(path, size, Hex)
}

// LoadEncoded is Load for a key written in another spelling.
func LoadEncoded(path string, size int, enc Encoding) ([]byte, error) {
	if size < minSize {
		return nil, fmt.Errorf("keyfile: size %d is below the %d-byte floor", size, minSize)
	}
	if !enc.valid() {
		return nil, fmt.Errorf("keyfile: unknown encoding %d", int(enc))
	}
	return read(path, size, enc)
}

// Store persists a key the caller already holds — a public key received at pairing — with
// the durability and permissions of LoadOrCreate, and refuses to replace a file that exists.
//
// The refusal is the point. Replacing a product's recovery public key is how every later
// backup gets sealed to whoever wrote the replacement; os.Link failing on an existing name
// is what makes that attack fail rather than succeed silently. Rotation, when it comes,
// gets a deliberate path, not an overwrite. The error satisfies errors.Is(err, fs.ErrExist).
func Store(path string, key []byte, enc Encoding) error {
	if len(key) < minSize {
		return fmt.Errorf("keyfile: key is %d bytes, below the %d-byte floor", len(key), minSize)
	}
	if !enc.valid() {
		return fmt.Errorf("keyfile: unknown encoding %d", int(enc))
	}

	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return write(path, key, enc)
}

// RequireOwnerOnly reports whether path is readable by anyone but its owner. Nothing in
// the suite checked this, so a key file relaxed to 0644 by a stray chmod or a restore
// kept being used as though it were secret.
func RequireOwnerOnly(path string) error {
	f, fi, err := openKey(path)
	if err != nil {
		return err
	}
	f.Close()
	return checkKeyInfo(fi)
}

func checkKeyInfo(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() || !ownedByCurrentUser(fi) {
		return fmt.Errorf("%w: %s", ErrUnsafe, fi.Name())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: mode is %04o, want 0600", ErrPermissive, perm)
	}
	return nil
}

// read reads and validates an existing key file. It never creates one, and it never
// re-opens by path: openKey hands back an already-verified descriptor, and everything
// below reads from that descriptor alone.
func read(path string, size int, enc Encoding) ([]byte, error) {
	f, fi, err := openKey(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := checkKeyInfo(fi); err != nil {
		return nil, err
	}
	// Bounded because this is the package that loads long-lived secrets, and a corrupt or
	// attacker-controlled file would otherwise be pulled into memory whole before any
	// decode or size check could refuse it. The cap comes from size rather than a round
	// number: hex is the widest of the three encodings at two characters per byte, and
	// the slack covers a trailing newline, a CRLF, or an editor's blank last line.
	limit := 2*size + 64
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		// Left where it was found, like every other unreadable file here.
		// TestReadRefusesAnOversizedFileWithoutTouchingIt holds that.
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrUnreadable, path, limit)
	}
	key, err := enc.decode(raw)
	if err != nil {
		if enc == Hex {
			// hex.InvalidByteError prints the offending byte. For a raw key misread as
			// hex, that byte is almost always byte 0 of the actual secret — keep this
			// message content-free so it never ends up in a startup log.
			return nil, fmt.Errorf("%w: %s: not hex", ErrUnreadable, path)
		}
		// base64.CorruptInputError is positional only; it carries no key content.
		return nil, fmt.Errorf("%w: %s: %w", ErrUnreadable, path, err)
	}
	if len(key) != size {
		// Left untouched on purpose. A file that does not decode to the expected size is
		// not a file to overwrite: it is either someone else's key or a truncated write,
		// and replacing it orphans everything encrypted under the original.
		return nil, fmt.Errorf("%w: %s holds %d bytes, expected %d", ErrUnreadable, path, len(key), size)
	}
	return key, nil
}

// openKey rejects symlinks and verifies that the file opened is the same object inspected,
// closing the pathname swap between validation and use.
func openKey(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("keyfile: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafe, path)
	}
	// Opening a FIFO or device can block forever; refuse before open.
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("keyfile: %w", err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("keyfile: %w", err)
		}
		return nil, nil, fmt.Errorf("%w: %s changed while opening", ErrUnsafe, path)
	}
	return f, after, nil
}

// writeAll is indirected so the failed-write test can produce a real short write.
var writeAll = func(f *os.File, s string) error {
	_, err := f.WriteString(s)
	return err
}

// create writes a fresh key, failing if the path already exists.
//
// The key is written to a uniquely named temporary file in the same directory, fsynced,
// and only then linked to its final name. Writing straight to the final name meant a
// short write or a full disk left partial hex at the real path — and because this package
// refuses to replace an unreadable key, that partial file is permanent until someone
// deletes it by hand.
func create(path string, size int, enc Encoding) ([]byte, error) {
	key := make([]byte, size)
	if _, err := randRead(key); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if err := write(path, key, enc); err != nil {
		return nil, err
	}
	return key, nil
}

// write is the durable, non-replacing write path shared by create and Store.
func write(path string, key []byte, enc Encoding) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyfile-*.tmp")
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	tmpName := tmp.Name()
	// Removed on every failure path below, and after a successful link, which leaves the
	// temporary name in place.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// CreateTemp makes the file 0600 already; set it explicitly so the guarantee does not
	// depend on that staying true.
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if err := writeAll(tmp, string(enc.encode(key))); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	// Without the fsync a crash here leaves a zero-length file that the next boot reads
	// as a corrupt key, which is the failure the refusal above then reports forever.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}

	// os.Link rather than os.Rename: rename would silently replace a key another process
	// created while we were writing, and this package must never destroy a key.
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	// And without syncing the directory the name can be lost even though its contents
	// were durable.
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return nil
}

// randRead is crypto/rand.Read, named so the error is never the discarded one. Two
// implementations wrote `_, _ = rand.Read(b)` and shipped an all-zero secret on failure.
func cryptoRandRead(b []byte) (int, error) { return cryptorand.Read(b) }

var randRead = cryptoRandRead

// ReadPrivate reads a bounded opaque secret or setup bundle from an existing private
// regular file. It uses the same verified descriptor as key loading and never creates
// or repairs a file. Content is returned only after ownership and mode checks pass.
func ReadPrivate(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || limit < 1 || limit > 1<<20 {
		return nil, errors.New("keyfile: absolute path and a limit of 1 byte through 1 MiB required")
	}
	f, info, err := openKey(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := checkKeyInfo(info); err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, errors.New("keyfile: private file exceeds size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("keyfile: private file exceeds size limit")
	}
	return raw, nil
}

func ownedByCurrentUser(fi os.FileInfo) bool {
	uid, ok := ownerUID(fi)
	return ok && uid == uint32(os.Geteuid())
}

// RequireTrustedAncestry refuses a path whose existing ancestors another user could
// rename or replace: each must be a real directory owned by root or the current user,
// writable by others only when root-owned and sticky. Missing components are allowed;
// they can only be created beneath a verified ancestor.
func RequireTrustedAncestry(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("keyfile: absolute path required")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil {
			uid, ok := ownerUID(info)
			shared := info.Mode().Perm()&0o022 != 0 && !(uid == 0 && info.Mode()&os.ModeSticky != 0)
			if !info.IsDir() || !ok || (uid != 0 && uid != uint32(os.Geteuid())) || shared {
				return fmt.Errorf("%w: %s has an untrusted ancestor", ErrUnsafe, path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("keyfile: %w", err)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// RequirePrivateDirectory validates a container-local control directory without
// changing ownership or permissions. It refuses a symlink or a foreign/permissive path.
func RequirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(info) || info.Mode().Perm()&0077 != 0 {
		return errors.New("keyfile: directory must be private and owned by the current user")
	}
	return nil
}
