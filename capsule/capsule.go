// Package capsule reads and writes the suite's encrypted backup container.
//
// The container is kycap/3: a JSON object holding the manifest and a base64 ciphertext,
// and nothing else. The payload is sealed to the suite recovery public key through HPKE;
// there is no per-capsule symmetric key and no nonce carried in the container — HPKE
// derives it from the encapsulated key and the key schedule. The manifest is bound in as
// the AEAD's additional authenticated data, so every field describing the capsule is
// authenticated rather than merely present.
//
// Three containers came before it and all are retired: kysignon-server's kycap/1 and
// kyrecovery-server's tar, which authenticated their ciphertext and left the manifest
// outside the AEAD, so the recovery topology a capsule advertises could be rewritten by
// anyone who could reach the file; and kycap/2, which fixed that and still handed back a
// raw key.
//
// The payload is a gzipped tar of the backed-up files, extracted through the hardening in
// extract.go.
package capsule

import (
	"errors"
	"os"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

var (
	// ErrCorruptCapsule reports a container that parsed but failed its payload hash.
	ErrCorruptCapsule = errors.New("corrupt capsule container or failed hash validation")
	// ErrUnknownContainer reports bytes that match neither container.
	ErrUnknownContainer = errors.New("not a recognised capsule container")
	// ErrPathTraversal reports an archive member that would escape the target directory.
	ErrPathTraversal = errors.New("capsule contains a path that escapes the target directory")
	// ErrCapsuleTooLarge reports an archive that expands past the permitted budget.
	ErrCapsuleTooLarge = errors.New("capsule payload exceeds the permitted expanded size")
	// ErrCapsuleEntryType reports an archive member that is not a regular file.
	ErrCapsuleEntryType = errors.New("capsule contains an entry that is not a regular file")
	// ErrTargetNotEmpty reports a restore target that already has contents.
	ErrTargetNotEmpty = errors.New("restore target directory is not empty")
	// ErrDuplicatePath reports two members that normalise to one destination.
	ErrDuplicatePath = errors.New("capsule contains two paths that normalise to the same destination")
	// ErrWrongRecoveryKey reports a capsule sealed to a recovery key other than the one
	// Open was given. It is checked before any decapsulation, so a wrong kit fails cheaply
	// and by name.
	ErrWrongRecoveryKey = errors.New("capsule is sealed to a different recovery key")
)

// File is one member of a capsule's payload.
type File struct {
	Path    string
	Content []byte
	Mode    os.FileMode
}

// Open parses a kycap/3 container, decrypts it with the recovery private key, verifies the
// payload hash, and returns the authenticated manifest with the files. When targetDir is
// non-empty the files are also written there under the containment rules in extract.go;
// the directory must be empty or absent. When it is empty nothing is written and the files
// are returned in memory.
//
// The manifest is returned because a successful Open is the proof that the container was
// not modified after sealing and was sealed to this recovery key. It proves nothing else:
// not which product sealed it, not that it is the backup the caller expected, and not that
// it is the newest one. Every product in the suite seals to the same public key, and that
// key is not secret, so anyone holding it can mint a capsule this function accepts. A
// caller acting on a restore must compare ServiceName, CapsuleID and CreatedAt against
// what it expects, and take freshness from the deposit record rather than the container.
// Callers that want the manifest without a key want ReadUnverifiedManifest, and should
// read that type's doc comment first.
//
// A capsule names the recovery key it was sealed to. Open compares that name with the key
// it was given before decapsulating anything, and fails with ErrWrongRecoveryKey on a
// mismatch — the custodians brought the wrong kit, and that is worth saying plainly.
func Open(raw []byte, with recoverykey.PrivateKey, targetDir string) (Manifest, []File, error) {
	m, payload, err := decryptPayload(raw, with)
	if err != nil {
		return Manifest{}, nil, err
	}
	// The file list is inside the payload, so it is read only after decryptPayload has
	// authenticated the container and verified the payload hash.
	files, entries, err := extractPayload(payload, targetDir)
	if err != nil {
		return Manifest{}, nil, err
	}
	m.Files = entries
	return Manifest{UnverifiedManifest: m}, files, nil
}
