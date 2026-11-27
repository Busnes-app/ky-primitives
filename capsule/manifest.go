package capsule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// FileEntry describes one member of the payload. The digest lets a restore say which file
// is wrong; the payload hash only says that one of them is.
//
// The list is carried inside the encrypted payload, never in the plaintext manifest — see
// the Files field below for why.
//
// Path and Mode are the normalised ones — the relative path extraction writes and the
// owner-only clamp it applies — not the caller's spelling of them, so an entry can be
// matched against the File values Open returns. Seal builds them that way
// (TestManifestEntriesDescribeWhatExtractionProduces), and Open refuses a list that
// disagrees with what it extracted (TestFileListMustDescribeTheExtractedMembers).
type FileEntry struct {
	Path string      `json:"path"`
	Size int64       `json:"size_bytes"`
	Sum  string      `json:"sha256"`
	Mode os.FileMode `json:"mode"`
}

// UnverifiedManifest is a capsule's manifest read without its key.
//
// Every field here is attacker-controlled wherever the capsule file is. The manifest is
// bound into the AEAD exactly so that threshold, total_shares and the verification recipe
// cannot be rewritten by whoever reaches the file — that is what kycap/1 got wrong, where
// a 2-of-3 kit could be restated as 1-of-1 and still open. Reading it without the key
// gives that guarantee up.
//
// So it is a distinct type from Manifest. The compiler stops one being passed where the
// other is required, which catches the accident — it cannot stop deliberate construction,
// because Manifest's only field is exported and a caller may write Manifest{...} itself.
// The type is a guard rail, not a proof. Show these fields to an operator if you must; do
// not decide anything on them. Anything that chooses a restore path, a quorum, or a
// verification rule wants Manifest, which only a successful Open or Seal produces.
type UnverifiedManifest struct {
	CapsuleID   string    `json:"capsule_id"`
	ServiceName string    `json:"service_name"`
	AppVersion  string    `json:"app_version"`
	CreatedAt   time.Time `json:"created_at"`
	PayloadHash string    `json:"payload_hash"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	// RecoveryKeyID names the recovery key this capsule is sealed to: recoverykey.PublicKey.ID().
	// Not secret — it is a hash of a public key — and in the clear on purpose, so kyrecovery
	// can display it and refuse a deposit sealed to a key it did not hand out, without
	// holding any key at all.
	RecoveryKeyID string `json:"recovery_key_id"`
	// EncapsulatedKey is the HPKE encapsulated key, standard base64 of 1120 bytes. Public by
	// construction. Inside the AAD like every other field, so swapping it fails the AEAD.
	EncapsulatedKey string `json:"encapsulated_key"`
	// SignerKeyID optionally names the per-product hybrid signing key that signed this
	// manifest: hybridsig.PublicKey.ID(). Omitted on unsigned capsules so existing wire
	// output stays byte-identical. When present it is inside both the HPKE AAD and the
	// manifest signature itself.
	SignerKeyID string `json:"signer_key_id,omitempty"`

	// Files is not a manifest field. The manifest is stored in the clear, so a per-member
	// path, size and digest published there is readable by anyone who merely holds the
	// capsule: the digest is an offline confirmation oracle — no key, no rate limit — that
	// recovers any member drawn from a guessable space, and equal digests across two
	// backups prove a signing key was never rotated between them. The whole-payload hash
	// stays in the manifest because it digests a gzip stream whose ModTimes make it
	// unguessable; a per-member digest is a different object.
	//
	// The list travels inside the encrypted payload instead, as reservedFileList, and Open
	// fills this in from there. `json:"-"` is the enforcement: no later edit can marshal it
	// back into the plaintext without deleting the tag.
	// TestFileListNeverAppearsInTheClear holds that.
	//
	// So it is empty on the keyless path, which is the correct answer for a keyless read.
	Files []FileEntry `json:"-"`

	Dependencies       any `json:"dependencies,omitempty"`
	VerificationRecipe any `json:"verification_recipe,omitempty"`
}

// Manifest is a capsule's manifest, authenticated. Only a successful Open or Seal returns one.
//
// The embedded field is not an accident: a Manifest can be read wherever the fields are
// wanted, but an UnverifiedManifest cannot be passed where a Manifest is required.
//
// A Manifest is authenticated, not validated. Open proves the manifest is the one that was
// sealed to this recovery key, by whoever held its public half; it does not re-apply
// Seal's topology rule, so a kit recorded as 0-of-0 by some other writer opens without
// complaint. Check the numbers you intend to act on.
type Manifest struct {
	UnverifiedManifest
}

// decodeManifest parses a raw manifest field and refuses JSON null or non-object values
// rather than silently returning a zero UnverifiedManifest.
func decodeManifest(raw json.RawMessage) (UnverifiedManifest, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return UnverifiedManifest{}, fmt.Errorf("%w: manifest is not a JSON object", ErrCorruptCapsule)
	}
	var m UnverifiedManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return UnverifiedManifest{}, fmt.Errorf("%w: unreadable manifest: %v", ErrCorruptCapsule, err)
	}
	return m, nil
}

// ReadUnverifiedManifest returns a capsule's manifest without decrypting it and without a
// key. Read the doc comment on UnverifiedManifest before using it.
func ReadUnverifiedManifest(raw []byte) (UnverifiedManifest, error) {
	cf, err := parseContainer(raw)
	if err != nil {
		return UnverifiedManifest{}, err
	}
	return decodeManifest(cf.Manifest)
}
