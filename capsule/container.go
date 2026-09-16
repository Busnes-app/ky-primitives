package capsule

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// KycapFileFormat identifies the one container this package reads and writes.
//
// It is kycap/3: kycap/2 with the payload sealed to the suite recovery public key through
// HPKE instead of a per-capsule symmetric key the caller had to protect and split. Three
// containers came before it and all are gone: kysignon-server's kycap/1 and
// kyrecovery-server's tar, which authenticated their ciphertext and left the manifest
// outside the AEAD — so capsule_id, service_name, threshold, total_shares and the
// verification recipe could all be rewritten by someone who never learned the key — and
// kycap/2, which fixed that and still handed back a raw key.
//
// Reading them was retired rather than kept: a reader that half-trusts a manifest cannot
// tell a caller which half, and nothing is in the wild.
const KycapFileFormat = "kycap/3"

// maxManifestBytes bounds the manifest before it is parsed. A manifest is a few hundred
// bytes of JSON; a megabyte of it is already absurd.
const maxManifestBytes = 1 << 20

// maxFileListBytes bounds the encoded file list, which lives inside the payload rather
// than the manifest. It is the budget that list had while it was a manifest field, kept
// identical so that moving it did not quietly raise what a caller's path lengths can reach
// — Seal refuses a list past this, and Open refuses to read one.
const maxFileListBytes = maxManifestBytes

// MaxContainerBytes bounds attacker-controlled input before JSON parsing and base64
// decoding can make additional copies of it. The plaintext ceiling is 256 MiB; this leaves
// room for base64 expansion, the manifest and archive framing.
const MaxContainerBytes = 384 << 20

// manifest is the authenticated description of a capsule. It is carried and authenticated
// as the exact bytes that were read, never a re-encoding of this struct — see kycapFile.
type manifest = UnverifiedManifest

// kycapFile is the JSON container.
//
// Manifest is kept as raw bytes rather than a decoded struct because those exact bytes are
// the additional authenticated data. Re-encoding a decoded manifest to rebuild the AAD
// would have to reproduce the writer's spelling byte for byte — field order, number
// formatting, the interface{} shape of dependencies — and any drift there fails every
// capsule rather than any forgery. The bytes that were read are the bytes that are
// authenticated.
type kycapFile struct {
	Format     string          `json:"format"`
	Manifest   json.RawMessage `json:"manifest"`
	Ciphertext string          `json:"ciphertext"`
}

// parseContainer parses the container envelope and bounds every attacker-controlled part of
// it before anything downstream can act on it. decryptPayload calls this with bytes it will
// decrypt under a key; ReadUnverifiedManifest calls it with bytes from a caller who has no
// key at all and so no other defence — both need the same limits, and a second copy of any
// of them is how it stops matching the first.
func parseContainer(raw []byte) (kycapFile, error) {
	if err := checkContainerSize("container", len(raw)); err != nil {
		return kycapFile{}, err
	}
	if len(bytes.TrimLeft(raw, " \t\r\n")) == 0 {
		return kycapFile{}, ErrUnknownContainer
	}

	var cf kycapFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return kycapFile{}, fmt.Errorf("%w: not readable as %s: %v", ErrUnknownContainer, KycapFileFormat, err)
	}
	if cf.Format != KycapFileFormat {
		return kycapFile{}, fmt.Errorf("%w: unsupported capsule format %q", ErrUnknownContainer, cf.Format)
	}
	if cf.Ciphertext == "" {
		return kycapFile{}, fmt.Errorf("%w: container carries no ciphertext", ErrCorruptCapsule)
	}
	if err := checkContainerSize("encoded ciphertext", len(cf.Ciphertext)); err != nil {
		return kycapFile{}, err
	}
	if len(cf.Manifest) > maxManifestBytes {
		return kycapFile{}, fmt.Errorf("%w: manifest is %d bytes", ErrCorruptCapsule, len(cf.Manifest))
	}
	return cf, nil
}

// decryptPayload parses the container, checks it names the key it was given, decrypts it
// under the manifest, and returns the authenticated manifest alongside the hash-verified
// gzipped tar payload.
func decryptPayload(raw []byte, with recoverykey.PrivateKey) (manifest, []byte, error) {
	cf, err := parseContainer(raw)
	if err != nil {
		return manifest{}, nil, err
	}
	var m manifest
	if err := json.Unmarshal(cf.Manifest, &m); err != nil {
		return manifest{}, nil, fmt.Errorf("%w: unreadable manifest: %v", ErrCorruptCapsule, err)
	}

	if with.IsZero() {
		return manifest{}, nil, fmt.Errorf("capsule: %w", recoverykey.ErrUninitializedKey)
	}

	// Before any decapsulation. The manifest is not yet authenticated here, so this is a
	// courtesy to the operator holding the wrong kit, not a security check — the AEAD below
	// is the security check, and a forged ID that matches the wrong key still fails there.
	if m.RecoveryKeyID != with.Public().ID() {
		return manifest{}, nil, ErrWrongRecoveryKey
	}

	enc, err := base64.StdEncoding.DecodeString(m.EncapsulatedKey)
	if err != nil {
		return manifest{}, nil, fmt.Errorf("%w: encapsulated key is not standard base64: %v", ErrCorruptCapsule, err)
	}
	if len(enc) != recoverykey.EncapsulationBytes {
		return manifest{}, nil, fmt.Errorf("%w: encapsulated key is %d bytes, want %d", ErrCorruptCapsule, len(enc), recoverykey.EncapsulationBytes)
	}

	ct, err := DecodeCiphertext(cf.Ciphertext)
	if err != nil {
		return manifest{}, nil, err
	}

	recipient, err := hpke.NewRecipient(enc, with.HPKE(), hpkeKDF(), hpkeAEAD(), hpkeInfo())
	if err != nil {
		return manifest{}, nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	// The manifest is the additional authenticated data, so any edit to it fails here
	// rather than being handed to the caller as fact.
	payload, err := recipient.Open(cf.Manifest, ct)
	if err != nil {
		return manifest{}, nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	if err := verifyPayloadHash(payload, m.PayloadHash); err != nil {
		return manifest{}, nil, err
	}
	return m, payload, nil
}

func checkContainerSize(part string, size int) error {
	if size > MaxContainerBytes {
		return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrCapsuleTooLarge, part, size, MaxContainerBytes)
	}
	return nil
}

// verifyPayloadHash is the last line of defence when the AEAD passes for a reason nobody
// predicted. It is load-bearing.
func verifyPayloadHash(payload []byte, want string) error {
	if want == "" {
		return fmt.Errorf("%w: manifest declares no payload hash", ErrCorruptCapsule)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != want {
		return ErrCorruptCapsule
	}
	return nil
}
