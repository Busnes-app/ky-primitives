package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// Seal writes a kycap/3 container sealed to the suite recovery public key, and returns it
// with the manifest it sealed.
//
// The manifest is returned because Seal is the only place CapsuleID, CreatedAt and
// PayloadHash exist: they are minted here and have no other source. Returning only the
// bytes left a caller re-parsing its own output through ReadUnverifiedManifest to recover
// them — reaching for the keyless reader, whose doc comment says not to decide on what it
// returns, to read fields it had just authored. This value is a Manifest because it is the
// one that went into the AEAD, not one read back out of a container.
//
// Seal returns no key. The payload is sealed to a public key through HPKE, the shared
// secret exists only inside crypto/hpke for the duration of this call, and the only thing
// that opens the result is the recovery private key the custodians hold in shares. A
// product that calls Seal holds nothing afterwards that it did not hold before.
//
// That is a statement about confidentiality, not origin: the public key is not secret, and
// a capsule Open accepts could have been sealed by anyone who holds it. Authenticity comes
// from the channel that deposits the capsule, not from the container.
func Seal(serviceName, appVersion string, files []File, deps, recipe map[string]any, threshold, totalShares int, to recoverykey.PublicKey) (raw []byte, m Manifest, err error) {
	if len(files) == 0 {
		return nil, Manifest{}, fmt.Errorf("refusing to seal a capsule with no files")
	}
	if to.IsZero() {
		return nil, Manifest{}, fmt.Errorf("capsule: %w", recoverykey.ErrUninitializedKey)
	}
	// The same invariant shamir.Split enforces. A capsule states its recovery topology in
	// the manifest, and a capsule advertising 5-of-3 — or 0-of-3, which reads as "no
	// shares needed" — sends a custodian looking for a kit that was never issuable.
	// Recording the number without checking it makes the manifest decoration.
	if threshold < 2 || totalShares < threshold || totalShares > 255 {
		return nil, Manifest{}, fmt.Errorf("capsule: %d-of-%d is not a recoverable kit; need 2 <= threshold <= total <= 255", threshold, totalShares)
	}

	payload, entries, err := buildPayload(files)
	if err != nil {
		return nil, Manifest{}, err
	}

	// The encapsulated key is minted before the manifest because the manifest carries it,
	// and the manifest is the AAD for the seal that follows.
	enc, sender, err := hpke.NewSender(to.HPKE(), hpkeKDF(), hpkeAEAD(), hpkeInfo())
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("failed to encapsulate capsule key: %w", err)
	}

	sum := sha256.Sum256(payload)

	now := time.Now().UTC()
	sealedManifest := manifest{
		CapsuleID:          fmt.Sprintf("cap-%s-%d", serviceName, now.UnixNano()),
		ServiceName:        serviceName,
		AppVersion:         appVersion,
		CreatedAt:          now,
		PayloadHash:        hex.EncodeToString(sum[:]),
		Threshold:          threshold,
		TotalShares:        totalShares,
		RecoveryKeyID:      to.ID(),
		EncapsulatedKey:    base64.StdEncoding.EncodeToString(enc),
		Files:              entries,
		Dependencies:       deps,
		VerificationRecipe: recipe,
	}
	// Marshalled once, then used twice: these bytes are the AAD and they are what lands
	// in the container. Deriving the AAD from a second encoding of the same struct would
	// make every capsule depend on two encoders agreeing forever. The returned Manifest
	// wraps this same value, so it is the sealed one rather than a second construction —
	// TestSealReturnsTheManifestItSealed re-encodes it against the container's own bytes.
	manifestBytes, err := json.Marshal(sealedManifest)
	if err != nil {
		return nil, Manifest{}, err
	}
	// The last limit Open enforces that sealing can reach. The manifest grows with caller
	// input in several places — deps, recipe, and the version strings — and none of them is
	// individually bounded, which is why the whole marshalled manifest is what gets
	// measured here rather than any one field. The file list is not among them: it is not
	// marshalled into the manifest at all, and buildPayload bounds it separately.
	//
	// Seal used to return a key for an oversized manifest and every later read of it failed
	// with ErrCorruptCapsule — a backup that cannot be restored, found at restore time.
	// TestSealRefusesWhatOpenWouldRefuse holds this, for both bounds.
	if len(manifestBytes) > maxManifestBytes {
		return nil, Manifest{}, fmt.Errorf("%w: manifest is %d bytes, Open permits %d", ErrCapsuleTooLarge, len(manifestBytes), maxManifestBytes)
	}

	sealed, err := sender.Seal(manifestBytes, payload)
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("failed to seal capsule: %w", err)
	}

	// json.Marshal rather than MarshalIndent: indenting re-spaces the embedded manifest,
	// and the AAD is the manifest's exact bytes. A pretty container that cannot be opened
	// is not a trade worth making.
	raw, err = json.Marshal(kycapFile{
		Format:     KycapFileFormat,
		Manifest:   manifestBytes,
		Ciphertext: EncodeCiphertext(sealed),
	})
	if err != nil {
		return nil, Manifest{}, err
	}
	return raw, Manifest{UnverifiedManifest: sealedManifest}, nil
}

// buildPayload writes the files as a gzipped tar, the plaintext both containers hold, and
// the manifest entries describing it.
//
// Every limit Open enforces is enforced here too, bar the manifest bound Seal applies to
// the encoded bytes. Sealing is the only place the failure is cheap: a capsule that Open
// refuses is a backup that cannot be restored, and it was previously reachable by sealing
// one file past the limit, or two paths that normalise to one destination.
//
// The entries are built here, from the normalised name and clamped mode this writes, so
// they describe the members a restore actually produces rather than the caller's spelling
// of them. Built anywhere else they are a second normalisation to keep in step.
//
// They are also written here, as the reserved member, so the list the key protects and the
// list Seal returns are one encoding of one slice.
func buildPayload(files []File) ([]byte, []FileEntry, error) {
	if len(files) > MaxFiles {
		return nil, nil, fmt.Errorf("%w: %d files, Open permits %d", ErrCapsuleTooLarge, len(files), MaxFiles)
	}
	var total int64
	seen := make(map[string]struct{}, len(files))
	entries := make([]FileEntry, 0, len(files))

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, f := range files {
		// Seal enforces the same containment Open does, so a capsule this package writes
		// can never be one this package refuses to extract.
		name, err := safeRelPath(f.Path)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := seen[name]; dup {
			return nil, nil, fmt.Errorf("%w: %q", ErrDuplicatePath, name)
		}
		seen[name] = struct{}{}

		size := int64(len(f.Content))
		if size > MaxFileBytes {
			return nil, nil, fmt.Errorf("%w: %q is %d bytes, Open permits %d", ErrCapsuleTooLarge, name, size, MaxFileBytes)
		}
		total += size
		if total > MaxExpandedBytes {
			return nil, nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrCapsuleTooLarge, MaxExpandedBytes)
		}
		mode := f.Mode.Perm() & 0700
		if mode == 0 {
			mode = 0600
		}
		hdr := &tar.Header{
			Name:     name,
			Mode:     int64(mode),
			Size:     int64(len(f.Content)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(f.Content); err != nil {
			return nil, nil, err
		}

		fsum := sha256.Sum256(f.Content)
		entries = append(entries, FileEntry{
			Path: name,
			Size: size,
			Sum:  hex.EncodeToString(fsum[:]),
			Mode: mode,
		})
	}

	// The file list, written last as the reserved member. Both limits are the ones Open
	// applies to it: a capsule Seal writes is never one Open refuses. Nothing bounds a
	// caller's path lengths individually, so a single absurd path is what these catch.
	list, err := json.Marshal(entries)
	if err != nil {
		return nil, nil, err
	}
	if len(list) > maxFileListBytes {
		return nil, nil, fmt.Errorf("%w: file list is %d bytes, Open permits %d", ErrCapsuleTooLarge, len(list), maxFileListBytes)
	}
	if total+int64(len(list)) > MaxExpandedBytes {
		return nil, nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrCapsuleTooLarge, MaxExpandedBytes)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     reservedFileList,
		Mode:     0600,
		Size:     int64(len(list)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Now().UTC(),
	}); err != nil {
		return nil, nil, err
	}
	if _, err := tw.Write(list); err != nil {
		return nil, nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), entries, nil
}
