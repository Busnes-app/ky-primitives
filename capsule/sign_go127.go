//go:build go1.27

package capsule

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// VerifiedManifest is a capsule's manifest whose hybrid signature has been verified
// against a pinned signer public key, without decrypting the capsule payload.
//
// Unlike UnverifiedManifest, its fields are authenticated as authored by the holder of
// the signing key under ManifestSignatureLabel. Unlike Manifest, the encrypted payload
// has not been opened, so Files is empty and the ciphertext has not been decrypted or
// hash-checked.
//
// Like Manifest, it is a distinct type so a caller expecting a verified manifest (for
// example a blind backup store accepting deposits) cannot be handed an
// UnverifiedManifest by accident.
type VerifiedManifest struct {
	UnverifiedManifest
}

// SealSigned writes a kycap/3 container sealed to the suite recovery public key and signs
// the canonical manifest bytes with signer under ManifestSignatureLabel.
//
// The manifest records signer.Public().ID() in SignerKeyID before marshalling, so the
// signer identity is covered by both the HPKE AEAD and the hybrid signature. The
// base64-encoded signature is stored in the container's manifest_signature field.
//
// Existing callers using Open (including Go 1.26 binaries) can still open a signed
// capsule without verifying the signature. Callers that require origin authenticity use
// VerifyManifest (without the recovery key) or OpenSigned (with both keys).
func SealSigned(serviceName, appVersion string, files []File, deps, recipe map[string]any, threshold, totalShares int, to recoverykey.PublicKey, signer *hybridsig.PrivateKey) (raw []byte, m Manifest, err error) {
	if isZeroSigner(signer) {
		return nil, Manifest{}, fmt.Errorf("capsule: %w", hybridsig.ErrUninitializedKey)
	}
	pub := signer.Public()
	return seal(serviceName, appVersion, files, deps, recipe, threshold, totalShares, to, pub.ID(), func(manifestBytes []byte) (string, error) {
		sig, err := signer.Sign(ManifestSignatureLabel, manifestBytes)
		if err != nil {
			return "", fmt.Errorf("failed to sign capsule manifest: %w", err)
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	})
}

// VerifyManifest parses a kycap/3 container and verifies its hybrid manifest signature
// against by under ManifestSignatureLabel, without decrypting the payload.
//
// Both halves of the hybrid signature (ML-DSA-65 and Ed25519) must verify. It rejects
// unsigned containers with ErrMissingSignature and rejects tampered manifests, tampered
// signatures, wrong signer keys, wrong domains, or mismatched SignerKeyID fields with
// ErrInvalidSignature.
func VerifyManifest(raw []byte, by *hybridsig.PublicKey) (VerifiedManifest, error) {
	if by == nil || by.ID() == "" {
		return VerifiedManifest{}, fmt.Errorf("capsule: %w", hybridsig.ErrUninitializedKey)
	}
	cf, err := parseContainer(raw)
	if err != nil {
		return VerifiedManifest{}, err
	}
	return verifyContainerManifest(cf, by)
}

// OpenSigned verifies the capsule's hybrid manifest signature against signer under
// ManifestSignatureLabel, then decrypts and extracts the capsule with the recovery
// private key.
//
// Unlike Open, which accepts unsigned capsules and ignores any manifest signature,
// OpenSigned requires a valid signature from signer before decapsulating the payload or
// writing to targetDir. It returns ErrMissingSignature for unsigned containers and
// ErrInvalidSignature when signature verification fails.
func OpenSigned(raw []byte, with recoverykey.PrivateKey, signer *hybridsig.PublicKey, targetDir string) (Manifest, []File, error) {
	if signer == nil || signer.ID() == "" {
		return Manifest{}, nil, fmt.Errorf("capsule: %w", hybridsig.ErrUninitializedKey)
	}
	cf, err := parseContainer(raw)
	if err != nil {
		return Manifest{}, nil, err
	}
	if _, err := verifyContainerManifest(cf, signer); err != nil {
		return Manifest{}, nil, err
	}
	return openContainer(cf, with, targetDir)
}

func verifyContainerManifest(cf kycapFile, by *hybridsig.PublicKey) (VerifiedManifest, error) {
	m, err := decodeManifest(cf.Manifest)
	if err != nil {
		return VerifiedManifest{}, err
	}
	if cf.ManifestSignature == "" {
		return VerifiedManifest{}, ErrMissingSignature
	}
	if strings.ContainsAny(cf.ManifestSignature, "\r\n") {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest signature contains line breaks", ErrInvalidSignature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(cf.ManifestSignature)
	if err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest signature is not standard base64: %v", ErrInvalidSignature, err)
	}
	if err := by.Verify(ManifestSignatureLabel, cf.Manifest, sig); err != nil {
		return VerifiedManifest{}, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	if m.SignerKeyID != "" && m.SignerKeyID != by.ID() {
		return VerifiedManifest{}, fmt.Errorf("%w: manifest names signer %q, verified against %q", ErrInvalidSignature, m.SignerKeyID, by.ID())
	}
	return VerifiedManifest{UnverifiedManifest: m}, nil
}

func isZeroSigner(signer *hybridsig.PrivateKey) bool {
	return signer == nil || reflect.ValueOf(*signer).IsZero()
}
