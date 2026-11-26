//go:build go1.27

// Package hybridsig signs with ML-DSA-65 and Ed25519 together; a signature verifies only if
// both halves do, so it stands while either algorithm does. It needs Go 1.27 (crypto/mldsa).
//
// The construction is kyguard-server's (internal/pqcrypto/sig.go @ 37b302b), kept as it is:
// both halves sign the same 32-byte digest
//
//	D = SHA-256(label ‖ 0x00 ‖ msg)
//
// ML-DSA-65 (FIPS 204, hedged, empty context) and pure Ed25519 (RFC 8032) each sign D.
// The label names the caller and purpose ("kyguard/1/tx"), so a signature made for one
// purpose never verifies for another. kyguard's own digest is this one with its
// "kyguard/1/<type>" label and JCS bytes as msg, so kyguard can import this package.
//
// Encodings, each starting with the algorithm tag Alg and a 0x00:
//
//	public key: "mldsa65+ed25519" 0x00 ‖ ML-DSA-65 public key (1952) ‖ Ed25519 public key (32)
//	signature:  "mldsa65+ed25519" 0x00 ‖ ML-DSA-65 signature (3309)  ‖ Ed25519 signature (64)
//	key ID:     "mldsa65+ed25519:" ‖ lowercase hex SHA-256("ky/hybridsig/1/key-id" 0x00 ‖ public key)
//
// This is a Ky-internal format. It is not the RFC 10073 X.509 composite signature and not
// the draft JOSE composite: neither reads it, and it reads neither. Use it only where Ky
// code signs and Ky code verifies; testdata/vectors.json is the contract for other
// languages.
package hybridsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// Alg is the only algorithm tag.
	Alg = "mldsa65+ed25519"
	// SeedBytes is the length of each of the two private key seeds.
	SeedBytes = 32
	// PublicKeyBytes is the length of an encoded public key.
	PublicKeyBytes = len(tag) + mldsa.MLDSA65PublicKeySize + ed25519.PublicKeySize
	// SignatureBytes is the length of an encoded signature.
	SignatureBytes = len(tag) + mldsa.MLDSA65SignatureSize + ed25519.SignatureSize
)

const (
	tag     = Alg + "\x00"
	idLabel = "ky/hybridsig/1/key-id\x00"
)

var (
	// ErrAlg reports an encoding whose tag is not Alg.
	ErrAlg = errors.New("hybridsig: algorithm is not " + Alg)
	// ErrLength reports a seed, key or signature of the wrong length.
	ErrLength = errors.New("hybridsig: wrong length")
	// ErrLabel reports an empty label or one containing 0x00.
	ErrLabel = errors.New("hybridsig: label must be non-empty and contain no 0x00")
	// ErrSignature reports a signature that does not verify. Which half failed is not said.
	ErrSignature = errors.New("hybridsig: signature does not verify")
	// ErrUninitializedKey reports a nil or zero-value key.
	ErrUninitializedKey = errors.New("hybridsig: zero-value key; use Generate, FromSeeds or ParsePublicKey")
)

// PrivateKey is a hybrid signing key.
type PrivateKey struct {
	mldsa *mldsa.PrivateKey
	ed    ed25519.PrivateKey
}

// PublicKey is a hybrid verification key.
type PublicKey struct {
	mldsa *mldsa.PublicKey
	ed    ed25519.PublicKey
}

// Generate makes a fresh key.
func Generate() (*PrivateKey, error) {
	m, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	_, ed, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	return &PrivateKey{mldsa: m, ed: ed}, nil
}

// FromSeeds rebuilds a key from its ML-DSA-65 and Ed25519 seeds, 32 bytes each.
func FromSeeds(mldsaSeed, edSeed []byte) (*PrivateKey, error) {
	if len(mldsaSeed) != SeedBytes || len(edSeed) != ed25519.SeedSize {
		return nil, ErrLength
	}
	m, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mldsaSeed)
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	return &PrivateKey{mldsa: m, ed: ed25519.NewKeyFromSeed(edSeed)}, nil
}

// Seeds returns copies of the two seeds, the only private encoding.
func (k *PrivateKey) Seeds() (mldsaSeed, edSeed []byte) {
	return k.mldsa.Bytes(), bytes.Clone(k.ed.Seed())
}

// Public returns the matching public key.
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{mldsa: k.mldsa.PublicKey(), ed: bytes.Clone(k.ed.Public().(ed25519.PublicKey))}
}

// digest is D = SHA-256(label ‖ 0x00 ‖ msg). A label with 0x00 in it could move bytes
// between label and msg, so it is refused.
func digest(label string, msg []byte) ([]byte, error) {
	if label == "" || strings.IndexByte(label, 0) >= 0 {
		return nil, ErrLabel
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(msg)
	return h.Sum(nil), nil
}

// Sign signs msg under label with both halves and returns the encoded signature.
func (k *PrivateKey) Sign(label string, msg []byte) ([]byte, error) {
	if k == nil || k.mldsa == nil {
		return nil, ErrUninitializedKey
	}
	d, err := digest(label, msg)
	if err != nil {
		return nil, err
	}
	m, err := k.mldsa.Sign(nil, d, &mldsa.Options{Context: ""})
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	out := make([]byte, 0, SignatureBytes)
	return append(append(append(out, tag...), m...), ed25519.Sign(k.ed, d)...), nil
}

// ParsePublicKey reads an encoded public key.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	if !bytes.HasPrefix(b, []byte(tag)) {
		return nil, ErrAlg
	}
	if len(b) != PublicKeyBytes {
		return nil, ErrLength
	}
	b = b[len(tag):]
	m, err := mldsa.NewPublicKey(mldsa.MLDSA65(), b[:mldsa.MLDSA65PublicKeySize])
	if err != nil {
		return nil, fmt.Errorf("hybridsig: %w", err)
	}
	return &PublicKey{mldsa: m, ed: bytes.Clone(b[mldsa.MLDSA65PublicKeySize:])}, nil
}

// Bytes returns the encoded public key, or nil if p is zero.
func (p *PublicKey) Bytes() []byte {
	if p == nil || p.mldsa == nil {
		return nil
	}
	out := make([]byte, 0, PublicKeyBytes)
	return append(append(append(out, tag...), p.mldsa.Bytes()...), p.ed...)
}

// ID returns "mldsa65+ed25519:" and the hex key ID, or "" if p is zero.
func (p *PublicKey) ID() string {
	b := p.Bytes()
	if b == nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(idLabel))
	h.Write(b)
	return Alg + ":" + hex.EncodeToString(h.Sum(nil))
}

// Verify checks an encoded signature over msg under label. Both halves are always checked
// and both must verify.
func (p *PublicKey) Verify(label string, msg, sig []byte) error {
	if p == nil || p.mldsa == nil {
		return ErrUninitializedKey
	}
	d, err := digest(label, msg)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(sig, []byte(tag)) {
		return ErrAlg
	}
	if len(sig) != SignatureBytes {
		return ErrSignature
	}
	sig = sig[len(tag):]
	errM := mldsa.Verify(p.mldsa, d, sig[:mldsa.MLDSA65SignatureSize], &mldsa.Options{Context: ""})
	okE := ed25519.Verify(p.ed, d, sig[mldsa.MLDSA65SignatureSize:])
	if errM != nil || !okE {
		return ErrSignature
	}
	return nil
}
