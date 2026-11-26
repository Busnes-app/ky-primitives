// Package xwing seals a message to an X-Wing public key and opens it with the private key.
//
// X-Wing is ML-KEM-768 combined with X25519 (KEM 0x647A), so a recorded ciphertext stays
// safe unless both are broken. Sealing is HPKE base mode (RFC 9180) through the standard
// library's crypto/hpke: KEM MLKEM768X25519, KDF HKDF-SHA256, AEAD AES-256-GCM. Any HPKE
// implementation with that suite can read the output; testdata/vectors.json pins it.
//
// The wire format is
//
//	version (1 byte, 0x01) ‖ enc (1120 bytes) ‖ HPKE ciphertext (len(msg) + 16 bytes)
//
// Version 1 means exactly this suite. The suite identifiers are already bound into HPKE's
// key schedule; the version byte lets a reader refuse a format it does not know before it
// tries any key. info is the HPKE info and aad the AEAD's additional data, both unchanged.
//
// The keypair is the one recoverykey uses (same seed, same 1216-byte public key), with a
// domain-separated ID. recoverykey keeps its own type and ID so capsules do not change.
package xwing

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// SeedBytes is the length of a private key seed.
	SeedBytes = 32
	// PublicKeyBytes is an X-Wing public key: ML-KEM-768 encapsulation key plus X25519 point.
	PublicKeyBytes = 1184 + 32
	// EncapsulationBytes is an X-Wing encapsulated key: ML-KEM-768 ciphertext plus X25519 point.
	EncapsulationBytes = 1088 + 32
	// Version is the first byte of every sealed message.
	Version byte = 1
	// Overhead is how many bytes Seal adds to a message.
	Overhead = 1 + EncapsulationBytes + 16
)

// idLabel separates key IDs from every other SHA-256 of a public key, recoverykey's included.
const idLabel = "ky/xwing/1/key-id\x00"

var (
	// ErrSeedLength reports a seed that is not exactly SeedBytes long.
	ErrSeedLength = errors.New("xwing: seed must be exactly 32 bytes")
	// ErrPublicKeyLength reports public key bytes that are not exactly PublicKeyBytes long.
	ErrPublicKeyLength = errors.New("xwing: public key must be exactly 1216 bytes")
	// ErrUninitializedKey reports a zero-value key used as if it were real.
	ErrUninitializedKey = errors.New("xwing: zero-value key; use Generate, FromSeed or ParsePublicKey")
	// ErrLabel reports an info that does not start with a caller label.
	ErrLabel = errors.New("xwing: info must start with a non-empty caller label")
	// ErrVersion reports a sealed message whose version byte is not Version.
	ErrVersion = errors.New("xwing: unknown sealed-message version")
	// ErrOpen reports a sealed message that does not open: wrong key, info or aad, or
	// a changed byte. It says nothing more, on purpose.
	ErrOpen = errors.New("xwing: message does not open")
)

func kem() hpke.KEM   { return hpke.MLKEM768X25519() }
func kdf() hpke.KDF   { return hpke.HKDFSHA256() }
func aead() hpke.AEAD { return hpke.AES256GCM() }

// PrivateKey is an X-Wing private key. Like any Go value it cannot be erased from memory.
type PrivateKey struct {
	seed [SeedBytes]byte
	key  hpke.PrivateKey
}

// PublicKey is an X-Wing public key.
type PublicKey struct {
	key hpke.PublicKey
}

// Generate makes a fresh keypair.
func Generate() (PrivateKey, error) {
	k, err := kem().GenerateKey()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("xwing: %w", err)
	}
	seed, err := k.Bytes()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("xwing: %w", err)
	}
	return FromSeed(seed)
}

// FromSeed rebuilds a private key from its 32-byte seed.
func FromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedBytes {
		return PrivateKey{}, fmt.Errorf("%w: got %d", ErrSeedLength, len(seed))
	}
	k, err := kem().NewPrivateKey(seed)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("xwing: %w", err)
	}
	p := PrivateKey{key: k}
	copy(p.seed[:], seed)
	return p, nil
}

// ParsePublicKey reads a 1216-byte public key.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != PublicKeyBytes {
		return PublicKey{}, fmt.Errorf("%w: got %d", ErrPublicKeyLength, len(b))
	}
	k, err := kem().NewPublicKey(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("xwing: %w", err)
	}
	return PublicKey{key: k}, nil
}

// Seed returns a copy of the 32-byte seed, the only private encoding.
func (k PrivateKey) Seed() []byte { return bytes.Clone(k.seed[:]) }

// Public returns the matching public key, or the zero PublicKey if k is zero.
func (k PrivateKey) Public() PublicKey {
	if k.IsZero() {
		return PublicKey{}
	}
	return PublicKey{key: k.key.PublicKey()}
}

// IsZero reports whether k holds no key.
func (k PrivateKey) IsZero() bool { return k.key == nil }

// Bytes returns a copy of the 1216-byte encoding, or nil if p is zero.
func (p PublicKey) Bytes() []byte {
	if p.IsZero() {
		return nil
	}
	return bytes.Clone(p.key.Bytes())
}

// ID is lowercase hex SHA-256("ky/xwing/1/key-id" ‖ 0x00 ‖ Bytes()), or "" if p is zero.
func (p PublicKey) ID() string {
	if p.IsZero() {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(idLabel))
	h.Write(p.key.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

// IsZero reports whether p holds no key.
func (p PublicKey) IsZero() bool { return p.key == nil }

// checkLabel requires info to be label, or label ‖ 0x00 ‖ context, with a non-empty
// label such as "kyidentity/ad-password/2". The label is what keeps one caller's
// ciphertext from opening in another caller's context.
func checkLabel(info []byte) error {
	label, _, _ := bytes.Cut(info, []byte{0})
	if len(label) == 0 {
		return ErrLabel
	}
	return nil
}

// Seal encrypts msg to pub, binding info into the key schedule and aad into the AEAD.
func Seal(pub PublicKey, info, aad, msg []byte) ([]byte, error) {
	if pub.IsZero() {
		return nil, ErrUninitializedKey
	}
	if err := checkLabel(info); err != nil {
		return nil, err
	}
	enc, s, err := hpke.NewSender(pub.key, kdf(), aead(), info)
	if err != nil {
		return nil, fmt.Errorf("xwing: %w", err)
	}
	ct, err := s.Seal(aad, msg)
	if err != nil {
		return nil, fmt.Errorf("xwing: %w", err)
	}
	out := make([]byte, 0, 1+len(enc)+len(ct))
	return append(append(append(out, Version), enc...), ct...), nil
}

// Open decrypts a Seal output. It needs the same info and aad the sender used.
func Open(priv PrivateKey, info, aad, sealed []byte) ([]byte, error) {
	if priv.IsZero() {
		return nil, ErrUninitializedKey
	}
	if err := checkLabel(info); err != nil {
		return nil, err
	}
	if len(sealed) == 0 || sealed[0] != Version {
		return nil, ErrVersion
	}
	if len(sealed) < Overhead {
		return nil, ErrOpen
	}
	enc, ct := sealed[1:1+EncapsulationBytes], sealed[1+EncapsulationBytes:]
	r, err := hpke.NewRecipient(enc, priv.key, kdf(), aead(), info)
	if err != nil {
		return nil, ErrOpen
	}
	msg, err := r.Open(aad, ct)
	if err != nil {
		return nil, ErrOpen
	}
	return msg, nil
}
