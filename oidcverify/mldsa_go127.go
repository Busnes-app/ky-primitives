//go:build go1.27

package oidcverify

import (
	"crypto/mldsa"
	"fmt"
)

const mldsa65Supported = true

type mldsaPublicKey = *mldsa.PublicKey

// Compile-time check that the Go 1.26-compatible constant matches stdlib crypto/mldsa.
const (
	_ uint = MLDSA65PublicKeySize - mldsa.MLDSA65PublicKeySize
	_ uint = mldsa.MLDSA65PublicKeySize - MLDSA65PublicKeySize
)

func parseMLDSA65PublicKey(raw []byte) (mldsaPublicKey, error) {
	if len(raw) != MLDSA65PublicKeySize {
		return nil, fmt.Errorf("%w: ML-DSA-65 public key must be %d bytes", ErrWeakKey, MLDSA65PublicKeySize)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ML-DSA-65 public key: %v", ErrWeakKey, err)
	}
	return pub, nil
}

func verifyMLDSA65(pub mldsaPublicKey, signingInput, sig []byte) error {
	if pub == nil || len(sig) != mldsa.MLDSA65SignatureSize {
		return ErrSignature
	}
	// RFC 9964 §3.1: pure ML-DSA-65 over the JWS Signing Input with an empty context string.
	if err := mldsa.Verify(pub, signingInput, sig, &mldsa.Options{Context: ""}); err != nil {
		return ErrSignature
	}
	return nil
}

// MarshalMLDSA65PublicJWK encodes a Go 1.27 *mldsa.PublicKey (ML-DSA-65) as an
// RFC 9964 AKP PublicJWK for publication in a JWKS.
func MarshalMLDSA65PublicJWK(kid string, pub *mldsa.PublicKey) (PublicJWK, error) {
	if pub == nil || *pub == (mldsa.PublicKey{}) {
		return PublicJWK{}, fmt.Errorf("%w: nil or uninitialized ML-DSA-65 public key", ErrWeakKey)
	}
	if pub.Parameters() != mldsa.MLDSA65() {
		return PublicJWK{}, fmt.Errorf("%w: AKP key must use ML-DSA-65", ErrWeakKey)
	}
	return MarshalAKPPublicJWK(kid, pub.Bytes())
}

// ParseMLDSA65PublicJWK validates an RFC 9964 AKP PublicJWK and returns its
// *mldsa.PublicKey.
func ParseMLDSA65PublicJWK(k PublicJWK) (*mldsa.PublicKey, error) {
	raw, err := ParseAKPPublicJWK(k)
	if err != nil {
		return nil, err
	}
	return parseMLDSA65PublicKey(raw)
}
