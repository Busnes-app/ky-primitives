//go:build !go1.27

package oidcverify

import "fmt"

const mldsa65Supported = false

type mldsaPublicKey struct{}

func parseMLDSA65PublicKey(raw []byte) (mldsaPublicKey, error) {
	if len(raw) != MLDSA65PublicKeySize {
		return mldsaPublicKey{}, fmt.Errorf("%w: ML-DSA-65 public key must be %d bytes", ErrWeakKey, MLDSA65PublicKeySize)
	}
	return mldsaPublicKey{}, nil
}

func verifyMLDSA65(mldsaPublicKey, []byte, []byte) error {
	return ErrAlgorithm
}
