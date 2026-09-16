package recoverykey

import "github.com/Busnes-app/ky-primitives/shamir"

// Split divides the private key's seed into total custodian shares, any threshold of which
// rebuild it. It is thin over shamir.Split, and exists so that the thing being split is the
// seed by construction: splitting the wrong 32 bytes would fail at restore through the
// capsule's key ID check, and "fails at restore" is the failure this package exists to move
// earlier. A zero-value key would otherwise split thirty-two zero bytes into perfectly
// printable custodian cards that open nothing.
func Split(k PrivateKey, threshold, total int) ([]shamir.Share, error) {
	if k.IsZero() {
		return nil, ErrUninitializedKey
	}
	return shamir.Split(k.Seed(), threshold, total)
}

// Combine rebuilds the private key from custodian shares. shamir.Combine refuses shares
// from different splits, of different lengths, or fewer than their threshold; anything it
// lets through that is not 32 bytes was never a seed and fails FromSeed.
func Combine(shares []shamir.Share) (PrivateKey, error) {
	seed, err := shamir.Combine(shares)
	if err != nil {
		return PrivateKey{}, err
	}
	return FromSeed(seed)
}
