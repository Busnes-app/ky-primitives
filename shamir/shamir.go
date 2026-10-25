// Package shamir splits a secret into custodian shares and reconstructs it.
//
// The suite carried two implementations over two different GF(2^8) fields — 0x11d in
// ky_server_base, gridlock-server and kysignon-server, 0x11b in kyrecovery-server. They
// silently reconstruct different secrets: 63232 of the 65536 products in their
// multiplication tables disagree. It stayed hidden because shares 1, 2 and 3 make every
// Lagrange coefficient 1, so the combine degenerates to XOR and agrees in any field, and
// those are the shares a round-trip test reaches for first.
//
// This package uses 0x11b, the AES field, and pins it with golden vectors.
//
// Arithmetic here is branch-free and table-free. Both predecessors indexed exp/log
// tables with share bytes, which are the secret; this one multiplies with shifts and
// masks and inverts by exponentiation, so no memory access depends on a secret value.
// It is slower and a capsule split is not a hot path.
package shamir

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version tags the wire format and, with it, the field.
//
// A share used to be "index-hex" with nothing else in it. That made a share from the
// suite's 0x11d implementations byte-indistinguishable from one of these, and combining
// across the two returns a different secret with no error at all. The tag is what turns
// that into a refusal.
const Version = "ky2"

// setIDBytes is the width of a set identifier.
//
// 128 bits, because a collision means the check the field exists for silently does not
// happen. The first version of this format carried 32, which reached even odds of a
// collision after about 65,000 splits — a number a deployment issuing recovery kits
// actually reaches. That version is not parsed: nothing outside this package ever wrote a
// share, so there are no cards to strand.
const setIDBytes = 16

// MaxSecretBytes bounds memory and CPU when shares come from an untrusted decoder. Recovery
// secrets are normally tens of bytes; 1 MiB leaves ample room for other uses.
const MaxSecretBytes = 1 << 20

var (
	// ErrNotEnoughShares reports fewer shares than the threshold the shares themselves
	// declare.
	ErrNotEnoughShares = errors.New("shamir: fewer shares than the threshold requires")
	// ErrShareVersion reports a share that is not this wire format.
	ErrShareVersion = errors.New("shamir: share is not " + Version + " format")
	// ErrShareSet reports shares that do not belong to one split.
	ErrShareSet = errors.New("shamir: shares belong to different splits")
	// ErrDuplicateIndex reports shares repeating an index, which makes a Lagrange
	// denominator zero.
	ErrDuplicateIndex = errors.New("shamir: shares repeat an index")
	// ErrShareIndex reports a share at index 0, the point the secret itself sits on.
	ErrShareIndex = errors.New("shamir: share index must be 1-255")
	// ErrShareLength reports shares of differing or zero length.
	ErrShareLength = errors.New("shamir: shares differ in length")
	// ErrMalformedShare reports a string that is not a share.
	ErrMalformedShare = errors.New("shamir: share is not index-hex")
)

// Share is one custodian's portion of a secret.
//
// Threshold and SetID travel with the share rather than in a manifest the custodian may
// not have. They are not secret — a share already reveals nothing about the secret — and
// they let Combine refuse the two mistakes that previously produced a plausible wrong
// answer: too few shares, and shares from two different splits.
type Share struct {
	Threshold int
	SetID     [setIDBytes]byte
	Index     byte
	Value     []byte
}

// String renders a share for a custodian card:
//
//	ky2-<threshold>-<set id>-<index>-<value>-<check>
//
// check is the first two bytes of SHA-256 over everything preceding it, so a card
// mistyped under stress fails at parse rather than reconstructing a wrong secret.
func (s Share) String() string {
	body := s.body()
	return body + "-" + checksum(body)
}

func (s Share) body() string {
	return Version +
		"-" + strconv.Itoa(s.Threshold) +
		"-" + hex.EncodeToString(s.SetID[:]) +
		"-" + strconv.Itoa(int(s.Index)) +
		"-" + hex.EncodeToString(s.Value)
}

func checksum(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:2])
}

// ParseShare reads a share off a custodian card. Surrounding space is accepted because a
// human types this; case is not, because the checksum covers the exact bytes.
func ParseShare(encoded string) (Share, error) {
	encoded = strings.TrimSpace(encoded)
	parts := strings.Split(encoded, "-")
	if len(parts) != 6 {
		return Share{}, fmt.Errorf("%w: %d fields, want 6", ErrShareVersion, len(parts))
	}
	if parts[0] != Version {
		return Share{}, fmt.Errorf("%w: tag %q", ErrShareVersion, parts[0])
	}

	body := encoded[:strings.LastIndex(encoded, "-")]
	if want := checksum(body); parts[5] != want {
		return Share{}, fmt.Errorf("%w: checksum %q, expected %q — check the card for a mistyped character", ErrMalformedShare, parts[5], want)
	}

	threshold, err := strconv.Atoi(parts[1])
	if err != nil || threshold < 2 || threshold > 255 {
		return Share{}, fmt.Errorf("%w: threshold %q", ErrMalformedShare, parts[1])
	}
	var setID [setIDBytes]byte
	idBytes, err := hex.DecodeString(parts[2])
	if err != nil || len(idBytes) != setIDBytes {
		return Share{}, fmt.Errorf("%w: set id %q", ErrMalformedShare, parts[2])
	}
	copy(setID[:], idBytes)
	index, err := strconv.Atoi(parts[3])
	if err != nil {
		return Share{}, fmt.Errorf("%w: %v", ErrMalformedShare, err)
	}
	if index < 1 || index > 255 {
		return Share{}, ErrShareIndex
	}
	value, err := hex.DecodeString(parts[4])
	if err != nil {
		return Share{}, fmt.Errorf("%w: %v", ErrMalformedShare, err)
	}
	if len(value) == 0 {
		return Share{}, ErrShareLength
	}
	return Share{Threshold: threshold, SetID: setID, Index: byte(index), Value: value}, nil
}

// Split divides secret into total shares, any threshold of which reconstruct it.
func Split(secret []byte, threshold, total int) ([]Share, error) {
	switch {
	case len(secret) == 0:
		return nil, errors.New("shamir: refusing to split an empty secret")
	case len(secret) > MaxSecretBytes:
		return nil, fmt.Errorf("shamir: secret is %d bytes, limit is %d", len(secret), MaxSecretBytes)
	case threshold < 2:
		return nil, errors.New("shamir: threshold must be at least 2")
	case threshold > total:
		return nil, errors.New("shamir: threshold exceeds the share count")
	case total > 255:
		return nil, errors.New("shamir: at most 255 shares fit in GF(2^8)")
	}

	// A random set identifier so shares of two different splits cannot be combined into
	// a plausible wrong secret. 128 bits because the cost of a collision is that this very
	// check silently does not happen, and 32 bits reached even odds of one after about
	// 65,000 splits — a number a deployment issuing recovery kits actually reaches.
	var set [setIDBytes]byte
	if _, err := rand.Read(set[:]); err != nil {
		return nil, fmt.Errorf("shamir: %w", err)
	}

	shares := make([]Share, total)
	for i := range shares {
		shares[i] = Share{
			Threshold: threshold,
			SetID:     set,
			Index:     byte(i + 1),
			Value:     make([]byte, len(secret)),
		}
	}

	coefficients := make([]byte, threshold)
	for byteIndex, secretByte := range secret {
		coefficients[0] = secretByte
		// Never resample a zero leading coefficient: refusing it rules out one secret
		// value per byte for anyone holding threshold-1 shares.
		if _, err := rand.Read(coefficients[1:]); err != nil {
			return nil, fmt.Errorf("shamir: %w", err)
		}
		for i := range shares {
			shares[i].Value[byteIndex] = evaluate(coefficients, shares[i].Index)
		}
	}
	return shares, nil
}

// Combine reconstructs a secret by Lagrange interpolation at x=0. Every share given is
// used; passing more than the threshold is correct and passing fewer returns a wrong
// secret rather than an error, for the reason on ErrNotEnoughShares.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("%w: got %d", ErrNotEnoughShares, len(shares))
	}
	size := len(shares[0].Value)
	if size == 0 {
		return nil, ErrShareLength
	}
	if size > MaxSecretBytes {
		return nil, fmt.Errorf("%w: share is %d bytes, limit is %d", ErrShareLength, size, MaxSecretBytes)
	}
	var seen [256]bool
	for _, s := range shares {
		switch {
		case s.Index == 0:
			return nil, ErrShareIndex
		case seen[s.Index]:
			return nil, ErrDuplicateIndex
		case len(s.Value) != size:
			return nil, ErrShareLength
		}
		seen[s.Index] = true
	}

	// Set consistency after the per-share checks, so a malformed share is reported as
	// malformed rather than as a set mismatch.
	threshold, set := shares[0].Threshold, shares[0].SetID
	for _, s := range shares {
		if s.Threshold != threshold || s.SetID != set {
			return nil, fmt.Errorf("%w: expected threshold %d set %x, found threshold %d set %x",
				ErrShareSet, threshold, set, s.Threshold, s.SetID)
		}
	}
	// Every share must declare a threshold this package could have produced. The check
	// used to be skipped for threshold zero, on the reasoning that a hand-built share
	// carries no declaration to enforce — but zero is what an absent field decodes to, so
	// the unenforced mode was the one a deserialised share landed in by default, and a
	// caller reading the field could reasonably think it had been checked.
	if threshold < 2 || threshold > 255 {
		return nil, fmt.Errorf("%w: shares declare threshold %d, which no split produces", ErrMalformedShare, threshold)
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("%w: %d shares, the split needs %d", ErrNotEnoughShares, len(shares), threshold)
	}

	// Distinct non-zero indices make every denominator non-zero, so no inverse here can
	// be of zero and Combine cannot divide by zero however malformed its input.
	basis := make([]byte, len(shares))
	for i, si := range shares {
		numerator, denominator := byte(1), byte(1)
		for j, sj := range shares {
			if i == j {
				continue
			}
			numerator = mul(numerator, sj.Index)
			denominator = mul(denominator, si.Index^sj.Index)
		}
		basis[i] = mul(numerator, inverse(denominator))
	}

	secret := make([]byte, size)
	for b := range secret {
		var acc byte
		for i, s := range shares {
			acc ^= mul(s.Value[b], basis[i])
		}
		secret[b] = acc
	}
	return secret, nil
}

// evaluate computes the polynomial at x by Horner's method, constant term first.
func evaluate(coefficients []byte, x byte) byte {
	var y byte
	for i := len(coefficients) - 1; i >= 0; i-- {
		y = mul(y, x) ^ coefficients[i]
	}
	return y
}

// mul multiplies in GF(2^8) mod 0x11b. Branch-free: the conditionals are mask arithmetic
// so neither timing nor memory access depends on a or b.
func mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= a & -(b & 1)
		high := a >> 7
		a <<= 1
		a ^= 0x1b & -high
		b >>= 1
	}
	return p
}

// inverse returns a^254, which is a^-1 for every non-zero a, and 0 for 0. The exponent's
// bits are a compile-time constant, so the branch does not depend on a.
func inverse(a byte) byte {
	result, power := byte(1), a
	for e := 0; e < 8; e++ {
		if (254>>e)&1 == 1 {
			result = mul(result, power)
		}
		power = mul(power, power)
	}
	return result
}
