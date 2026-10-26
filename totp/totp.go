// Package totp implements RFC 6238 time-based one-time passwords using only the standard
// library.
//
// All four implementations in the suite agreed on the arithmetic — HMAC-SHA1, 20-byte
// secret, 6 digits, 30-second period — so enrolled secrets stay valid across a migration
// onto this one. They disagreed on everything around it, and two of the three differences
// outlive the request:
//
// ky_server_base and gridlock-server build the enrolment URI by interpolation, so an
// account name carrying a '?' starts the query string early and the authenticator enrols
// the parameters the name supplies. The user's phone then holds a secret the server never
// issued, until they re-enrol. ProvisioningURI escapes instead.
//
// The same two return a bare bool from validation, so a caller cannot know which step
// matched and cannot spend it. A phished code stays valid for the whole 90-second window.
// Validate returns the counter for that reason; the caller records it and refuses a
// repeat.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Period is the step width in seconds.
	Period = 30
	// Digits is the code length.
	Digits = 6
	// secretBytes is the generated secret size, the RFC 4226 recommendation.
	secretBytes = 20
	// MinSecretBytes is RFC 4226 section 4's minimum shared-secret size (128 bits).
	MinSecretBytes = 16
)

// encoding is base32 without padding: authenticator apps reject the '=' characters.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new base32 secret to enrol.
func GenerateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: %w", err)
	}
	return encoding.EncodeToString(b), nil
}

// ProvisioningURI builds the otpauth:// URI encoded into the enrolment QR code.
//
// issuer and account are user-controlled in practice, so both are escaped. The label is
// one path segment carrying an unescaped ':' separator, which is what authenticators
// expect, and every parameter goes through url.Values.
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(Digits))
	q.Set("period", strconv.Itoa(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Code returns the password for secret at time t. The decoded secret must contain
// at least MinSecretBytes; undersized issuer secrets must be replaced by re-enrolment.
func Code(secret string, t time.Time) (string, error) {
	return hotp(secret, t.Unix()/Period)
}

// Validate reports whether code is valid for secret at t, accepting one step of skew
// either side, and returns the counter that matched so the caller can spend it.
func Validate(secret, code string, t time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	step := t.Unix() / Period
	for _, delta := range []int64{-1, 0, 1} {
		counter := step + delta
		if counter < 0 {
			// Near the epoch the window reaches below zero. Probing it would wrap into
			// a huge unsigned counter rather than fail.
			continue
		}
		expected, err := hotp(secret, counter)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

// hotp is RFC 4226 dynamic truncation.
func hotp(secret string, counter int64) (string, error) {
	key, err := encoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: secret is not base32: %w", err)
	}
	if len(key) < MinSecretBytes {
		return "", fmt.Errorf("totp: secret must contain at least %d decoded bytes; re-enrol with the issuer", MinSecretBytes)
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, truncated%mod), nil
}
