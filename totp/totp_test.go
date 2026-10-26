package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret is RFC 4226's test key, the ASCII "12345678901234567890", base32 encoded.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// rfcCodes are the published RFC 4226 Appendix D values for counters 0-9. TOTP is HOTP
// over counter = unixSeconds/30, so these pin the whole construction against a document
// rather than against this implementation.
var rfcCodes = []string{
	"755224", "287082", "359152", "969429", "338314",
	"254676", "287922", "162583", "399871", "520489",
}

func TestMatchesRFC4226Vectors(t *testing.T) {
	for counter, want := range rfcCodes {
		got, err := Code(rfcSecret, time.Unix(int64(counter)*Period, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("counter %d: got %s, want %s", counter, got, want)
		}
	}
}

func TestValidateReturnsTheMatchedCounter(t *testing.T) {
	// The counter is what lets a caller spend a code. ky_server_base and gridlock-server
	// return a bare bool, so a phished code stays valid for the whole 90-second window.
	at := time.Unix(5*Period, 0)
	counter, ok := Validate(rfcSecret, rfcCodes[5], at)
	if !ok {
		t.Fatal("a correct code did not validate")
	}
	if counter != 5 {
		t.Fatalf("got counter %d, want 5", counter)
	}
}

func TestValidateAcceptsOneStepOfSkew(t *testing.T) {
	at := time.Unix(5*Period, 0)
	for _, tc := range []struct {
		name   string
		code   string
		want   int64
		accept bool
	}{
		{"one step early", rfcCodes[4], 4, true},
		{"current step", rfcCodes[5], 5, true},
		{"one step late", rfcCodes[6], 6, true},
		{"two steps early", rfcCodes[3], 0, false},
		{"two steps late", rfcCodes[7], 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counter, ok := Validate(rfcSecret, tc.code, at)
			if ok != tc.accept {
				t.Fatalf("ok=%v, want %v", ok, tc.accept)
			}
			if ok && counter != tc.want {
				t.Fatalf("counter=%d, want %d", counter, tc.want)
			}
		})
	}
}

// ky_server_base and gridlock-server interpolate the account name straight into the URI.
// An account name carrying a '?' starts the query string early, so the authenticator
// enrols the parameters the name supplies instead of the ones the server meant — and it
// keeps them until the user re-enrols.
func TestProvisioningURICannotBeRewrittenByTheAccountName(t *testing.T) {
	const real = "REALSECRETBASE32AAAA"
	for _, account := range []string{
		"x?secret=ATTACKERAAAAAAAA&digits=8",
		"x&secret=ATTACKERAAAAAAAA",
		"a/../../b",
		"plain@example.com",
	} {
		t.Run(account, func(t *testing.T) {
			uri := ProvisioningURI("Gridlock", account, real)
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatalf("unparseable URI: %v", err)
			}
			q := parsed.Query()
			if got := q.Get("secret"); got != real {
				t.Errorf("enrolled secret is %q, want %q", got, real)
			}
			if got := q.Get("digits"); got != "6" {
				t.Errorf("enrolled digits is %q, want 6", got)
			}
			if got := q.Get("period"); got != "30" {
				t.Errorf("enrolled period is %q, want 30", got)
			}
			if got := q.Get("issuer"); got != "Gridlock" {
				t.Errorf("enrolled issuer is %q, want Gridlock", got)
			}
		})
	}
}

func TestProvisioningURIRoundTripsTheLabel(t *testing.T) {
	uri := ProvisioningURI("Ky Suite", "alice@example.com", rfcSecret)
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Fatalf("scheme/host are %q/%q", parsed.Scheme, parsed.Host)
	}
	if want := "/Ky Suite:alice@example.com"; parsed.Path != want {
		t.Fatalf("label decodes to %q, want %q", parsed.Path, want)
	}
}

func TestValidateRejectsMalformedInput(t *testing.T) {
	at := time.Unix(5*Period, 0)
	for _, tc := range []struct{ name, secret, code string }{
		{"wrong length code", rfcSecret, "12345"},
		{"empty code", rfcSecret, ""},
		{"non digit code", rfcSecret, "abcdef"},
		{"bad base32 secret", "not!base32", rfcCodes[5]},
		{"empty secret", "", rfcCodes[5]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := Validate(tc.secret, tc.code, at); ok {
				t.Fatal("malformed input validated")
			}
		})
	}
}

func TestValidateIgnoresSurroundingSpace(t *testing.T) {
	at := time.Unix(5*Period, 0)
	if _, ok := Validate(rfcSecret, "  "+rfcCodes[5]+" ", at); !ok {
		t.Fatal("a code with surrounding space did not validate")
	}
}

// Near the Unix epoch the skew window reaches below counter 0. A negative counter must
// not be probed rather than wrapping into a huge unsigned value.
func TestValidateHandlesTheEpochBoundary(t *testing.T) {
	if _, ok := Validate(rfcSecret, rfcCodes[0], time.Unix(0, 0)); !ok {
		t.Fatal("counter 0 did not validate at the epoch")
	}
}

func TestRejectsUndersizedSecrets(t *testing.T) {
	at := time.Unix(5*Period, 0)
	// Independently calculated RFC 4226 values for the first 1, 13 and 15 bytes of
	// its published test key. A matching code must not make a short key acceptable.
	for _, tc := range []struct{ secret, code string }{
		{"GE", "733789"},
		{"GEZDGNBVGY3TQOJQGEZDG", "731718"},
		{"GEZDGNBVGY3TQOJQGEZDGNBV", "046607"},
	} {
		if _, err := Code(tc.secret, at); err == nil {
			t.Errorf("Code accepted an undersized secret")
		}
		if _, ok := Validate(tc.secret, tc.code, at); ok {
			t.Errorf("Validate accepted a matching code under an undersized secret")
		}
	}
}

func TestMinimumSecretMatchesRFC4226(t *testing.T) {
	// RFC 4226 section 4 requires at least 128 bits; this is its test key's
	// first 16 bytes, with the counter-5 value calculated independently.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY"
	at := time.Unix(5*Period, 0)
	code, err := Code(secret, at)
	if err != nil || code != "715195" {
		t.Fatalf("Code = %q, %v; want 715195", code, err)
	}
	if counter, ok := Validate(secret, code, at); !ok || counter != 5 {
		t.Fatalf("Validate = %d, %v; want 5, true", counter, ok)
	}
}

func TestGenerateSecretIsUsableAndRandom(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated secrets are identical")
	}
	if strings.ContainsRune(a, '=') {
		t.Fatalf("secret %q carries base32 padding, which authenticators reject", a)
	}
	code, err := Code(a, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Validate(a, code, time.Unix(0, 0)); !ok {
		t.Fatal("a generated secret does not validate its own code")
	}
}
