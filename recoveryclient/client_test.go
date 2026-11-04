package recoveryclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func jsonResponse(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{"Content-Type": {"application/json"}}}
}

func TestValidateURLRefusesPrivateByDefault(t *testing.T) {
	for _, u := range []string{"https://100.64.0.1", "https://192.0.0.9", "https://198.18.0.1", "https://240.0.0.1", "https://[64:ff9b::a00:1]", "https://[64:ff9b:1::a00:1]", "https://192.168.1.91", "https://10.0.0.5", "https://127.0.0.1"} {
		if err := ValidateURL(u, false); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if err := ValidateURL("https://203.0.113.10", false); err != nil {
		t.Errorf("public refused: %v", err)
	}
}

func TestValidateURLAdmitsPrivateAndCGNATWithSwitch(t *testing.T) {
	for _, u := range []string{"https://192.168.1.91", "https://10.0.0.5", "https://100.64.0.1", "https://203.0.113.10", "https://kyrecovery.lan"} {
		if err := ValidateURL(u, true); err != nil {
			t.Errorf("%s refused with the switch: %v", u, err)
		}
	}
}

func TestValidateURLNeverAdmitsLoopbackLinkLocalMulticast(t *testing.T) {
	for _, u := range []string{"https://127.0.0.1", "https://[::1]", "https://0.0.0.0", "https://169.254.1.1", "https://224.0.0.1", "https://240.0.0.1", "https://192.0.0.9"} {
		if err := ValidateURL(u, true); err == nil {
			t.Errorf("%s accepted even with the switch", u)
		}
	}
}

func TestValidateURLRequiresHTTPSAndRefusesQueryFragmentCredentials(t *testing.T) {
	for _, u := range []string{"http://recovery.example.test", "https://user:pw@recovery.example.test", "https://recovery.example.test/?x=1", "https://recovery.example.test/#frag", "https://recovery.example.test?", "ftp://recovery.example.test", "https://"} {
		if err := ValidateURL(u, true); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestClientRefusesRedirect(t *testing.T) {
	c := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": {"https://evil.example/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}), Options{})
	_, err := c.Deposit(context.Background(), "https://recovery.example.test", "tok", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect followed or unnamed: %v", err)
	}
}

func TestDepositRefusesReceiptThatDoesNotDescribeBytesSent(t *testing.T) {
	container := []byte("container-bytes")
	sum := sha256.Sum256(container)
	good := Receipt{CapsuleID: "cap-1", Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now()}
	for name, rcpt := range map[string]Receipt{
		"wrong digest": {CapsuleID: "cap-1", Digest: strings.Repeat("0", 64), SizeBytes: good.SizeBytes},
		"wrong size":   {CapsuleID: "cap-1", Digest: good.Digest, SizeBytes: 1},
	} {
		c := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusCreated, rcpt), nil
		}), Options{})
		if _, err := c.Deposit(context.Background(), "https://recovery.example.test", "tok", container); !errors.Is(err, ErrRemote) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var seen *http.Request
	c := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return jsonResponse(http.StatusCreated, good), nil
	}), Options{})
	got, err := c.Deposit(context.Background(), "https://recovery.example.test", "tok", container)
	if err != nil || got.CapsuleID != "cap-1" {
		t.Fatalf("%v %+v", err, got)
	}
	if seen.Header.Get("Authorization") != "Bearer tok" || seen.Header.Get("Content-Type") != "application/octet-stream" || seen.URL.Path != "/api/backup/deposit" {
		t.Errorf("request %v %v", seen.URL, seen.Header)
	}
}

func TestClaimPairingSendsServiceNameAndRequiresAKey(t *testing.T) {
	_, k := testKey(t)
	var body map[string]string
	c := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		return jsonResponse(http.StatusOK, map[string]any{"api_token": "kyrec_live_t", "recovery_public_key": base64.StdEncoding.EncodeToString(k.Public.Bytes()), "threshold": 2, "total_shares": 3}), nil
	}), Options{})
	res, err := c.ClaimPairing(context.Background(), "https://recovery.example.test", "123456", "Svc", "Svc")
	if err != nil || res.APIToken != "kyrec_live_t" || res.Key.Public.ID() != k.Public.ID() || res.Key.Threshold != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if body["service_name"] != "Svc" || body["pairing_code"] != "123456" {
		t.Errorf("claim body %v", body)
	}
	c = NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{"api_token": "t"}), nil
	}), Options{})
	if _, err := c.ClaimPairing(context.Background(), "https://recovery.example.test", "123456", "Svc", "Svc"); err == nil {
		t.Error("claim without a key accepted")
	}
}

func TestRemoteMessageIsBounded(t *testing.T) {
	c := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(strings.Repeat("x\n", 5000)))}, nil
	}), Options{})
	_, err := c.Deposit(context.Background(), "https://recovery.example.test", "tok", []byte("x"))
	if !errors.Is(err, ErrRemote) || len(err.Error()) > 400 || strings.Contains(err.Error(), "\n") {
		t.Fatalf("%d chars: %v", len(err.Error()), err)
	}
	if got := AuditSafe("a\x00b\ncd" + strings.Repeat("z", 500)); len(got) > 210 || strings.ContainsAny(got, "\x00\n") {
		t.Errorf("AuditSafe %d %q", len(got), got[:10])
	}
}

// A deposit on a slow uplink takes as long as it takes while bytes keep moving; one that
// stalls ends after the idle limit with context.DeadlineExceeded (Q6, client half).
func TestDepositBudgetRenewsOnProgressAndEndsAStall(t *testing.T) {
	old := depositIdle
	depositIdle = 100 * time.Millisecond
	t.Cleanup(func() { depositIdle = old })

	container := []byte("a-container-sent-slowly")
	sum := sha256.Sum256(container)
	rcpt := Receipt{CapsuleID: "cap-1", Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now()}
	slow := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.ContentLength != int64(len(container)) {
			t.Errorf("ContentLength %d, want %d", r.ContentLength, len(container))
		}
		var got []byte
		b := make([]byte, 1)
		for {
			// One byte every 30 ms: the whole upload takes about seven idle limits.
			time.Sleep(30 * time.Millisecond)
			if err := r.Context().Err(); err != nil {
				return nil, err
			}
			n, err := r.Body.Read(b)
			got = append(got, b[:n]...)
			if err == io.EOF {
				break
			}
		}
		if !bytes.Equal(got, container) {
			t.Errorf("body %q", got)
		}
		return jsonResponse(http.StatusCreated, rcpt), nil
	}), Options{})
	if _, err := slow.Deposit(context.Background(), "https://recovery.example.test", "tok", container); err != nil {
		t.Fatalf("a deposit that keeps moving must complete: %v", err)
	}

	stalled := NewClientWithTransportForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}), Options{})
	start := time.Now()
	_, err := stalled.Deposit(context.Background(), "https://recovery.example.test", "tok", container)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrRemote) {
		t.Fatalf("a stalled deposit must end with DeadlineExceeded, got %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stall took %v to end", d)
	}
}
