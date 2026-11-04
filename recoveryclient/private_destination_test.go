package recoveryclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestPrivateDestinationLiteralClassification(t *testing.T) {
	for _, host := range []string{"192.168.1.91", "10.0.0.5", "172.16.0.1", "100.64.0.1", "[fd00::1]"} {
		u := "https://" + host
		if err := ValidateURL(u, false); !errors.Is(err, ErrPrivateDestination) {
			t.Errorf("%s: want private-destination error, got %v", u, err)
		}
		if err := ValidateURL(u, true); err != nil {
			t.Errorf("%s with opt-in: %v", u, err)
		}
	}
	for _, u := range []string{"https://127.0.0.1", "https://[::1]", "https://169.254.1.1", "https://0.0.0.0", "https://224.0.0.1", "https://240.0.0.1", "https://192.0.0.9", "http://192.168.1.91", "https://192.168.1.91?x=1", "https://user:pw@192.168.1.91"} {
		for _, allow := range []bool{false, true} {
			if err := ValidateURL(u, allow); err == nil || errors.Is(err, ErrPrivateDestination) {
				t.Errorf("%s allow=%v: want other refusal, got %v", u, allow, err)
			}
		}
	}
}

func TestPrivateDestinationThroughClaimAndDeposit(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	for _, tc := range []struct {
		name    string
		host    string
		ips     []net.IP
		lookup  error
		allow   bool
		private bool
	}{
		{name: "literal", host: "192.168.1.91", private: true},
		{name: "private DNS", ips: []net.IP{net.ParseIP("192.168.1.91")}, private: true},
		{name: "CGNAT DNS", ips: []net.IP{net.ParseIP("100.64.0.1")}, private: true},
		{name: "ULA DNS", ips: []net.IP{net.ParseIP("fd00::1")}, private: true},
		{name: "mixed blocked DNS", ips: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.91")}, private: true},
		{name: "loopback DNS", ips: []net.IP{net.ParseIP("127.0.0.1")}},
		{name: "reserved DNS", ips: []net.IP{net.ParseIP("169.254.1.1"), net.ParseIP("240.0.0.1")}},
		{name: "opt-in still refuses loopback", ips: []net.IP{net.ParseIP("127.0.0.1")}, allow: true},
		{name: "lookup failure", lookup: lookupErr},
		{name: "empty DNS answer"},
	} {
		for _, operation := range []string{"claim", "deposit"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				host := tc.host
				if host == "" {
					host = "recovery.example.test"
				}
				lookedUp := false
				c := newClient(Options{AllowPrivate: tc.allow}, func(_ context.Context, network, name string) ([]net.IP, error) {
					lookedUp = true
					if network != "ip" || name != host {
						t.Errorf("unexpected lookup: %s %s", network, name)
					}
					return tc.ips, tc.lookup
				}, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
				var err error
				if operation == "claim" {
					_, err = c.ClaimPairing(context.Background(), "https://"+host, "123456", "Svc", "Svc")
				} else {
					_, err = c.Deposit(context.Background(), "https://"+host, "test-token", []byte("sealed"))
				}
				if err == nil || errors.Is(err, ErrPrivateDestination) != tc.private {
					t.Fatalf("private=%v: got %v", tc.private, err)
				}
				if lookedUp != (tc.host == "") {
					t.Fatalf("DNS path exercised=%v", lookedUp)
				}
				if lookedUp {
					var urlErr *url.Error
					if !errors.As(err, &urlErr) {
						t.Fatalf("transport wrapper lost: %v", err)
					}
				}
				if tc.lookup != nil && !errors.Is(err, tc.lookup) {
					t.Fatalf("lookup error lost: %v", err)
				}
			})
		}
	}
}

// The transport dialled only the first allowed address, so a dead AAAA ended every claim
// and deposit even when the A record answered.
func TestDialFallsBackToTheNextAllowedAddress(t *testing.T) {
	dead, live := net.ParseIP("2001:db8::1"), net.ParseIP("203.0.113.7")
	var tried []string
	c := newClient(Options{AllowPrivate: true}, func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{dead, live}, nil
	}, func(_ context.Context, _, address string) (net.Conn, error) {
		tried = append(tried, address)
		if address == net.JoinHostPort(dead.String(), "443") {
			return nil, errors.New("connect: network is unreachable")
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	})
	conn, err := c.client.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "recovery.example.test:443")
	if err != nil {
		t.Fatalf("dial = %v after trying %v", err, tried)
	}
	_ = conn.Close()
	if len(tried) != 2 {
		t.Fatalf("tried %v, want both addresses", tried)
	}
}
