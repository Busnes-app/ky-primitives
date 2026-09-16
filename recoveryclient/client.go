package recoveryclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// uploadTimeout bounds one deposit. A container is at most 384 MiB and kyrecovery gives the
// read fifteen minutes; the claim keeps the short timeout because it carries a few hundred bytes.
const uploadTimeout = 15 * time.Minute

// Client is the product half of the pairing and deposit contract.
type Client struct {
	client       *http.Client
	allowPrivate bool
}

// Options configures the client.
type Options struct {
	// AllowPrivate admits private and carrier-grade NAT destinations for a KyRecovery on the
	// operator's own network behind a TLS proxy. HTTPS stays mandatory either way.
	AllowPrivate bool
}

// ErrPrivateDestination means a destination was refused because AllowPrivate is false,
// and enabling it would admit at least one address. Use errors.Is on ValidateURL,
// ClaimPairing or Deposit errors to offer the product's private-network opt-in.
// It does not identify loopback/reserved addresses that remain forbidden with the opt-in,
// or DNS lookup, connection, TLS, and remote-server failures.
var ErrPrivateDestination = errors.New("recoveryclient: private destinations are disabled")

// NewClient builds the client. With Options.AllowPrivate:
// with it, a KyRecovery on the operator's LAN is dialled; without it, only public addresses.
// HTTPS is required either way.
func NewClient(o Options) *Client {
	return newClient(o, net.DefaultResolver.LookupIP)
}

// newClient keeps DNS resolution injectable in tests while exercising the real transport.
func newClient(o Options, lookupIP func(context.Context, string, string) ([]net.IP, error)) *Client {
	allowPrivate := o.AllowPrivate
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := lookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		privateDestination := false
		for _, ip := range ips {
			if allowedIP(ip, allowPrivate) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			privateDestination = privateDestination || allowedIP(ip, true)
		}
		if !allowPrivate && privateDestination {
			return nil, fmt.Errorf("recovery host resolves only to private or reserved addresses: %w; set the private-destination option for a KyRecovery on your own network", ErrPrivateDestination)
		}
		return nil, errors.New("recovery host resolves only to loopback or unroutable addresses")
	}}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: refuseRedirect}
	return &Client{client: client, allowPrivate: allowPrivate}
}

// refuseRedirect is the client's redirect policy: none. A validated destination must not be
// able to bounce a claim or a sealed capsule to a host the operator never named, and nothing
// in the deposit contract needs a redirect. Go would otherwise replay the POST body on a 308.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("KyRecovery redirected to %s; redirects are refused", req.URL.Redacted())
}

// ValidateRecoveryURL is the rule for where this server will send a capsule: HTTPS, no
// credentials, and unless allowPrivate, not a private or reserved address. Handlers call it
// before storing a URL.
func ValidateURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("recovery URL must be an HTTPS URL without credentials")
	}
	// The API path is appended to this URL; a query or fragment would silently send the
	// claim and the capsule to the host's root instead of the deposit endpoint.
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("recovery URL must not carry a query string or fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !allowedIP(ip, allowPrivate) {
		if !allowPrivate && allowedIP(ip, true) {
			return fmt.Errorf("recovery URL cannot target a private or reserved address: %w; set the private-destination option for a KyRecovery on your own network", ErrPrivateDestination)
		}
		return errors.New("recovery URL cannot target a loopback or unroutable address")
	}
	return nil
}

// allowedIP is isPublicIP, or with allowPrivate the wider rule for an operator's own network:
// private ranges and carrier-grade NAT (Tailscale) are in; loopback, link-local, multicast
// and the unspecified address never are, because none of them is a KyRecovery.
func allowedIP(ip net.IP, allowPrivate bool) bool {
	if !allowPrivate {
		return isPublicIP(ip)
	}
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, n := range reservedRanges {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// reservedRanges are the special-purpose blocks net.IP's own predicates miss and that no
// KyRecovery ever lives in, opt-in or not: "this" network, IETF protocol assignments,
// benchmarking, class E, the NAT64 well-known prefix, and deprecated IPv6 site-local.
var reservedRanges = mustCIDRs("0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96", "fec0::/10")

// cgnatRange is carrier-grade NAT, which is also every Tailscale address. Refused by default
// like the private ranges, admitted with them under BackupAllowPrivateRecovery.
var cgnatRange = mustCIDRs("100.64.0.0/10")[0]

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// isPublicIP is the default rule for where a capsule may be sent. The backup client never
// honours AllowPrivateCallbacks: that setting is for paired systems' callbacks. Its own
// opt-in is BackupAllowPrivateRecovery, because a KyRecovery on a private address makes every
// scheduled deposit an unattended request into that network and deserves its own decision.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || cgnatRange.Contains(ip) {
		return false
	}
	for _, n := range reservedRanges {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// endpoint joins the server URL and an API path after checking the URL is one the client is
// willing to talk to.
func endpoint(serverURL, path string, allowPrivate bool) (string, error) {
	u := strings.TrimRight(serverURL, "/") + path
	if err := ValidateURL(u, allowPrivate); err != nil {
		return "", fmt.Errorf("invalid recovery URL: %w", err)
	}
	return u, nil
}

// PairingResult is what a completed pairing yields: the bearer token for deposits and the
// suite recovery public key with its custodian topology. A claim that returns no key is not a
// completed pairing.
type PairingResult struct {
	APIToken string
	Key      RecoveryKey
}

// ClaimPairing exchanges a 6-digit ephemeral pairing PIN with KyRecovery for a permanent API
// bearer token and the suite recovery public key to seal backups to.
//
// serviceName is sent explicitly: kyrecovery pins whatever the claimer sends and refuses every
// later deposit whose manifest names a different service, so it must be the same value Seal
// is given.
func (c *Client) ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (PairingResult, error) {
	u, err := endpoint(serverURL, "/api/pairing/claim", c.allowPrivate)
	if err != nil {
		return PairingResult{}, err
	}
	bodyBytes, _ := json.Marshal(map[string]string{
		"pairing_code": strings.TrimSpace(pairingCode),
		"service_name": serviceName,
		"app_name":     appName,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(bodyBytes))
	if err != nil {
		return PairingResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return PairingResult{}, fmt.Errorf("pairing claim request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PairingResult{}, fmt.Errorf("pairing claim rejected (%d): %s", resp.StatusCode, remoteMessage(resp.Body))
	}
	var claimResp struct {
		APIToken          string `json:"api_token"`
		RecoveryPublicKey string `json:"recovery_public_key"` // std base64 of 1216 bytes
		Threshold         int    `json:"threshold"`
		TotalShares       int    `json:"total_shares"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&claimResp); err != nil {
		return PairingResult{}, err
	}
	if claimResp.APIToken == "" {
		return PairingResult{}, errors.New("empty api_token in claim response")
	}
	pkBytes, err := base64.StdEncoding.DecodeString(claimResp.RecoveryPublicKey)
	if err != nil {
		return PairingResult{}, fmt.Errorf("recovery_public_key: %w", err)
	}
	pk, err := recoverykey.ParsePublicKey(pkBytes)
	if err != nil {
		return PairingResult{}, fmt.Errorf("recovery_public_key: %w", err)
	}
	if !validTopology(claimResp.Threshold, claimResp.TotalShares) {
		return PairingResult{}, fmt.Errorf("claim response: %d-of-%d is not a custodian topology", claimResp.Threshold, claimResp.TotalShares)
	}
	return PairingResult{
		APIToken: claimResp.APIToken,
		Key:      RecoveryKey{Public: pk, Threshold: claimResp.Threshold, TotalShares: claimResp.TotalShares},
	}, nil
}

// ErrRemote marks an error that came from the wire or from KyRecovery itself, as opposed to
// one raised here before any byte was sent. Handlers answer the two differently.
var ErrRemote = errors.New("recoveryclient: KyRecovery")

// Receipt is kyrecovery's record of one deposit. Digest and SizeBytes are the only values
// the store computed itself; a restore compares CapsuleID against the capsule in hand.
type Receipt struct {
	CapsuleID   string    `json:"capsule_id"`
	Digest      string    `json:"digest"`
	SizeBytes   int64     `json:"size_bytes"`
	DepositedAt time.Time `json:"deposited_at"`
}

// Deposit hands a sealed container to kyrecovery and returns its receipt. The receipt's
// digest is checked against the bytes sent so a deposit counts only when kyrecovery stored
// exactly what left here. 200 is kyrecovery re-sending the receipt for bytes it already
// holds, which is a success.
func (c *Client) Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error) {
	u, err := endpoint(serverURL, "/api/backup/deposit", c.allowPrivate)
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(container))
	if err != nil {
		return Receipt{}, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/octet-stream")

	// The client's own timeout is sized for a claim; the upload budget is the context above.
	upload := *c.client
	upload.Timeout = 0
	resp, err := upload.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: deposit request failed: %w", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("%w: deposit rejected (%d): %s", ErrRemote, resp.StatusCode, remoteMessage(resp.Body))
	}
	var rcpt Receipt
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&rcpt); err != nil {
		return Receipt{}, fmt.Errorf("%w: deposit receipt: %w", ErrRemote, err)
	}
	sum := sha256.Sum256(container)
	if want := hex.EncodeToString(sum[:]); rcpt.Digest != want {
		return Receipt{}, fmt.Errorf("%w: deposit receipt digest %s does not match the container sent (%s)", ErrRemote, rcpt.Digest, want)
	}
	if rcpt.SizeBytes != int64(len(container)) {
		return Receipt{}, fmt.Errorf("%w: deposit receipt size %d does not match the %d bytes sent", ErrRemote, rcpt.SizeBytes, len(container))
	}
	if rcpt.CapsuleID == "" {
		return Receipt{}, fmt.Errorf("%w: deposit receipt has no capsule_id", ErrRemote)
	}
	return rcpt, nil
}

// auditTextLimit bounds any text that reaches the audit log from outside the process.
const auditTextLimit = 200

// AuditSafe makes a string fit for an audit record: printable characters only, cut at
// auditTextLimit. Remote bodies and operator input go through it before they are stored,
// because the audit table rides inside every capsule and grows with whatever lands in it.
func AuditSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= auditTextLimit {
			b.WriteString("...")
			break
		}
		switch {
		case r == '\n' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// remoteMessage is what a KyRecovery error body contributes to an error: a bounded, printable
// excerpt, never the raw body.
func remoteMessage(body io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(body, 4<<10))
	return AuditSafe(string(b))
}
