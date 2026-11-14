// Package netallow parses and matches the admin-configured list of networks whose requests
// skip a product's per-IP rate limits: an office behind one NAT address shares those limits
// and trips them on an ordinary morning.
//
// It decides nothing about who the client is. Callers pass the address their own
// trusted-proxy handling resolved; this package never reads a forwarding header.
package netallow

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
)

// The broadest ranges Parse accepts. A wider entry would switch per-IP limits off for a
// large part of the internet by typo.
const (
	MinIPv4Bits = 16
	MinIPv6Bits = 48
)

// MaxEntries bounds a list: every exempt check scans it.
const MaxEntries = 256

// List is a parsed allowlist. A nil or empty List matches nothing.
type List struct {
	prefixes []netip.Prefix
	exempted atomic.Uint64
}

// Parse reads a comma-separated list of CIDR ranges or single addresses. Blank entries are
// skipped, so "" yields an empty list. Host bits are masked off ("10.1.2.3/16" is
// 10.1.0.0/16) and duplicates dropped.
//
// It refuses anything broader than MinIPv4Bits or MinIPv6Bits, loopback, zoned addresses and
// IPv4-mapped IPv6 ranges (write those as IPv4). One bad entry fails the whole list.
func Parse(s string) (*List, error) {
	l := &List{}
	for _, raw := range strings.Split(s, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		p, err := parseEntry(entry)
		if err != nil {
			return nil, err
		}
		if !l.has(p) {
			l.prefixes = append(l.prefixes, p)
		}
		if len(l.prefixes) > MaxEntries {
			return nil, fmt.Errorf("netallow: more than %d networks", MaxEntries)
		}
	}
	return l, nil
}

func parseEntry(entry string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(entry, "/") {
		var err error
		if p, err = netip.ParsePrefix(entry); err != nil {
			return p, fmt.Errorf("netallow: %q is not a network range", entry)
		}
	} else {
		a, err := netip.ParseAddr(entry)
		if err != nil || a.Zone() != "" {
			return p, fmt.Errorf("netallow: %q is not an address or network range", entry)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	addr := p.Addr()
	if addr.Is4In6() {
		return p, fmt.Errorf("netallow: write %q as an IPv4 range", entry)
	}
	minBits, family := MinIPv6Bits, "IPv6"
	if addr.Is4() {
		minBits, family = MinIPv4Bits, "IPv4"
	}
	if p.Bits() < minBits {
		return p, fmt.Errorf("netallow: %q is too broad; the widest %s range allowed is /%d", entry, family, minBits)
	}
	p = p.Masked()
	if p.Addr().IsLoopback() || p.Contains(netip.IPv6Loopback()) {
		return p, fmt.Errorf("netallow: %q covers loopback, not an office network", entry)
	}
	return p, nil
}

func (l *List) has(p netip.Prefix) bool {
	for _, q := range l.prefixes {
		if q == p {
			return true
		}
	}
	return false
}

// Contains reports whether addr is in the list. IPv4-mapped IPv6 addresses match as IPv4.
func (l *List) Contains(addr netip.Addr) bool {
	if l == nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Exempt is Contains that also counts the match, for the request path.
func (l *List) Exempt(addr netip.Addr) bool {
	if !l.Contains(addr) {
		return false
	}
	l.exempted.Add(1)
	return true
}

// Exempted is how many Exempt calls matched since this List was parsed.
func (l *List) Exempted() uint64 {
	if l == nil {
		return 0
	}
	return l.exempted.Load()
}

// Len is the number of networks in the list.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.prefixes)
}

// String is the canonical form: Parse(l.String()) yields the same networks.
func (l *List) String() string {
	if l == nil {
		return ""
	}
	parts := make([]string, len(l.prefixes))
	for i, p := range l.prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}
