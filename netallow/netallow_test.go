package netallow

import (
	"net/netip"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *List {
	t.Helper()
	l, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return l
}

func TestEmptyListMatchesNothing(t *testing.T) {
	var nilList *List
	for name, l := range map[string]*List{"nil": nilList, "empty": mustParse(t, ""), "blanks": mustParse(t, " , ,")} {
		for _, a := range []string{"10.0.0.1", "::1", "203.0.113.9", "0.0.0.0"} {
			if l.Exempt(netip.MustParseAddr(a)) {
				t.Errorf("%s list matched %s", name, a)
			}
		}
		if l.Contains(netip.Addr{}) {
			t.Errorf("%s list matched the zero address", name)
		}
		if l.Len() != 0 || l.Exempted() != 0 || l.String() != "" {
			t.Errorf("%s list: Len=%d Exempted=%d String=%q", name, l.Len(), l.Exempted(), l.String())
		}
	}
}

func TestMatching(t *testing.T) {
	l := mustParse(t, "203.0.113.0/24, 198.51.100.7 ,2001:db8:1::/48")
	for addr, want := range map[string]bool{
		"203.0.113.1":          true,
		"203.0.113.255":        true,
		"203.0.114.1":          false,
		"198.51.100.7":         true,
		"198.51.100.8":         false,
		"2001:db8:1:ffff::1":   true,
		"2001:db8:2::1":        false,
		"::ffff:203.0.113.1":   true, // IPv4-mapped matches as IPv4
		"::ffff:203.0.114.1":   false,
		"::203.0.113.1":        false, // IPv4-compatible is not IPv4
		"fe80::1%eth0":         false,
		"2001:db8:1::1%eth0":   false, // a zoned address is never in a prefix
		"64:ff9b::203.0.113.1": false,
	} {
		if got := l.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
	if l.Contains(netip.Addr{}) {
		t.Error("matched the zero address")
	}
}

func TestMinimumPrefix(t *testing.T) {
	for _, ok := range []string{"10.0.0.0/16", "10.0.0.0/32", "2001:db8::/48", "2001:db8::1/128"} {
		if _, err := Parse(ok); err != nil {
			t.Errorf("Parse(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{
		"0.0.0.0/0", "::/0", "10.0.0.0/8", "10.0.0.0/15", "2001:db8::/47", "::/1", "0.0.0.0/1",
	} {
		_, err := Parse(bad)
		if err == nil || !strings.Contains(err.Error(), "too broad") {
			t.Errorf("Parse(%q) error = %v, want too broad", bad, err)
		}
	}
}

func TestRejectsInvalidEntries(t *testing.T) {
	for _, bad := range []string{
		"office", "10.0.0.0/33", "10.0.0/24", "10.0.0.0/-1", "10.0.0.0/24/24", "10.0.0.0-10.0.0.9",
		"fe80::1%eth0", "fe80::%eth0/64",
		"::ffff:10.0.0.0/112", "::ffff:10.0.0.1", "::ffff:0.0.0.0/96",
		"127.0.0.1", "127.0.0.0/16", "127.9.0.0/16", "::1", "::1/128", "::/100",
		"10.0.0.0/24 10.0.1.0/24", "10.0.0.0/24;10.0.1.0/24",
		"10.0.0.0/24,nope", // one bad entry fails the whole list
	} {
		if l, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted as %q", bad, l)
		}
	}
}

func TestMaxEntries(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxEntries; i++ {
		b.WriteString(netip.AddrFrom4([4]byte{10, 0, byte(i), 0}).String() + "/24,")
	}
	if l := mustParse(t, b.String()); l.Len() != MaxEntries {
		t.Fatalf("Len = %d", l.Len())
	}
	if _, err := Parse(b.String() + "192.0.2.0/24"); err == nil {
		t.Fatal("accepted more than MaxEntries networks")
	}
	// Duplicates do not count against the bound.
	if l := mustParse(t, b.String()+"10.0.0.0/24,10.0.0.9/24"); l.Len() != MaxEntries {
		t.Fatalf("Len with duplicates = %d", l.Len())
	}
}

func TestCanonicalString(t *testing.T) {
	l := mustParse(t, " 10.1.2.3/16 ,10.1.0.0/16, 192.0.2.5,2001:DB8:0:0::9/48")
	const want = "10.1.0.0/16,192.0.2.5/32,2001:db8::/48"
	if l.String() != want {
		t.Fatalf("String = %q, want %q", l.String(), want)
	}
	if again := mustParse(t, l.String()); again.String() != want {
		t.Fatalf("round trip = %q", again.String())
	}
}

func TestExemptCounts(t *testing.T) {
	l := mustParse(t, "203.0.113.0/24")
	in, out := netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("192.0.2.1")
	l.Contains(in)
	l.Exempt(out)
	if l.Exempted() != 0 {
		t.Fatalf("Exempted = %d before any exempt match", l.Exempted())
	}
	l.Exempt(in)
	l.Exempt(in)
	if l.Exempted() != 2 {
		t.Fatalf("Exempted = %d, want 2", l.Exempted())
	}
}

// Whatever Parse accepts obeys the breadth rule, never matches loopback, and survives a
// round trip through String.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"", "10.0.0.0/16", "0.0.0.0/0", "::/0", "::ffff:10.0.0.0/112", "2001:db8::/48,10.1.2.3/24",
		"fe80::1%eth0", "127.0.0.1", " , ,", "10.0.0.0/8", "1.2.3.4",
	} {
		f.Add(s, []byte{203, 0, 113, 1})
	}
	f.Fuzz(func(t *testing.T, s string, raw []byte) {
		l, err := Parse(s)
		if err != nil {
			return
		}
		for _, p := range l.prefixes {
			minBits := MinIPv6Bits
			if p.Addr().Is4() {
				minBits = MinIPv4Bits
			}
			if p.Bits() < minBits || p.Addr().Is4In6() || p != p.Masked() {
				t.Fatalf("Parse(%q) kept %s", s, p)
			}
		}
		if l.Contains(netip.MustParseAddr("127.0.0.1")) || l.Contains(netip.MustParseAddr("::1")) {
			t.Fatalf("Parse(%q) matches loopback", s)
		}
		again, err := Parse(l.String())
		if err != nil || again.String() != l.String() {
			t.Fatalf("round trip of %q: %q, %v", l.String(), again, err)
		}
		if addr, ok := netip.AddrFromSlice(raw); ok {
			mapped := netip.AddrFrom16(addr.As16())
			if l.Contains(addr) != again.Contains(addr) || l.Contains(addr) != l.Contains(mapped) {
				t.Fatalf("Parse(%q) disagrees on %s", s, addr)
			}
		}
	})
}
