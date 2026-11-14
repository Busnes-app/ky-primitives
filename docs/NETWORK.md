# Network allowlist

## netallow

The admin-configured list of office networks whose requests skip a product's **per-IP** rate
limits. Staff behind one NAT address share those limits, and an ordinary Monday sign-in
rush trips them while the server is idle.

```go
list, err := netallow.Parse(setting) // "203.0.113.0/24, 2001:db8:1::/48"; "" matches nothing
if list.Exempt(clientAddr) {         // counts the match; a nil *List matches nothing
    // skip the per-IP limiter only
}
shown := list.Exempted()
```

`Parse` refuses the whole list when any entry is invalid, broader than /16 (IPv4) or /48
(IPv6), covers loopback, carries a zone, or is an IPv4-mapped IPv6 range. Host bits are
masked and `String` returns the canonical form to store. `Contains` is `Exempt` without the
count. IPv4-mapped IPv6 client addresses match as IPv4.

What the caller owns:

- **The address.** Pass the client address your trusted-proxy handling resolved. This
  package never reads `X-Forwarded-For`; an allowlist matched against a header an untrusted
  peer can forge exempts every attacker.
- **The scope.** Exempt per-IP limiters only. Per-account lockouts, instance-wide budgets,
  MFA and proof of work keep applying: a compromised machine inside the office is still
  bounded by them.
- **The swap.** The count belongs to one parsed `List`; replacing the list starts it at zero.

Never list a network you do not control (guest Wi-Fi, a carrier NAT, a VPN provider's exit):
everyone behind it loses the per-IP limit.
