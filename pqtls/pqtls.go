// Package pqtls pins and proves hybrid post-quantum TLS key exchange
// (X25519MLKEM768, RFC 10024) on links where both ends are Ky code.
//
// Go's default configuration already offers X25519MLKEM768 first, but falls
// back to classical X25519 or P-256 when a peer does not offer it. HybridOnly
// removes that fallback; RequireHybrid lets a handshake test prove the result.
package pqtls

import "crypto/tls"

// HybridOnly restricts cfg to TLS 1.3 with the X25519MLKEM768 key exchange and
// returns cfg. Use it on both ends of a Ky-to-Ky link only: a peer that cannot
// do the hybrid exchange (TLS 1.2, or an older or classical-only stack) is
// refused rather than downgraded.
func HybridOnly(cfg *tls.Config) *tls.Config {
	cfg.MinVersion = tls.VersionTLS13
	cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	return cfg
}

// TB is the subset of testing.TB that RequireHybrid uses. Taking it instead of
// testing.TB keeps the testing package out of binaries that call HybridOnly.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// RequireHybrid fails t unless state completed a handshake that negotiated
// X25519MLKEM768.
func RequireHybrid(t TB, state tls.ConnectionState) {
	t.Helper()
	if !state.HandshakeComplete || state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("TLS key exchange = %v (handshake complete %v), want X25519MLKEM768", state.CurveID, state.HandshakeComplete)
	}
}
