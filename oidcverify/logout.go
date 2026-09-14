package oidcverify

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// MaxLogoutTokenAge bounds logout-token freshness even if exp is far in the future.
// KySignOn issues a fresh token for each attempt with a two-minute expiration.
const MaxLogoutTokenAge = 5 * time.Minute

// ErrLogoutClaims means a signed token does not meet the KySignOn logout profile.
var ErrLogoutClaims = errors.New("oidcverify: invalid logout claims")

// LogoutClaims identifies sessions to end, never an identity to authenticate.
// With a SessionID, match that issuer/client-scoped session and Subject when present.
// Without a SessionID, end all sessions for Issuer and Subject at this client.
// The receiver must atomically record (Issuer, JWTID) with session invalidation and
// retain it through ReplayUntil, including across restart. Verification is stateless.
type LogoutClaims struct {
	Issuer      string
	Subject     string
	SessionID   string
	Audience    []string
	JWTID       string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	ReplayUntil time.Time // last acceptance boundary, including clock-skew leeway
	KeyID       string
}

// VerifyLogout verifies an RS256 logout+jwt with issuer, audience, required iat/exp/jti,
// a sub or sid, the back-channel event object, and no nonce or token_use claim.
// It shares Verify's JWKS cache, refresh limits, clock and leeway. Tokens older than
// MaxLogoutTokenAge plus leeway are refused. It neither records replay IDs nor ends
// sessions; the receiver owns those durable operations and bounds its HTTP request.
func (v *Verifier) VerifyLogout(ctx context.Context, token string) (LogoutClaims, error) {
	c, err := v.verifyJWT(ctx, token, "logout+jwt")
	if err != nil {
		return LogoutClaims{}, err
	}
	for _, name := range []string{"nonce", "token_use"} {
		if _, present := c.Raw[name]; present {
			return LogoutClaims{}, ErrLogoutClaims
		}
	}
	var sub, sid, jti string
	for name, dst := range map[string]*string{"sub": &sub, "sid": &sid, "jti": &jti} {
		if raw, present := c.Raw[name]; present {
			if err := json.Unmarshal(raw, dst); err != nil || *dst == "" {
				return LogoutClaims{}, ErrLogoutClaims
			}
		}
	}
	if (sub == "" && sid == "") || jti == "" || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return LogoutClaims{}, ErrLogoutClaims
	}
	var events map[string]json.RawMessage
	if err := json.Unmarshal(c.Raw["events"], &events); err != nil {
		return LogoutClaims{}, ErrLogoutClaims
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(events[backchannelLogoutEvent], &event); err != nil || event == nil {
		return LogoutClaims{}, ErrLogoutClaims
	}
	replayUntil := c.ExpiresAt.Add(v.leeway())
	if freshUntil := c.IssuedAt.Add(MaxLogoutTokenAge).Add(v.leeway()); freshUntil.Before(replayUntil) {
		replayUntil = freshUntil
	}
	if !v.now().Before(replayUntil) {
		return LogoutClaims{}, ErrExpired
	}
	return LogoutClaims{
		Issuer: c.Issuer, Subject: sub, SessionID: sid, Audience: c.Audience, JWTID: jti,
		IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, ReplayUntil: replayUntil, KeyID: c.KeyID,
	}, nil
}
