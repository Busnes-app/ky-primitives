# Sync signing, OIDC and SCIM

[Overview](../README.md) · [Assurance case](ASSURANCE-CASE.md) · [Contributing](../CONTRIBUTING.md)

## syncauth

One definition of how KySignOn signs a directory-sync event and how a product verifies it.
Before this, the sender signed the timestamp and body and at least one receiver verified the
body alone, so the two sides could not agree; and the signing secret also travelled as the
bearer token on every request. A receiver that accepts a forged deprovision, or that never
sees a real one, cannot tell either from a good event, which is the admission bar.

Scheme v1: HMAC-SHA256 over a canonical string binding the timestamp, the event type, the
event ID and the SHA-256 of the body, carried as `X-KySignOn-Signature: v1=<hex>` with the
timestamp, type and ID in their own headers. The key travels nowhere.

```go
// sender
h, _ := syncauth.Sign(secret, time.Now(), "user.deprovisioned", eventID, body)
h.Apply(req)

// receiver
mux.Handle("POST /api/sync", syncauth.Middleware(keyFn, syncauth.Options{Replay: syncauth.NewMemoryReplay(0, 0)}, 0, logReject)(handler))
```

Pinned: every bound field changes the verdict (`TestVerifyBindsEveryField`); a missing
signature, a timestamp outside the window in either direction, and a short key each refuse
(`TestVerifyRefusesMissingStaleAndShort`); the replay guard forgets only what has left the window and refuses with
`ErrReplayGuardFull` rather than forget an ID it must remember (`TestReplayGuard`); the middleware reads a bounded body, fails closed when the key is not
configured, and hands the handler exactly the bytes that were signed
(`TestMiddlewareVerifiesAndReplaysTheBodyToTheHandler`); `FuzzVerify` accepts only the
original tuple.

## oidcverify

Verifies the RS256 tokens KySignOn issues against its JWKS, on the standard library. Five
products parsed these with their own code, and at least one read the claims without checking
the signature. One wrong check of `alg`, `aud`, `iss`, `exp` or `kid` accepts a token it
should not.

```go
v := &oidcverify.Verifier{Issuer: cfg.IssuerURL, Audience: cfg.ClientID}
claims, err := v.VerifyWithNonce(ctx, idToken, session.Nonce)
mux.Handle("GET /api/me", v.Middleware(logReject)(handler))
```

Pinned: the issuer and JWKS URL must be HTTPS and the fetch follows no redirect, checked
before any request is made (`TestPlaintextIssuerIsRefusedWithoutARequest`,
`TestJWKSRedirectIsRefused`); the algorithm is RS256 or nothing, so `none`, `HS256` and an empty signature segment
are refused before any key work (`TestVerifyRefusesAlgorithmConfusionAndBadSignatures`);
each standard claim is checked with one minute of leeway and an audience array is refused
unless the product opts in (`TestVerifyRefusesEachBadClaim`); base64url must be unpadded so
one token has one encoding; JWKS entries that are not RSA signing keys are ignored even under
the right `kid` (`TestJWKSIgnoresNonRSAKeysUnderTheSameKid`); an unknown `kid` triggers at
most one rate-limited refresh whether the fetch succeeds or fails, the fetch runs outside
the lock so concurrent verifications share it, and a stale key set outlives an issuer outage
(`TestJWKSRefreshIsRateLimitedAndStaleSetSurvivesOutage`, `TestUnknownKidDoesNotStallVerification`,
`TestConcurrentUnknownKidsShareOneFetch`).


### Back-channel logout

`VerifyLogout` is the dedicated verifier for the KySignOn profile of
[OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation):

```go
logout, err := v.VerifyLogout(ctx, logoutToken)
// On success, atomically record (logout.Issuer, logout.JWTID) and invalidate
// matching sessions. Keep the replay record through logout.ReplayUntil.
```

It shares the verifier's RS256 signature checks, HTTPS JWKS cache, issuer/audience checks,
clock and leeway. It requires exact `typ: logout+jwt`, numeric `iat` and `exp`, a nonempty
`jti`, a nonempty `sub` or `sid` (or both), and an `events` object whose
`http://schemas.openid.net/event/backchannel-logout` member is an object. `nonce` and
`token_use` must be absent, including null or empty values. Expiration must follow
issuance; tokens older than `MaxLogoutTokenAge` (five minutes) plus leeway are refused,
even with a later expiration. KySignOn currently issues two-minute tokens per attempt.
`ReplayUntil` is the earlier expiration/freshness cutoff, including leeway (one minute
by default). `ErrTokenType` reports a wrong token purpose; `ErrLogoutClaims` reports a
logout-specific claim failure; common signature, issuer, audience and time errors are
shared with `Verify`.

The returned `LogoutClaims` is separate from authentication `Claims`. With `SessionID`,
match the local sessions for this issuer/client and that session ID, checking `Subject`
when present. Without `SessionID`, end all this client's sessions for `Issuer` and
`Subject`. Never broaden an unknown session ID into a subject-wide logout. A missing
local session is an idempotent success. The receiving product owns the HTTP body limit,
durable replay check, session invalidation and audit transaction; this primitive verifies
only and deliberately holds no replay database. Store replay IDs across restart and check
them atomically with invalidation so concurrent deliveries cannot replay a logout.

**Authentication compatibility:** `Verify`, `VerifyWithNonce` and `Middleware` now accept
only an absent/empty `typ`, `JWT`, or `at+jwt`, and reject any `events` claim. An ID token
with a logout type cannot authenticate, and ordinary ID/access tokens cannot authorize
logout. Numeric dates must be JSON numbers rather than quoted numbers, nulls or values
outside the supported integer range; payloads must be a single JSON object. Existing
KySignOn ID/access tokens use `JWT` and remain compatible. Neither authentication API
becomes an access-token-only verifier: products must still enforce their token-use policy.

The `oidcverify/logout_test.go` suite checks both logout scopes, malformed claims,
signatures, purpose separation through all three authentication APIs, JWKS reuse, and
exact freshness/replay boundaries with an injected clock.

## scim

The SCIM 2.0 client KySignOn provisions accounts with, and the RFC 7643 User type it shares
with a server. Before this the types, paths and status handling sat in KySignOn's sync engine,
where a 409 on create counted as a delivered account, later calls used local IDs the server
never issued, and generic targets got the suite signature instead of their bearer token. An
account that does not exist recorded as provisioned is the bar.

```go
c := &scim.Client{BaseURL: sys.URL, Token: sys.Token, HTTPClient: netguard.Client(5 * time.Second)}
created, err := c.CreateUser(ctx, user)          // keep created.ID; it is the handle from here on
if errors.Is(err, scim.ErrConflict) {
	created, err = c.FindUser(ctx, "externalId", user.ExternalID)
}
_, err = c.PatchUser(ctx, created.ID, scim.PatchOperation{Op: "replace", Path: "active", Value: false})
err = c.DeleteUser(ctx, created.ID)              // errors.Is(err, scim.ErrNotFound): already gone
```

Users only; groups, listing and bulk wait for a caller. `FindUser` takes `externalId` or
`userName`, the two attributes whose match it can check on the way back. `HTTPClient` is the
product's, so its outbound policy applies; the client adds what every product must not get
wrong.

Pinned: the base URL is HTTPS with a host and nothing else, and an empty token is refused,
before any request (`TestPlaintextOrMalformedBaseURLIsRefusedWithoutARequest`); a redirect is
refused and the bearer does not follow it (`TestRedirectIsRefusedAndTokenNotReplayed`);
resource IDs are path-escaped and an empty or dot ID never reaches the wire
(`TestResourceIDsAreEscapedAndRequired`); the filter value is quoted with `\` and `"` escaped
and any other attribute is refused (`TestFilterIsEscapedAndAttributeRestricted`); zero matches
is `ErrNotFound`, two is `ErrAmbiguous`, and one that does not carry the value is
`ErrMalformedResponse`, so a server that ignores the filter cannot hand back someone else
(`TestFindUserZeroAndManyResults`, `TestFindUserRefusesAUserThatDoesNotMatch`); 409 is
`ErrConflict` and a 2xx create without an `id` is `ErrMalformedResponse`
(`TestCreateConflictIsAnErrorNotSuccess`, `TestCreateWithoutAnIDIsAnError`); only 200, 201 and
204 are success, so a 3xx without `Location` or a 202 is not a completed delete, and `Ping`
needs a JSON object (`TestUnexpectedStatusesAreNotSuccess`); bodies are read to 1 MiB, error
detail is printable and short with the bearer token redacted out of it, and `Retry-After` is
surfaced capped at an hour and never negative (`TestOversizedSuccessBodyIsRefused`,
`TestErrorBodyIsBoundedAndPrintable`, `TestTokenIsRedactedFromErrorDetail`,
`TestRetryAfterIsBoundedAndNonNegative`); a transport error names the path, not the query
that carries a user identifier (`TestTransportErrorsDoNotCarryTheQuery`); the round trip
against a server that mints unrelated IDs uses those IDs throughout
(`TestLifecycleAgainstServerMintedIDs`).
