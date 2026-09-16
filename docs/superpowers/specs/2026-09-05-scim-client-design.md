# scim: SCIM 2.0 client for the suite

Date: 2026-09-05. Requested by Yoshi: "add a SCIM client to the primitives lib".

## Why it belongs here

KySignOn is the suite's SCIM client. It pushes accounts to downstream products and to
third-party SCIM servers, and today its resource types, URL construction and status
handling are inlined in `kysignon-server/internal/sync/sync.go`. The access-lifecycle plan
(PR 07) lists the defects: generic SCIM targets get the suite signature instead of the
configured bearer token, downstream paths are built from local IDs rather than the IDs the
server minted, and a 409 on create counts as a successful sync. Each of those makes a wrong
answer look like a right one: an account that was never created reads as delivered. That
is the admission bar. The scaffold's `elimity-com/scim` server is the other end of the
wire, and the plan to replace it with stdlib handlers wants the same resource types.

## Scope

Users only. Groups, listing with pagination, bulk and PATCH beyond a list of operations are
not built: nothing in the suite sends them yet (kysignon's AGENTS.md: "SCIM group
provisioning remain[s] a separate roadmap step"). The package is named `scim`, not
`scimclient`, so the wire types can serve a stdlib server later without a rename.

## Package `github.com/Busnes-app/ky-primitives/scim` (stdlib only)

Types, RFC 7643 core User with the attributes the suite uses:

- `User{Schemas, ID, ExternalID, UserName, DisplayName, Name, Emails, Roles, Active, Meta}`
- `Name{Formatted, GivenName, FamilyName}`, `MultiValue{Value, Type, Primary, Display}`,
  `Meta{ResourceType, Created, LastModified, Location, Version}`
- `PatchOperation{Op, Path, Value}`; `ListResponse` (internal, for the filter lookup)
- `Error{Status, ScimType, Detail, RetryAfter}`: the RFC 7644 error body, `Detail` cut to
  printable text. `errors.Is` matches `ErrNotFound` (404), `ErrConflict` (409),
  `ErrUnauthorized` (401/403), `ErrThrottled` (429/503).

Client:

```go
c := &scim.Client{BaseURL: "https://host/scim/v2", Token: bearer, HTTPClient: netguard.Client(5*time.Second)}
created, err := c.CreateUser(ctx, user)          // POST /Users, returns the server's User (ID minted there)
u, err := c.FindUser(ctx, "externalId", localID) // GET /Users?filter=externalId eq "..."
u, err := c.GetUser(ctx, remoteID)               // GET /Users/{id}
u, err := c.ReplaceUser(ctx, remoteID, user)     // PUT /Users/{id}
u, err := c.PatchUser(ctx, remoteID, scim.PatchOperation{Op: "replace", Path: "active", Value: false})
err = c.DeleteUser(ctx, remoteID)                // DELETE /Users/{id}; 404 is ErrNotFound, caller decides
err = c.Ping(ctx)                                // GET /ServiceProviderConfig; proves URL and token
```

Rules the client enforces, each pinned by a test:

- `BaseURL` is HTTPS with a host and no credentials, query or fragment, checked before any
  request. A bearer token over plaintext is the token published.
- Redirects are refused. Go would otherwise replay the body, and the Authorization header,
  at a host the operator never named.
- The token is sent only as `Authorization: Bearer`; no signing, no query parameter.
- Resource IDs are path-escaped and must be non-empty: `DELETE /Users/` with an empty ID is
  a different endpoint, not a delete.
- The filter value is quoted with `\` and `"` escaped; the attribute name is restricted to
  `[A-Za-z][A-Za-z0-9.]*`. An operator-supplied value cannot change the filter's shape.
- `FindUser` returns `ErrNotFound` on zero results and `ErrAmbiguous` on more than one. A
  lookup that picks the first of two is the failure mode the bar names.
- `CreateUser` returns the resource the server sent; a 2xx without an `id` is an error, since
  the ID is the one thing the caller needs from a create. 409 is `ErrConflict`, never success.
- Response bodies are read to 1 MiB. Error detail is printable and at most 200 characters
  before it reaches a log or an audit record.
- `HTTPClient` is the caller's. Products already own an outbound policy (kysignon's
  `netguard`, recoveryclient's private-range rule); the lib does not pick one for them. The
  default is a ten-second client.

## Not decided here

Whether kysignon stores remote IDs per connector (PR 07) and how the connector type becomes
explicit are product changes. This package gives them `CreateUser`'s returned ID and
`FindUser` by `externalId`, which is what those changes need.

## Testing

`httptest.NewTLSServer` with its client, as `oidcverify` does. One test per rule above plus a
round trip through a fake server that assigns unrelated IDs: create, look up by externalId,
replace, deactivate, delete.
