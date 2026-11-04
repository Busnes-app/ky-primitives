// Package scim is the suite's SCIM 2.0 client (RFC 7643, RFC 7644) and the wire types it
// shares with a server. KySignOn provisions accounts into downstream products and third-party
// SCIM servers; before this package its resource types, paths and status handling were inlined
// in its sync engine, where a 409 on create counted as a delivered account, paths were built
// from local IDs the server had never issued, and generic targets got the suite signature in
// place of their bearer token. Each of those leaves an account that does not exist recorded as
// provisioned, which is the bar for a primitive living here.
//
// Users only. Groups, listing and bulk are not built because nothing in the suite sends them.
package scim

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	UserSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	PatchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// User is the core User resource with the attributes the suite exchanges. The server owns
// ID and Meta; the client never sends them. CreateUser and ReplaceUser always send roles,
// as [] when Roles is empty, so a replace revokes a last role.
//
// Active is a plain bool, so decoding a body without "active" gives false, although RFC 7643
// makes an absent active mean the account is usable. A server decoding inbound users with this
// type must check for the key itself (decode into a map or json.RawMessage first) or it creates
// disabled accounts, and a client that fetches a user and replaces it must set Active
// explicitly or it deactivates the account.
type User struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	UserName    string       `json:"userName"`
	DisplayName string       `json:"displayName,omitempty"`
	Name        *Name        `json:"name,omitempty"`
	Emails      []MultiValue `json:"emails,omitempty"`
	Roles       []MultiValue `json:"roles,omitempty"`
	Active      bool         `json:"active"`
	Meta        *Meta        `json:"meta,omitempty"`
}

// Name is the User's name complex attribute.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// MultiValue is one entry of a multi-valued attribute such as emails or roles.
type MultiValue struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta is the server-owned resource metadata.
type Meta struct {
	ResourceType string     `json:"resourceType,omitempty"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
	Version      string     `json:"version,omitempty"`
}

// PatchOperation is one entry of a PatchOp's Operations. Value is omitted when nil, which
// is what a remove wants.
type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

var (
	// ErrNotFound is a 404: the resource is not there. On a delete the caller decides
	// whether "already gone" is the outcome it wanted.
	ErrNotFound = errors.New("scim: resource not found")
	// ErrConflict is a 409: the server refused a create as a duplicate. It is never success;
	// look the account up by externalId or userName and reconcile.
	ErrConflict = errors.New("scim: conflict")
	// ErrUnauthorized is a 401 or 403: the bearer token is wrong or lacks the scope.
	ErrUnauthorized = errors.New("scim: unauthorized")
	// ErrThrottled is a 429 or 503; Error.RetryAfter carries the server's hint when it sent one.
	ErrThrottled = errors.New("scim: throttled")
	// ErrAmbiguous means a filter that should identify one user matched more than one.
	ErrAmbiguous = errors.New("scim: filter matched more than one user")
	// ErrMalformedResponse means a 2xx whose body is not the resource it should be, is
	// larger than the client will read, or lacks the id a create must return.
	ErrMalformedResponse = errors.New("scim: malformed response")
	// ErrInsecureURL means BaseURL is not an HTTPS URL with a host and nothing else.
	ErrInsecureURL = errors.New("scim: base URL must be https with a host and no credentials, query or fragment")
	// ErrNoToken means Token is empty.
	ErrNoToken = errors.New("scim: bearer token is required")
)

// Error is a non-2xx response. Detail is the server's text with the bearer token redacted,
// made printable and cut short, so it can reach a log or an audit record as it is.
type Error struct {
	Status   int
	ScimType string
	Detail   string
	// RetryAfter is the server's Retry-After hint, zero when absent, capped at one hour.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	s := fmt.Sprintf("scim: status %d", e.Status)
	if e.ScimType != "" {
		s += " " + e.ScimType
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Is maps the status to the sentinel a caller branches on.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == 404
	case ErrConflict:
		return e.Status == 409
	case ErrUnauthorized:
		return e.Status == 401 || e.Status == 403
	case ErrThrottled:
		return e.Status == 429 || e.Status == 503
	}
	return false
}

// detailLimit bounds server text before it reaches a log.
const detailLimit = 200

func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= detailLimit {
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
