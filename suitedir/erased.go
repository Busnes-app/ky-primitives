package suitedir

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ErasedSubject identifies an erased KyIdentity account. The notice outlives the account.
type ErasedSubject struct {
	Sub      string `json:"sub"`
	OrgID    string `json:"org_id"`
	Revision int64  `json:"revision"`
}

const (
	erasedPageSize = 500
	maxErasedPages = 100
)

var (
	// KyIdentity issues OIDC subjects and canonical lowercase organisation UUIDs.
	erasedSub          = regexp.MustCompile(`^[ -~]{1,255}$`)
	erasedOrg          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	errErasedMalformed = errors.New("suitedir: erased: malformed page")
)

// Erased lists erasures after since on a multi-tenant KyIdentity, in revision order.
// It follows up to 100 pages and returns the last revision read, or since for an empty
// result. On any error it returns nil and the original since. Save the revision only
// after applying the notices. After a restore, start at zero and read until empty.
func (c *Client) Erased(ctx context.Context, since int64) ([]ErasedSubject, int64, error) {
	if since < 0 {
		return nil, since, errors.New("suitedir: erased: since is negative")
	}
	q := url.Values{"since": {strconv.FormatInt(since, 10)}, "limit": {strconv.Itoa(erasedPageSize)}}
	subjects, last := []ErasedSubject{}, since
	for range maxErasedPages {
		var page erasedPage
		if err := c.get(ctx, "erased", q, &page); err != nil {
			return nil, since, err
		}
		for _, entry := range page.subjects {
			if entry.Revision <= last {
				return nil, since, errErasedMalformed
			}
			last = entry.Revision
		}
		subjects = append(subjects, page.subjects...)
		if page.next == "" {
			break
		}
		if len(page.subjects) == 0 || page.next != strconv.FormatInt(last, 10) {
			return nil, since, errErasedMalformed
		}
		q.Set("since", page.next)
	}
	return subjects, last, nil
}

type erasedPage struct {
	subjects []ErasedSubject
	next     string
}

func (p *erasedPage) UnmarshalJSON(raw []byte) error {
	var rows json.RawMessage
	fields := map[string]any{"subjects": &rows, "next": &p.next}
	if !decodeErasedFields(json.NewDecoder(bytes.NewReader(raw)), fields) {
		return errErasedMalformed
	}
	if _, omitted := fields["next"]; !omitted && p.next == "" {
		return errErasedMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(rows))
	if start, err := dec.Token(); err != nil || start != json.Delim('[') {
		return errErasedMalformed
	}
	for dec.More() {
		var e ErasedSubject
		if len(p.subjects) == erasedPageSize || !decodeErasedFields(dec, map[string]any{"sub": &e.Sub, "org_id": &e.OrgID, "revision": &e.Revision}) ||
			!erasedSub.MatchString(e.Sub) || strings.TrimSpace(e.Sub) == "" || !erasedOrg.MatchString(e.OrgID) {
			return errErasedMalformed
		}
		p.subjects = append(p.subjects, e)
	}
	return nil
}

// Decode one object, matching exact member names and consuming each field once
// so an ambiguous erasure cannot select an account.
func decodeErasedFields(dec *json.Decoder, fields map[string]any) bool {
	if start, err := dec.Token(); err != nil || start != json.Delim('{') {
		return false
	}
	for dec.More() {
		name, err := dec.Token()
		key, ok := name.(string)
		if err != nil || !ok || fields[key] == nil || dec.Decode(fields[key]) != nil {
			return false
		}
		delete(fields, key)
	}
	end, err := dec.Token()
	return err == nil && end == json.Delim('}')
}
