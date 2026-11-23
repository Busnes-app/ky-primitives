package s3

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"time"
)

const maxListBody = 8 << 20

// ObjectPage is one bounded ListObjectsV2 page. Next is an opaque continuation token.
type ObjectPage struct {
	Objects []Object
	Next    string
}

// VersionCursor preserves both S3 markers. VersionID is never URL-decoded or interpreted.
type VersionCursor struct{ Key, VersionID string }

type VersionPage struct {
	Objects []Object // Versions and delete markers in provider order.
	Next    VersionCursor
}

type objectXML struct {
	XMLName      xml.Name
	Key          string
	VersionID    string `xml:"VersionId"`
	Size         *int64
	IsLatest     bool
	LastModified time.Time
}

func (c *Client) ListObjects(ctx context.Context, prefix, continuation string) (ObjectPage, error) {
	q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}, "encoding-type": {"url"}}
	if continuation != "" {
		q.Set("continuation-token", continuation)
	}
	var body struct {
		XMLName   xml.Name    `xml:"ListBucketResult"`
		Truncated *bool       `xml:"IsTruncated"`
		Encoding  string      `xml:"EncodingType"`
		Next      string      `xml:"NextContinuationToken"`
		Objects   []objectXML `xml:"Contents"`
	}
	if err := c.list(ctx, q, &body); err != nil {
		return ObjectPage{}, err
	}
	if body.Truncated == nil || len(body.Objects) > 1000 {
		return ObjectPage{}, failure("LIST", 200)
	}
	out := ObjectPage{Objects: make([]Object, 0, len(body.Objects))}
	seen := map[string]bool{}
	for _, item := range body.Objects {
		key, err := decodeKey(item.Key, body.Encoding)
		if err != nil || key == "" || !strings.HasPrefix(key, prefix) || item.Size == nil || *item.Size < 0 || seen[key] {
			return ObjectPage{}, failure("LIST", 200)
		}
		seen[key] = true
		out.Objects = append(out.Objects, Object{Key: key, Size: *item.Size, LastModified: item.LastModified})
	}
	if *body.Truncated {
		if body.Next == "" || body.Next == continuation || len(out.Objects) == 0 {
			return ObjectPage{}, failure("LIST", 200)
		}
		out.Next = body.Next
	}
	return out, nil
}

func (c *Client) ListObjectVersions(ctx context.Context, prefix string, cursor VersionCursor) (VersionPage, error) {
	if cursor.Key == "" && cursor.VersionID != "" {
		return VersionPage{}, ErrInvalid
	}
	q := url.Values{"versions": {""}, "prefix": {prefix}, "max-keys": {"1000"}, "encoding-type": {"url"}}
	if cursor.Key != "" {
		q.Set("key-marker", cursor.Key)
	}
	if cursor.VersionID != "" {
		q.Set("version-id-marker", cursor.VersionID)
	}
	var body struct {
		XMLName     xml.Name `xml:"ListVersionsResult"`
		Truncated   *bool    `xml:"IsTruncated"`
		Encoding    string   `xml:"EncodingType"`
		NextKey     string   `xml:"NextKeyMarker"`
		NextVersion string   `xml:"NextVersionIdMarker"`
		// Named pagination fields are decoded above; remaining Version/DeleteMarker elements
		// share one slice so XML order is retained. Other S3 metadata is ignored.
		Entries []objectXML `xml:",any"`
	}
	if err := c.list(ctx, q, &body); err != nil {
		return VersionPage{}, err
	}
	out := VersionPage{Objects: make([]Object, 0)}
	seen := map[VersionCursor]bool{}
	for _, item := range body.Entries {
		marker := item.XMLName.Local == "DeleteMarker"
		if !marker && item.XMLName.Local != "Version" {
			continue
		}
		key, err := decodeKey(item.Key, body.Encoding)
		if err != nil || key == "" || !strings.HasPrefix(key, prefix) || item.VersionID == "" || (!marker && (item.Size == nil || *item.Size < 0)) {
			return VersionPage{}, failure("LIST", 200)
		}
		ref := VersionCursor{key, item.VersionID}
		if seen[ref] {
			return VersionPage{}, failure("LIST", 200)
		}
		seen[ref] = true
		obj := Object{Key: key, VersionID: item.VersionID, DeleteMarker: marker, IsLatest: item.IsLatest, LastModified: item.LastModified}
		if !marker {
			obj.Size = *item.Size
		}
		out.Objects = append(out.Objects, obj)
	}
	if body.Truncated == nil || len(out.Objects) > 1000 {
		return VersionPage{}, failure("LIST", 200)
	}
	if *body.Truncated {
		key, err := decodeKey(body.NextKey, body.Encoding)
		out.Next = VersionCursor{Key: key, VersionID: body.NextVersion}
		if err != nil || key == "" || !strings.HasPrefix(key, prefix) || out.Next == cursor || len(out.Objects) == 0 {
			return VersionPage{}, failure("LIST", 200)
		}
	}
	return out, nil
}

func decodeKey(key, encoding string) (string, error) {
	switch encoding {
	case "":
		return key, nil
	case "url":
		return url.PathUnescape(key)
	default:
		return "", ErrFailure
	}
}

func (c *Client) list(ctx context.Context, q url.Values, result any) error {
	req, err := c.request(ctx, "GET", "", q, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req, true, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return failure("LIST", 0)
	}
	if len(raw) > maxListBody {
		return failure("LIST", 200)
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	if err := d.Decode(result); err != nil {
		return failure("LIST", 200)
	}
	// Decode alone accepts a second document; only XML whitespace/comments may follow.
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return failure("LIST", 200)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return failure("LIST", 200)
			}
		case xml.Comment:
		default:
			return failure("LIST", 200)
		}
	}
}
