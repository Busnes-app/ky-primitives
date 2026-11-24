// Package s3 accesses opaque objects in one S3-compatible bucket over signed HTTPS.
// Products own sealing, authorization, namespace selection, caches and retained-byte policy.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrPrecondition  = errors.New("s3: precondition failed")
	ErrAlreadyExists = fs.ErrExist
	ErrNotFound      = fs.ErrNotExist
	ErrFailure       = errors.New("s3: request failed")
	ErrInvalid       = errors.New("s3: invalid configuration or input")
)

// Error contains only locally selected operation/status data, never a URL, key, provider
// message or underlying transport error. Retryable describes a transient failure, not whether
// replaying a write is safe. Use errors.Is(err, ErrNotFound) for a missing object/version.
type Error struct {
	Operation     string
	StatusCode    int
	Retryable     bool
	Missing       bool
	AlreadyExists bool
	Precondition  bool
}

func (e *Error) Error() string {
	if e.Precondition {
		return "s3: " + e.Operation + ": precondition failed"
	}
	if e.AlreadyExists {
		return "s3: " + e.Operation + ": object already exists"
	}
	if e.Missing {
		return "s3: " + e.Operation + ": object or version not found"
	}
	return fmt.Sprintf("s3: %s failed (HTTP %d)", e.Operation, e.StatusCode)
}
func (e *Error) Is(target error) bool {
	return (target == ErrPrecondition && e.Precondition) || (target == ErrAlreadyExists && e.AlreadyExists) || (target == ErrNotFound && e.Missing) || (target == ErrFailure && !e.Missing && !e.AlreadyExists && !e.Precondition)
}

// Config selects a path-style HTTPS endpoint and bucket. HTTP supplies optional transport,
// TLS roots and timeout; redirects are always refused. Nil HTTP uses a 30-second client.
// Credentials are explicit; no ambient credential chain, endpoint discovery or logging.
type Config struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string       `json:"-"`
	SecretKey string       `json:"-"`
	HTTP      *http.Client `json:"-"`
}

func (Config) String() string   { return "s3.Config" }
func (Config) GoString() string { return "s3.Config" }

type Client struct {
	endpoint                             url.URL
	bucket, region, accessKey, secretKey string
	http                                 http.Client
	now                                  func() time.Time
}

func (Client) String() string   { return "s3.Client" }
func (Client) GoString() string { return "s3.Client" }

// New validates configuration without making a request. Private HTTPS endpoints are allowed:
// this is operator configuration, never a user-supplied fetch URL. Keep normal TLS verification.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrInvalid
	}
	if cfg.Bucket == "" || strings.ContainsAny(cfg.Bucket, "/\\\r\n") || cfg.AccessKey == "" || strings.ContainsAny(cfg.AccessKey, " /,\r\n\t") || cfg.SecretKey == "" {
		return nil, ErrInvalid
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if strings.ContainsAny(cfg.Region, "/, \r\n\t") {
		return nil, ErrInvalid
	}
	client := http.Client{Timeout: 30 * time.Second}
	if cfg.HTTP != nil {
		client = *cfg.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: *u, bucket: cfg.Bucket, region: cfg.Region, accessKey: cfg.AccessKey, secretKey: cfg.SecretKey, http: client, now: time.Now}, nil
}

// Object describes logical S3 bytes, not a product's plaintext or accounting policy.
// VersionID is opaque ("null" is a valid ID); empty means the provider supplied none.
type Object struct {
	Key          string
	VersionID    string
	Size         int64
	DeleteMarker bool
	IsLatest     bool
	// LastModified is provider metadata, zero when absent. Products must not infer orphan
	// age from a zero value; storage retention policy remains outside this client.
	LastModified time.Time
	// ETag is an opaque quoted provider token, not a content digest or a version ID.
	ETag string
}

// Put streams a known-length body with SigV4 UNSIGNED-PAYLOAD over HTTPS, without
// whole-body hashing, buffering or local spool. It is never retried: replay can add a version.
// The caller owns its reader, which must unblock on cancellation if it can block in Read.
func (c *Client) Put(ctx context.Context, key string, body io.Reader, size int64) (Object, error) {
	return c.put(ctx, key, body, size, "", "")
}

// PutIfAbsent streams PUT with If-None-Match: *. ErrAlreadyExists means the provider
// returned HTTP 412; no HEAD-then-PUT fallback or automatic replay is attempted. The
// provider must implement atomic conditional writes; qualify that behavior before use.
func (c *Client) PutIfAbsent(ctx context.Context, key string, body io.Reader, size int64) (Object, error) {
	return c.put(ctx, key, body, size, "If-None-Match", "*")
}

// PutIfMatch streams only if the current object's ETag exactly matches the supplied strong
// quoted token. HTTP 412 is ErrPrecondition; 404/409 remain failures. Never retries or falls
// back to unconditional PUT. Products own fencing/ledger policy and provider qualification.
func (c *Client) PutIfMatch(ctx context.Context, key, etag string, body io.Reader, size int64) (Object, error) {
	if !validETag(etag) {
		return Object{}, ErrInvalid
	}
	return c.put(ctx, key, body, size, "If-Match", etag)
}

func (c *Client) put(ctx context.Context, key string, body io.Reader, size int64, condition, token string) (Object, error) {
	if key == "" || size < 0 || (body == nil && size != 0) {
		return Object{}, ErrInvalid
	}
	var stream io.Reader
	if size > 0 {
		// One extra byte lets net/http detect a length mismatch without draining an unbounded reader.
		limit := size
		if size < 1<<63-1 {
			limit++
		}
		stream = io.LimitReader(body, limit)
	}
	req, err := c.request(ctx, http.MethodPut, key, nil, stream)
	if err != nil {
		return Object{}, err
	}
	if size == 0 && body != nil {
		if err := req.Context().Err(); err != nil {
			return Object{}, err
		}
		// Refuse an incorrect zero length before S3 can replace any existing object.
		var probe [1]byte
		n, err := io.ReadFull(body, probe[:])
		if err := req.Context().Err(); err != nil {
			return Object{}, err
		}
		if n != 0 || err != io.EOF {
			return Object{}, ErrInvalid
		}
	}
	req.ContentLength = size
	if condition != "" {
		req.Header.Set(condition, token)
	}
	resp, err := c.do(req, false, false)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.StatusCode == http.StatusPreconditionFailed {
			e.AlreadyExists = condition == "If-None-Match"
			e.Precondition = condition == "If-Match"
		}
		return Object{}, err
	}
	defer resp.Body.Close()
	etag, err := responseETag("PUT", resp)
	if err != nil {
		return Object{}, err
	}
	return Object{Key: key, VersionID: resp.Header.Get("X-Amz-Version-Id"), Size: size, ETag: etag}, nil
}

// Get opens the exact version when versionID is nonempty, otherwise the current object.
// Callers close the returned stream. No mid-stream retry/resume is attempted.
func (c *Client) Get(ctx context.Context, key, versionID string) (io.ReadCloser, Object, error) {
	if key == "" {
		return nil, Object{}, ErrInvalid
	}
	req, err := c.request(ctx, http.MethodGet, key, versionQuery(versionID), nil)
	if err != nil {
		return nil, Object{}, err
	}
	// Content-Encoding belongs to the stored object; never let net/http decompress it.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.do(req, true, true)
	if err != nil {
		return nil, Object{}, err
	}
	obj, err := metadata("GET", key, versionID, resp)
	if err != nil {
		resp.Body.Close()
		return nil, Object{}, err
	}
	return &safeBody{ReadCloser: resp.Body, ctx: ctx}, obj, nil
}

func (c *Client) Head(ctx context.Context, key, versionID string) (Object, error) {
	if key == "" {
		return Object{}, ErrInvalid
	}
	req, err := c.request(ctx, http.MethodHead, key, versionQuery(versionID), nil)
	if err != nil {
		return Object{}, err
	}
	resp, err := c.do(req, true, true)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	return metadata("HEAD", key, versionID, resp)
}

// Delete removes an exact version, including a delete marker. Empty versionID sends a normal
// S3 DELETE: in a versioned bucket this creates a marker and retains historical bytes. Only
// exact-version deletes are automatically retried. Missing exact versions are already gone.
func (c *Client) Delete(ctx context.Context, key, versionID string) (Object, error) {
	if key == "" {
		return Object{}, ErrInvalid
	}
	req, err := c.request(ctx, http.MethodDelete, key, versionQuery(versionID), nil)
	if err != nil {
		return Object{}, err
	}
	resp, err := c.do(req, versionID != "", true)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	id := resp.Header.Get("X-Amz-Version-Id")
	if id == "" {
		id = versionID
	}
	if versionID != "" && id != versionID {
		return Object{}, failure("DELETE", resp.StatusCode)
	}
	return Object{Key: key, VersionID: id, DeleteMarker: resp.Header.Get("X-Amz-Delete-Marker") == "true"}, nil
}

func versionQuery(id string) url.Values {
	if id == "" {
		return nil
	}
	return url.Values{"versionId": {id}}
}

func metadata(op, key, versionID string, resp *http.Response) (Object, error) {
	id := resp.Header.Get("X-Amz-Version-Id")
	if resp.ContentLength < 0 || (versionID != "" && id != versionID) || resp.Header.Get("X-Amz-Delete-Marker") == "true" {
		return Object{}, failure(op, resp.StatusCode)
	}
	var modified time.Time
	if raw := resp.Header.Get("Last-Modified"); raw != "" {
		var err error
		if modified, err = http.ParseTime(raw); err != nil {
			return Object{}, failure(op, resp.StatusCode)
		}
	}
	etag, err := responseETag(op, resp)
	if err != nil {
		return Object{}, err
	}
	return Object{Key: key, VersionID: id, Size: resp.ContentLength, LastModified: modified, ETag: etag}, nil
}

func failure(op string, status int) *Error {
	return &Error{Operation: op, StatusCode: status, Retryable: status == 0 || status == 429 || status == 500 || status == 502 || status == 503 || status == 504}
}

// do retries only safe, bodyless requests. A status error never includes provider-controlled
// text: even an error code, header, or transport error can echo a credential.
func (c *Client) do(req *http.Request, retry, missing bool) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		c.sign(req, c.now())
		resp, err := c.http.Do(req)
		var result *Error
		if err != nil {
			if e := req.Context().Err(); e != nil {
				return nil, e
			}
			result = failure(req.Method, 0)
		} else {
			ok := resp.StatusCode == http.StatusOK || (req.Method == http.MethodPut && (resp.StatusCode == 201 || resp.StatusCode == 204)) || (req.Method == http.MethodDelete && resp.StatusCode == 204)
			if ok {
				return resp, nil
			}
			result = failure(req.Method, resp.StatusCode)
			result.Missing = missing && resp.StatusCode == 404
			resp.Body.Close()
		}
		if !retry || !result.Retryable || attempt == 2 {
			return nil, result
		}
		wait := time.NewTimer(time.Duration(1<<attempt) * 100 * time.Millisecond)
		select {
		case <-req.Context().Done():
			wait.Stop()
			return nil, req.Context().Err()
		case <-wait.C:
		}
	}
}

type safeBody struct {
	io.ReadCloser
	ctx context.Context
}

func (b *safeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		if b.ctx.Err() != nil {
			err = b.ctx.Err()
		} else {
			err = failure("GET", 0)
		}
	}
	return n, err
}
func (b *safeBody) Close() error {
	if err := b.ReadCloser.Close(); err != nil {
		if b.ctx.Err() != nil {
			return b.ctx.Err()
		}
		return failure("GET", 0)
	}
	return nil
}

// request preserves key/prefix bytes: no path cleaning or interpretation of opaque IDs.
func (c *Client) request(ctx context.Context, method, key string, q url.Values, body io.Reader) (*http.Request, error) {
	u := c.endpoint
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + c.bucket
	if key != "" {
		u.Path += "/" + key
	}
	u.RawPath = strings.TrimSuffix(c.endpoint.EscapedPath(), "/") + "/" + escape(c.bucket, false)
	if key != "" {
		u.RawPath += "/" + escape(key, true)
	}
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, ErrInvalid
	}
	return req, nil
}

func escape(s string, slash bool) string {
	s = strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
	if slash {
		s = strings.ReplaceAll(s, "%2F", "/")
	}
	return s
}

// validETag accepts exactly one strong RFC 9110 entity tag. Preserve the quotes/opaque bytes;
// lists, wildcards, weak tags and header controls cannot stand in for an exact predecessor.
func validETag(tag string) bool {
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return false
	}
	for i := 1; i < len(tag)-1; i++ {
		b := tag[i]
		if b != 0x21 && (b < 0x23 || b == 0x7f) {
			return false
		}
	}
	return true
}

func responseETag(op string, resp *http.Response) (string, error) {
	tag := resp.Header.Get("ETag")
	if tag != "" && !validETag(tag) {
		return "", failure(op, resp.StatusCode)
	}
	return tag, nil
}
