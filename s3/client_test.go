package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSecret = "test-secret-32-bytes-not-a-real-key"
const testAccess = "test-access-key"

func tlsClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, err := New(Config{Endpoint: s.URL, Bucket: "bucket", AccessKey: testAccess, SecretKey: testSecret, HTTP: s.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func TestConfigurationAndSecretRedaction(t *testing.T) {
	base := Config{Endpoint: "https://s3.example.test", Bucket: "bucket", AccessKey: testAccess, SecretKey: testSecret}
	for _, endpoint := range []string{"http://127.0.0.1", "https://user:" + testSecret + "@host", "https://host?secret=" + testSecret, "https://host#" + testSecret, "://" + testSecret} {
		cfg := base
		cfg.Endpoint = endpoint
		if _, err := New(cfg); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), testSecret) {
			t.Fatalf("unsafe configuration error: %v", err)
		}
	}
	for _, change := range []func(*Config){func(c *Config) { c.Bucket = "" }, func(c *Config) { c.Bucket = "a/b" }, func(c *Config) { c.AccessKey = "\r\n" }, func(c *Config) { c.SecretKey = "" }, func(c *Config) { c.Region = "a/b" }} {
		cfg := base
		change(&cfg)
		if _, err := New(cfg); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted invalid config")
		}
	}
	c, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{base, &base, c, *c} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, testAccess) || strings.Contains(got, testSecret) {
				t.Fatal("formatted credentials")
			}
		}
		raw, _ := json.Marshal(value)
		if strings.Contains(string(raw), testAccess) || strings.Contains(string(raw), testSecret) {
			t.Fatal("serialized credentials")
		}
	}
}

func TestOpaqueKeysVersionsAndMetadata(t *testing.T) {
	key := "orgs/a/raw%2F+ space//../é?#"
	version := "v%2F+ /=&é"
	var calls atomic.Int32
	c, s := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.EscapedPath() != "/bucket/"+escape(key, true) || r.URL.Query().Get("versionId") != version {
			t.Errorf("changed opaque path/ID: %s %q", r.URL.EscapedPath(), r.URL.Query().Get("versionId"))
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+testAccess+"/") {
			t.Error("unsigned request")
		}
		w.Header().Set("X-Amz-Version-Id", version)
		w.Header().Set("Content-Length", "3")
		if r.Method != "HEAD" {
			_, _ = io.WriteString(w, "abc")
		}
	})
	for _, head := range []bool{false, true} {
		var obj Object
		var err error
		if head {
			obj, err = c.Head(context.Background(), key, version)
		} else {
			var body io.ReadCloser
			body, obj, err = c.Get(context.Background(), key, version)
			if err == nil {
				raw, e := io.ReadAll(body)
				body.Close()
				if e != nil || string(raw) != "abc" {
					t.Fatal(string(raw), e)
				}
			}
		}
		if err != nil || obj.Size != 3 || obj.VersionID != version || obj.Key != key {
			t.Fatalf("metadata %+v %v", obj, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
	// A configured encoded base path also remains literal.
	cfg := Config{Endpoint: s.URL + "/gateway%2Fbase", Bucket: "bucket", AccessKey: testAccess, SecretKey: testSecret, HTTP: s.Client()}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.request(context.Background(), "GET", key, versionQuery(version), nil)
	if err != nil || !strings.HasPrefix(r.URL.EscapedPath(), "/gateway%2Fbase/bucket/") {
		t.Fatal(r, err)
	}
}

func TestStreamingPutAndReturnedVersion(t *testing.T) {
	arrived := make(chan struct{})
	payload := strings.Repeat("x", 64<<10) + "last"
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		if r.ContentLength != int64(len(payload)) || r.Header.Get("X-Amz-Content-Sha256") != "UNSIGNED-PAYLOAD" {
			t.Error("wrong streaming request")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil || string(raw) != payload {
			t.Errorf("stream: %d %v", len(raw), err)
		}
		w.Header().Set("X-Amz-Version-Id", "opaque+/%=version")
		w.WriteHeader(200)
	})
	reader, writer := io.Pipe()
	t.Cleanup(func() { reader.Close(); writer.Close() })
	finished := make(chan error, 1)
	go func() {
		obj, err := c.Put(context.Background(), "key", reader, int64(len(payload)))
		if err == nil && (obj.Size != int64(len(payload)) || obj.VersionID != "opaque+/%=version") {
			err = errors.New("wrong PUT metadata")
		}
		finished <- err
	}()
	go func() {
		_, err := io.WriteString(writer, payload[:64<<10])
		if err != nil {
			writer.CloseWithError(err)
		}
	}()
	select {
	case <-arrived: // The request reached S3 before the reader could finish.
	case <-time.After(3 * time.Second):
		t.Fatal("PUT buffered the whole body before sending")
	}
	_, _ = io.WriteString(writer, "last")
	writer.Close()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestMissingFailuresRetriesAndRedirects(t *testing.T) {
	var requests atomic.Int32
	status := atomic.Int32{}
	status.Store(503)
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "https://"+testSecret+".invalid/")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, testSecret+testAccess)
	})
	_, err := c.Head(context.Background(), "secret-in-key", "")
	var failure *Error
	if !errors.As(err, &failure) || !failure.Retryable || failure.StatusCode != 503 || requests.Load() != 3 {
		t.Fatalf("retry %v %d", err, requests.Load())
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, err), testSecret) || strings.Contains(fmt.Sprintf(format, err), testAccess) {
			t.Fatal("error leaked credentials")
		}
	}
	status.Store(404)
	if _, err = c.Head(context.Background(), "missing", ""); !errors.Is(err, ErrNotFound) || errors.Is(err, ErrFailure) {
		t.Fatal(err)
	}
	if _, err = c.ListObjects(context.Background(), "", ""); !errors.Is(err, ErrFailure) || errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	status.Store(403)
	requests.Store(0)
	if _, err = c.Delete(context.Background(), "key", "v"); !errors.Is(err, ErrFailure) || requests.Load() != 1 {
		t.Fatal(err, requests.Load())
	}
	status.Store(503)
	requests.Store(0)
	if _, err = c.Put(context.Background(), "key", strings.NewReader("x"), 1); !errors.Is(err, ErrFailure) || requests.Load() != 1 {
		t.Fatal("PUT was replayed", err, requests.Load())
	}
	requests.Store(0)
	if _, err = c.Delete(context.Background(), "key", ""); !errors.Is(err, ErrFailure) || requests.Load() != 1 {
		t.Fatal("unversioned DELETE was replayed", err, requests.Load())
	}

	var reached atomic.Bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer destination.Close()
	c, s := tlsClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) })
	callerHTTP := s.Client()
	called := false
	callerHTTP.CheckRedirect = func(*http.Request, []*http.Request) error { called = true; return nil }
	c, err = New(Config{Endpoint: s.URL, Bucket: "bucket", AccessKey: testAccess, SecretKey: testSecret, HTTP: callerHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Head(context.Background(), "key", ""); !errors.Is(err, ErrFailure) || reached.Load() || called {
		t.Fatal("redirect followed", err)
	}
	if callerHTTP.CheckRedirect == nil {
		t.Fatal("caller client was mutated")
	}
}

func TestCancellationAndVersionBinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "x")
		w.(http.Flusher).Flush()
		close(ready)
		<-r.Context().Done()
	})
	body, _, err := c.Get(ctx, "key", "")
	if err != nil {
		t.Fatal(err)
	}
	<-ready
	cancel()
	_, err = io.ReadAll(body)
	body.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stream: %v", err)
	}
	c, _ = tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Version-Id", "other")
		w.Header().Set("Content-Length", "0")
	})
	if _, _, err = c.Get(context.Background(), "key", "wanted"); !errors.Is(err, ErrFailure) {
		t.Fatal("wrong version accepted", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err = c.Head(ctx, "key", ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestListPagesKeepOpaqueMarkers(t *testing.T) {
	version := "v%2F+/=& space"
	key := "orgs/a/key +%/é"
	calls := 0
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Get("prefix") != "orgs/a/" || q.Get("encoding-type") != "url" {
			t.Error(q)
		}
		if _, versions := q["versions"]; versions {
			if calls == 2 && (q.Get("key-marker") != key || q.Get("version-id-marker") != version) {
				t.Errorf("changed version cursor: %v", q)
			}
			fmt.Fprintf(w, `<ListVersionsResult><EncodingType>url</EncodingType><IsTruncated>%t</IsTruncated><Version><Key>%s</Key><VersionId>null</VersionId><Size>7</Size></Version><DeleteMarker><Key>%s</Key><VersionId>marker+/=</VersionId></DeleteMarker><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>v%%2F+/=&amp; space</NextVersionIdMarker></ListVersionsResult>`, calls == 1, escape(key, false), escape(key, false), escape(key, false))
		} else {
			if calls == 4 && q.Get("continuation-token") != version {
				t.Errorf("changed token: %v", q)
			}
			fmt.Fprintf(w, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>%t</IsTruncated><Contents><Key>%s</Key><Size>7</Size></Contents><NextContinuationToken>v%%2F+/=&amp; space</NextContinuationToken></ListBucketResult>`, calls == 3, escape(key, false))
		}
	})
	p, err := c.ListObjectVersions(context.Background(), "orgs/a/", VersionCursor{})
	if err != nil || len(p.Objects) != 2 || p.Objects[0].VersionID != "null" || !p.Objects[1].DeleteMarker || p.Next != (VersionCursor{key, version}) {
		t.Fatalf("versions %+v %v", p, err)
	}
	p, err = c.ListObjectVersions(context.Background(), "orgs/a/", p.Next)
	if err != nil || p.Next != (VersionCursor{}) {
		t.Fatal(p, err)
	}
	objects, err := c.ListObjects(context.Background(), "orgs/a/", "")
	if err != nil || objects.Next != version || objects.Objects[0].Key != key {
		t.Fatal(objects, err)
	}
	objects, err = c.ListObjects(context.Background(), "orgs/a/", objects.Next)
	if err != nil || objects.Next != "" {
		t.Fatal(objects, err)
	}
}

func TestMalformedListingsFailBeforeReturningAnyObject(t *testing.T) {
	for _, raw := range []string{
		`<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>other-org/key</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>`,
		`<ListVersionsResult><Version><Key>orgs/a/k</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>`,
		`<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>orgs/a/k</Key><VersionId>v</VersionId></Version></ListVersionsResult>`,
		`<ListVersionsResult><IsTruncated>true</IsTruncated><Version><Key>orgs/a/k</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>`,
		`<ListVersionsResult><IsTruncated>false</IsTruncated><DeleteMarker><Key>orgs/a/k</Key></DeleteMarker></ListVersionsResult>`,
		`<ListVersionsResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Version><Key>orgs/a/%zz</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>`,
		`<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>orgs/a/k</Key><VersionId>v</VersionId><Size>-1</Size></Version></ListVersionsResult>`,
		`<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult><extra/>`,
		strings.Repeat("x", maxListBody+1),
	} {
		c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, raw) })
		p, err := c.ListObjectVersions(context.Background(), "orgs/a/", VersionCursor{})
		if !errors.Is(err, ErrFailure) || len(p.Objects) != 0 {
			t.Fatalf("malformed listing accepted: %+v %v", p, err)
		}
	}
}

// Keep URL-decoding expectations explicit: opaque version IDs never pass through this helper.
func TestURLDecoderPreservesLiteralPlus(t *testing.T) {
	if got, err := decodeKey("a%2Bb%20c%252F", "url"); err != nil || got != "a+b c%2F" {
		t.Fatal(got, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type badBody struct{}

func (badBody) Read([]byte) (int, error) { return 0, errors.New(testSecret) }
func (badBody) Close() error             { return errors.New(testSecret) }

func TestTransportAndStreamErrorsHideSecrets(t *testing.T) {
	cfg := Config{Endpoint: "https://s3.example.test", Bucket: "bucket", AccessKey: testAccess, SecretKey: testSecret, HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(testSecret) })}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Put(context.Background(), "key", strings.NewReader("x"), 1)
	if !errors.Is(err, ErrFailure) || strings.Contains(err.Error(), testSecret) {
		t.Fatal("transport error leaked", err)
	}
	cfg.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: 1, Body: badBody{}}, nil
	})}
	c, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := c.Get(context.Background(), "key", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(body)
	if !errors.Is(err, ErrFailure) || strings.Contains(err.Error(), testSecret) {
		t.Fatal("stream error leaked", err)
	}
	if err = body.Close(); !errors.Is(err, ErrFailure) || strings.Contains(err.Error(), testSecret) {
		t.Fatal("close error leaked", err)
	}
}

// Content-Encoding is object metadata, not permission to transform sealed stored bytes.
func TestGetPreservesGzipObjectBytes(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := io.WriteString(zw, "stored object bytes"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(compressed.Len()))
		w.Header().Set("X-Amz-Version-Id", "opaque-version")
		if r.Method != "HEAD" {
			_, _ = w.Write(compressed.Bytes())
		}
	})
	head, err := c.Head(context.Background(), "key", "opaque-version")
	if err != nil {
		t.Fatal(err)
	}
	body, obj, err := c.Get(context.Background(), "key", "opaque-version")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(raw, compressed.Bytes()) || obj != head || obj.Size != int64(compressed.Len()) {
		t.Fatal("GET changed stored bytes or metadata", obj, head, err)
	}
}

func TestZeroSizePutChecksTheReaderBeforeSending(t *testing.T) {
	var requests atomic.Int32
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if raw, err := io.ReadAll(r.Body); err != nil || len(raw) != 0 {
			t.Error("nonempty zero-length request", err)
		}
	})
	for _, body := range []io.Reader{strings.NewReader("must not replace existing bytes"), badBody{}} {
		if _, err := c.Put(context.Background(), "existing", body, 0); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), testSecret) {
			t.Fatal("invalid zero length accepted", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("invalid zero-length PUT reached S3")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Put(ctx, "existing", strings.NewReader(""), 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, body := range []io.Reader{nil, strings.NewReader("")} {
		if obj, err := c.Put(context.Background(), "empty", body, 0); err != nil || obj.Size != 0 {
			t.Fatal(obj, err)
		}
	}
	if requests.Load() != 2 {
		t.Fatal("valid empty PUT was not sent once")
	}
}

func TestPutIfAbsentHasTypedConflictAndNeverReplays(t *testing.T) {
	for _, status := range []int{200, 412, 409, 403, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "PUT" || r.Header.Get("If-None-Match") != "*" || !strings.Contains(r.Header.Get("Authorization"), ";if-none-match;") {
					t.Error("condition absent or unsigned")
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("X-Amz-Version-Id", "created-version")
				w.WriteHeader(status)
			})
			obj, err := c.PutIfAbsent(context.Background(), "marker", strings.NewReader("id"), 2)
			switch status {
			case 200:
				if err != nil || obj.Size != 2 || obj.VersionID != "created-version" {
					t.Fatal(obj, err)
				}
			case 412:
				var e *Error
				if !errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrFailure) || errors.Is(err, ErrNotFound) || !errors.As(err, &e) || !e.AlreadyExists {
					t.Fatal("untyped existing object", err)
				}
			default:
				if !errors.Is(err, ErrFailure) || errors.Is(err, ErrAlreadyExists) {
					t.Fatal("wrong conflict classification", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("conditional body replayed")
			}
		})
	}
}

func TestProviderModificationTime(t *testing.T) {
	modified := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("versions") {
			io.WriteString(w, `<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>key</Key><VersionId>v</VersionId><Size>3</Size><ETag>&quot;opaque+/%=tag&quot;</ETag><LastModified>2026-11-23T12:00:00Z</LastModified></Version><DeleteMarker><Key>marker</Key><VersionId>m</VersionId><LastModified>2026-11-23T12:00:00Z</LastModified></DeleteMarker></ListVersionsResult>`)
		} else if r.URL.Query().Get("list-type") == "2" {
			io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>key</Key><Size>3</Size><ETag>&quot;opaque+/%=tag&quot;</ETag><LastModified>2026-11-23T12:00:00Z</LastModified></Contents></ListBucketResult>`)
		} else {
			w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
			w.Header().Set("ETag", `"opaque+/%=tag"`)
			w.Header().Set("Content-Length", "3")
			if r.Method != "HEAD" {
				io.WriteString(w, "abc")
			}
		}
	})
	ctx := context.Background()
	body, get, err := c.Get(ctx, "key", "")
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	head, err := c.Head(ctx, "key", "")
	if err != nil {
		t.Fatal(err)
	}
	objects, err := c.ListObjects(ctx, "", "")
	if err != nil || len(objects.Objects) != 1 {
		t.Fatal(objects, err)
	}
	versions, err := c.ListObjectVersions(ctx, "", VersionCursor{})
	if err != nil || len(versions.Objects) != 2 {
		t.Fatal(versions, err)
	}
	for _, obj := range []Object{get, head, objects.Objects[0], versions.Objects[0], versions.Objects[1]} {
		if !obj.LastModified.Equal(modified) {
			t.Fatal("provider age lost", obj)
		}
		if !obj.DeleteMarker && obj.ETag != `"opaque+/%=tag"` {
			t.Fatal("opaque provider tag lost", obj)
		}
	}
}

func TestInvalidModificationTimeFailsClosed(t *testing.T) {
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "bad-secret-timestamp")
		w.Header().Set("Content-Length", "0")
	})
	if _, err := c.Head(context.Background(), "key", ""); !errors.Is(err, ErrFailure) || strings.Contains(err.Error(), "bad-secret-timestamp") {
		t.Fatal(err)
	}
}

func TestPutIfAbsentRefusesNonemptyZeroLength(t *testing.T) {
	c, _ := tlsClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid empty marker reached S3") })
	if _, err := c.PutIfAbsent(context.Background(), "store-id", strings.NewReader("retained-id"), 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid conditional zero-length body accepted", err)
	}
}

func TestPutIfMatchPreservesOpaqueTagAndNeverReplays(t *testing.T) {
	const tag = `"opaque+/%=tag"`
	for _, status := range []int{200, 412, 404, 409, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var requests atomic.Int32
			c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("If-Match") != tag || !strings.Contains(r.Header.Get("Authorization"), ";if-match;") {
					t.Error("condition changed or unsigned")
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("ETag", `"next"`)
				w.Header().Set("X-Amz-Version-Id", "next-version")
				w.WriteHeader(status)
			})
			for _, invalid := range []string{"", "*", `W/"weak"`, "unquoted", `"one", "two"`, "\"bad\nheader\"", `"bad space"`} {
				if _, err := c.PutIfMatch(context.Background(), "key", invalid, strings.NewReader("x"), 1); !errors.Is(err, ErrInvalid) {
					t.Fatal("invalid tag accepted", err)
				}
			}
			if requests.Load() != 0 {
				t.Fatal("invalid tag reached S3")
			}
			obj, err := c.PutIfMatch(context.Background(), "key", tag, strings.NewReader("x"), 1)
			switch status {
			case 200:
				if err != nil || obj.ETag != `"next"` || obj.VersionID != "next-version" {
					t.Fatal(obj, err)
				}
			case 412:
				var e *Error
				if !errors.Is(err, ErrPrecondition) || errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrFailure) || !errors.As(err, &e) || !e.Precondition {
					t.Fatal("untyped precondition", err)
				}
			default:
				if !errors.Is(err, ErrFailure) || errors.Is(err, ErrPrecondition) {
					t.Fatal("wrong conditional failure", err)
				}
			}
			if requests.Load() != 1 {
				t.Fatal("conditional write retried or fell back")
			}
		})
	}
}

func TestMalformedProviderTagFailsWithoutEcho(t *testing.T) {
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "bad-secret-tag")
		w.Header().Set("Content-Length", "0")
	})
	if _, err := c.Head(context.Background(), "key", ""); !errors.Is(err, ErrFailure) || strings.Contains(err.Error(), "bad-secret-tag") {
		t.Fatal(err)
	}
}
