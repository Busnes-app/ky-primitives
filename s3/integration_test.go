package s3

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// The optional fixture is an isolated loopback S3 server. A verified TLS proxy preserves
// Host/path/query, so the server independently verifies the signature the public client sent.
func TestS3VersionedIntegration(t *testing.T) {
	endpoint := os.Getenv("KY_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set KY_TEST_S3_* for the disposable versioned S3 fixture")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("integration fixture must be loopback HTTP, never a live store")
	}
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(u))
	defer proxy.Close()
	cfg := Config{Endpoint: proxy.URL, Bucket: os.Getenv("KY_TEST_S3_BUCKET") + "-" + strings.ToLower(rand.Text()), Region: "us-east-1", AccessKey: os.Getenv("KY_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KY_TEST_S3_SECRET_KEY"), HTTP: proxy.Client()}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	setup := func(q url.Values, body string) {
		t.Helper()
		req, err := c.request(ctx, "PUT", "", q, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.do(req, false, false)
		if err != nil {
			t.Fatal("fixture setup", err)
		}
		resp.Body.Close()
	}
	setup(nil, "")
	setup(url.Values{"versioning": {""}}, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	prefix := "ky-client-tests/" + rand.Text() + "/"
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := c.DeletePrefix(ctx, prefix); err != nil {
			t.Error("fixture cleanup", err)
		}
	}()
	key := prefix + "file +%é.txt"
	first, err := c.Put(ctx, key, strings.NewReader("first"), 5)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Put(ctx, key, strings.NewReader("second"), 6)
	if err != nil {
		t.Fatal(err)
	}
	if first.VersionID == "" || second.VersionID == "" || first.VersionID == second.VersionID {
		t.Fatal("fixture does not retain distinct versions")
	}
	body, obj, err := c.Get(ctx, key, first.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(body)
	body.Close()
	if err != nil || string(raw) != "first" || obj.Size != 5 {
		t.Fatal("version read", obj, err)
	}
	if obj, err = c.Head(ctx, key, second.VersionID); err != nil || obj.Size != 6 || obj.VersionID != second.VersionID {
		t.Fatal("HEAD", obj, err)
	}
	marker, err := c.Delete(ctx, key, "")
	if err != nil || !marker.DeleteMarker || marker.VersionID == "" {
		t.Fatal("current delete", marker, err)
	}
	if _, err = c.Head(ctx, key, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete marker did not hide current", err)
	}
	versions, err := c.ListObjectVersions(ctx, key, VersionCursor{})
	if err != nil || len(versions.Objects) != 3 {
		t.Fatal("retained versions/marker", versions, err)
	}
	if _, err = c.Delete(ctx, key, second.VersionID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Head(ctx, key, second.VersionID); !errors.Is(err, ErrNotFound) {
		t.Fatal("exact version survived", err)
	}
	if err = c.DeleteAllVersions(ctx, key); err != nil {
		t.Fatal(err)
	}
	// Real pagination across more than S3's maximum 1,000 entries in one response.
	paged := prefix + "pages"
	for range 1001 {
		if _, err = c.Put(ctx, paged, strings.NewReader("x"), 1); err != nil {
			t.Fatal(err)
		}
	}
	var cursor VersionCursor
	count, pages := 0, 0
	for {
		p, err := c.ListObjectVersions(ctx, paged, cursor)
		if err != nil {
			t.Fatal(err)
		}
		count += len(p.Objects)
		pages++
		if p.Next == (VersionCursor{}) {
			break
		}
		if pages > 3 {
			t.Fatal("pagination did not finish")
		}
		cursor = p.Next
	}
	if count != 1001 || pages != 2 {
		t.Fatalf("version pages: %d entries in %d pages", count, pages)
	}
	objects, err := c.ListObjects(ctx, prefix, "")
	if err != nil || len(objects.Objects) != 1 || objects.Objects[0].Key != paged {
		t.Fatal(objects, err)
	}
	// A server that checks real signatures must refuse the wrong secret.
	cfg.SecretKey = "wrong-secret-not-the-fixture-secret"
	wrong, _ := New(cfg)
	if _, err = wrong.Head(ctx, paged, ""); !errors.Is(err, ErrFailure) || errors.Is(err, ErrNotFound) {
		t.Fatal("wrong secret accepted", err)
	}
	if err = c.DeletePrefix(ctx, prefix); err != nil {
		t.Fatal(err)
	}
	versions, err = c.ListObjectVersions(ctx, prefix, VersionCursor{})
	if err != nil || len(versions.Objects) != 0 {
		t.Fatal("prefix versions survived", versions, err)
	}
}
