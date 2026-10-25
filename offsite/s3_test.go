package offsite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestS3PutGetAndMissing(t *testing.T) {
	objects := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), " SignedHeaders=host;x-amz-content-sha256;x-amz-date, ") {
			http.Error(w, "signed headers changed", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			if r.ContentLength != int64(len("payload")) && r.ContentLength != int64(len("ping")) {
				http.Error(w, "content length", http.StatusLengthRequired)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			objects[r.URL.Path] = string(raw)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if r.Header.Get("x-amz-content-sha256") != "UNSIGNED-PAYLOAD" {
				http.Error(w, "GET payload was not unsigned", http.StatusUnauthorized)
				return
			}
			value, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, value)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	target, err := Parse(Config{URL: "s3://bucket/prefix", S3Endpoint: server.URL, S3Region: "auto", AccessKey: "key", Secret: "secret", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s3 := target.(*s3Target)
	s3.now = func() time.Time { return time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC) }
	if err := target.Put(context.Background(), "folder/object", strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	r, err := target.Get(context.Background(), "folder/object")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(raw) != "payload" {
		t.Fatalf("Get = %q, %v", raw, err)
	}
	if _, err := target.Get(context.Background(), "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing error = %v", err)
	}
	if err := target.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if objects["/bucket/prefix/"+pingName] != "ping" {
		t.Fatalf("probe objects = %#v", objects)
	}
}

func TestS3UsesVirtualHostedAWSURL(t *testing.T) {
	target, err := Parse(Config{URL: "s3://my-bucket/a b", AccessKey: "key", Secret: "secret", S3Region: "us-west-2"})
	if err != nil {
		t.Fatal(err)
	}
	u := target.(*s3Target).objectURL("object")
	if got, want := u.String(), "https://my-bucket.s3.us-west-2.amazonaws.com/a%20b/object"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestS3ErrorBodyIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("x", 20000))
	}))
	defer server.Close()
	target, err := Parse(Config{URL: "s3://bucket", S3Endpoint: server.URL, AccessKey: "key", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	err = target.Put(context.Background(), "object", strings.NewReader("x"), 1)
	if err == nil || len(err.Error()) > 8300 {
		t.Fatalf("error length = %d", len(err.Error()))
	}
}

func TestS3RefusesRedirect(t *testing.T) {
	followed := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed = true
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	target, err := Parse(Config{URL: "s3://bucket", S3Endpoint: redirect.URL, AccessKey: "key", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Put(context.Background(), "object", strings.NewReader("x"), 1); err == nil {
		t.Fatal("redirect was accepted")
	}
	if followed {
		t.Fatal("S3 request followed a redirect and exposed its authorization header")
	}
}

// Authorization headers produced by the hand-written SigV4 signer this replaced, for
// path-style, virtual-hosted, base-path and unusual object keys. Any change here makes
// every configured destination refuse uploads.
func TestS3SignatureMatchesPreviousSigner(t *testing.T) {
	const scope = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/"
	const signed = "/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
	const putHash = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	for _, c := range []struct {
		url, endpoint, region, method, name, hash, wantURL, wantAuth string
	}{
		{"s3://bucket/prefix", "http://127.0.0.1:9000", "auto", http.MethodPut, "folder/object", putHash,
			"http://127.0.0.1:9000/bucket/prefix/folder/object",
			scope + "auto" + signed + "91df9e03f7ef00269d0d948778bb7282c20e7984e534e636a2c222a1938082bb"},
		{"s3://bucket/prefix", "http://127.0.0.1:9000", "auto", http.MethodGet, "folder/object", "UNSIGNED-PAYLOAD",
			"http://127.0.0.1:9000/bucket/prefix/folder/object",
			scope + "auto" + signed + "1016159adb988376a50b109fcfb2dacccb2decb428c9a92992b0bde793f83334"},
		{"s3://my-bucket/a b", "", "us-west-2", http.MethodGet, "ü+~=;@$&,.kycap", "UNSIGNED-PAYLOAD",
			"https://my-bucket.s3.us-west-2.amazonaws.com/a%20b/%C3%BC+~=;@$&,.kycap",
			scope + "us-west-2" + signed + "3ca153294cc15923d9c2abb9a5957c8b9e3776b5280ba05f614f4cd9b635f873"},
		{"s3://my-bucket", "", "", http.MethodPut, "object", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"https://my-bucket.s3.us-east-1.amazonaws.com/object",
			scope + "us-east-1" + signed + "60280cd96c764aeb9891a680d60c8e2000486a18b6665d6c56a965f6a090e9e7"},
		{"s3://backups/kyrecovery", "https://acct.r2.cloudflarestorage.com/base/", "auto", http.MethodPut, "kycap-v1-x.kycap", putHash,
			"https://acct.r2.cloudflarestorage.com/base/backups/kyrecovery/kycap-v1-x.kycap",
			scope + "auto" + signed + "ba97975ca9f122fad4b8417835e69887c50bd9111672fe4abfee7fa7b0511ff3"},
	} {
		target, err := Parse(Config{URL: c.url, S3Endpoint: c.endpoint, S3Region: c.region, AccessKey: "AKIAIOSFODNN7EXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
		if err != nil {
			t.Fatal(err)
		}
		s3 := target.(*s3Target)
		s3.now = func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }
		req, err := s3.request(context.Background(), c.method, c.name, c.hash)
		if err != nil {
			t.Fatal(err)
		}
		if req.URL.String() != c.wantURL {
			t.Errorf("%s %s: URL %q, want %q", c.method, c.name, req.URL, c.wantURL)
		}
		if got := req.Header.Get("Authorization"); got != c.wantAuth {
			t.Errorf("%s %s:\n got %s\nwant %s", c.method, req.URL, got, c.wantAuth)
		}
		if req.Header.Get("x-amz-date") != "20130524T000000Z" || req.Header.Get("x-amz-content-sha256") != c.hash {
			t.Errorf("%s %s: headers %v", c.method, req.URL, req.Header)
		}
	}
}

// The SDK signer caches derived keys by access key ID. Two targets sharing a key ID must
// still each sign with their own secret.
func TestS3TargetsDoNotShareSigningKeys(t *testing.T) {
	auth := func(secret string) string {
		target, err := Parse(Config{URL: "s3://bucket", S3Endpoint: "https://s3.example", AccessKey: "key", Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		req, err := target.(*s3Target).request(context.Background(), http.MethodGet, "object", "UNSIGNED-PAYLOAD")
		if err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Authorization")
	}
	if auth("first") == auth("second") {
		t.Fatal("a second target signed with the first target's secret")
	}
}
