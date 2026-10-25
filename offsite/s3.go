package offsite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type s3Target struct {
	bucket, prefix, region, accessKey, secret string
	endpoint                                  *url.URL
	timeout                                   time.Duration
	client                                    *http.Client
	now                                       func() time.Time
	// One per target: the signer caches derived keys by access key ID, not secret.
	signer *v4.Signer
}

func newS3Target(bucket, prefix string, c Config) (*s3Target, error) {
	region := c.S3Region
	if region == "" {
		region = "us-east-1"
	}
	var endpoint *url.URL
	if c.S3Endpoint != "" {
		var err error
		endpoint, err = url.Parse(c.S3Endpoint)
		if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, errors.New("offsite: S3Endpoint must be an HTTP(S) URL without userinfo, query, or fragment")
		}
	}
	return &s3Target{
		bucket: bucket, prefix: prefix, region: region, accessKey: c.AccessKey,
		secret: c.Secret, endpoint: endpoint, timeout: c.Timeout,
		client: &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}}, now: time.Now,
		// S3 object keys are escaped once, never twice as other SigV4 services are.
		signer: v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }),
	}, nil
}

func (t *s3Target) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	var body io.Reader
	var size int64
	var payloadHash string
	if seeker, ok := r.(io.ReadSeeker); ok {
		start, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		h := sha256.New()
		size, err = io.Copy(h, &contextReader{ctx: ctx, r: seeker})
		if err != nil {
			return fmt.Errorf("offsite: hash S3 upload: %w", err)
		}
		if _, err := seeker.Seek(start, io.SeekStart); err != nil {
			return fmt.Errorf("offsite: rewind S3 upload: %w", err)
		}
		payloadHash, body = hex.EncodeToString(h.Sum(nil)), seeker
	} else {
		raw, err := io.ReadAll(&contextReader{ctx: ctx, r: r})
		if err != nil {
			return fmt.Errorf("offsite: read S3 upload: %w", err)
		}
		sum := sha256.Sum256(raw)
		payloadHash, size, body = hex.EncodeToString(sum[:]), int64(len(raw)), bytes.NewReader(raw)
	}
	req, err := t.request(ctx, http.MethodPut, name, payloadHash)
	if err != nil {
		return err
	}
	req.Body, req.ContentLength = io.NopCloser(body), size
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("offsite: S3 PUT: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return responseError("S3 PUT", resp)
	}
	return nil
}

func (t *s3Target) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := budget(ctx, t.timeout)
	req, err := t.request(ctx, http.MethodGet, name, "UNSIGNED-PAYLOAD")
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("offsite: S3 GET: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		cancel()
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		err := responseError("S3 GET", resp)
		resp.Body.Close()
		cancel()
		return nil, err
	}
	return &cancelReadCloser{ReadCloser: resp.Body, cancel: cancel}, nil
}

func (t *s3Target) Test(ctx context.Context) error {
	return t.Put(ctx, pingName, strings.NewReader("ping"), 4)
}

// request is signed without a body, so content-length stays out of the signature as it
// always has; Put attaches the body afterwards.
func (t *s3Target) request(ctx context.Context, method, name, payloadHash string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, t.objectURL(name).String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	creds := aws.Credentials{AccessKeyID: t.accessKey, SecretAccessKey: t.secret}
	if err := t.signer.SignHTTP(ctx, creds, req, payloadHash, "s3", t.region, t.now()); err != nil {
		return nil, fmt.Errorf("offsite: sign S3 request: %w", err)
	}
	return req, nil
}

func (t *s3Target) objectURL(name string) *url.URL {
	object := path.Join(t.prefix, name)
	if t.endpoint == nil {
		return &url.URL{Scheme: "https", Host: t.bucket + ".s3." + t.region + ".amazonaws.com", Path: "/" + object}
	}
	u := *t.endpoint
	u.Path = path.Join(u.Path, t.bucket, object)
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	return &u
}

func responseError(op string, resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return fmt.Errorf("offsite: %s returned HTTP %d: %s", op, resp.StatusCode, strings.TrimSpace(string(raw)))
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
