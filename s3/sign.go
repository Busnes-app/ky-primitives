package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// SigV4 follows the existing offsite S3 signer design; canonical query encoding and exact
// S3 paths are shared by all operations. Only PUT's streaming body uses UNSIGNED-PAYLOAD.
func (c *Client) sign(req *http.Request, now time.Time) {
	now = now.UTC()
	date, stamp := now.Format("20060102"), now.Format("20060102T150405Z")
	sum := sha256.Sum256(nil)
	payload := hex.EncodeToString(sum[:])
	if req.Method == http.MethodPut {
		payload = "UNSIGNED-PAYLOAD"
	}
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", payload)
	headers := "host:" + req.URL.Host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + stamp + "\n"
	const signed = "host;x-amz-content-sha256;x-amz-date"
	canonical := req.Method + "\n" + req.URL.EscapedPath() + "\n" + req.URL.RawQuery + "\n" + headers + "\n" + signed + "\n" + payload
	digest := sha256.Sum256([]byte(canonical))
	scope := date + "/" + c.region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	key := mac([]byte("AWS4"+c.secretKey), date)
	for _, s := range []string{c.region, "s3", "aws4_request"} {
		key = mac(key, s)
	}
	sig := hex.EncodeToString(mac(key, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}
func mac(key []byte, text string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(text))
	return h.Sum(nil)
}
