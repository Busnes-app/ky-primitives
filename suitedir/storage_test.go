package suitedir

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const storageOrg = "11111111-1111-4111-8111-111111111111"

func storageRequest() []StorageReport {
	return []StorageReport{{OrgID: storageOrg, UsedBytes: 100, Seq: 5, WantBytes: 200}}
}

const storageOK = `{"results":[{"org_id":"11111111-1111-4111-8111-111111111111","result":"ok","seq":5,"ceiling_bytes":300,"ttl_seconds":900,"pool_bytes":1000,"org_used_bytes":100,"over_since":null}]}`

func storageClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return &Client{Issuer: s.URL, ClientID: "calendar", ClientSecret: "storage-test-only", HTTP: s.Client()}
}
func TestStorageReport(t *testing.T) {
	c := storageClient(t, func(w http.ResponseWriter, r *http.Request) {
		id, key, ok := r.BasicAuth()
		if !ok || id != "calendar" || key != "storage-test-only" {
			t.Error("wrong client auth")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/suite/storage" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong request")
		}
		var body struct {
			Reports []StorageReport `json:"reports"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Reports) != 1 || body.Reports[0] != storageRequest()[0] {
			t.Error("wrong report body")
		}
		w.Write([]byte(storageOK))
	})
	got, err := c.ReportStorage(context.Background(), storageRequest())
	if err != nil || len(got) != 1 || got[0].Seq != 5 || got[0].CeilingBytes != 300 {
		t.Fatalf("result: %+v %v", got, err)
	}
}
func TestStorageRejectsInvalidReportsBeforeRequest(t *testing.T) {
	var calls atomic.Int32
	c := storageClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(storageOK)) })
	for _, change := range []func([]StorageReport) []StorageReport{
		func(r []StorageReport) []StorageReport { return nil },
		func(r []StorageReport) []StorageReport { return append(r, r[0]) },
		func(r []StorageReport) []StorageReport { r[0].OrgID = "bad"; return r },
		func(r []StorageReport) []StorageReport { r[0].Seq = 0; return r },
		func(r []StorageReport) []StorageReport { r[0].UsedBytes = -1; return r },
		func(r []StorageReport) []StorageReport { r[0].WantBytes = 1<<53 + 1; return r },
	} {
		if _, err := c.ReportStorage(context.Background(), change(storageRequest())); !errors.Is(err, ErrStorageRequest) {
			t.Fatalf("invalid report: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("sent invalid reports")
	}
}
func TestStorageRejectsMalformedWholeAnswer(t *testing.T) {
	for name, body := range map[string]string{
		"missing list": `{}`, "null list": `{"results":null}`, "empty list": `{"results":[]}`,
		"missing figure":   strings.Replace(storageOK, `"ceiling_bytes":300,`, "", 1),
		"null figure":      strings.Replace(storageOK, `"ceiling_bytes":300`, `"ceiling_bytes":null`, 1),
		"extra org":        strings.Replace(storageOK, storageOrg, "22222222-2222-4222-8222-222222222222", 1),
		"wrong seq":        strings.Replace(storageOK, `"seq":5`, `"seq":6`, 1),
		"negative ceiling": strings.Replace(storageOK, `"ceiling_bytes":300`, `"ceiling_bytes":-1`, 1),
		"below usage":      strings.Replace(storageOK, `"ceiling_bytes":300`, `"ceiling_bytes":99`, 1),
		"above request":    strings.Replace(storageOK, `"ceiling_bytes":300`, `"ceiling_bytes":301`, 1),
		"long ttl":         strings.Replace(storageOK, `"ttl_seconds":900`, `"ttl_seconds":901`, 1),
		"bad result":       strings.Replace(storageOK, `"ok"`, `"fine"`, 1),
		"unknown grant":    strings.Replace(storageOK, `"ok"`, `"unknown_org"`, 1),
		"stale lower seq":  strings.Replace(strings.Replace(storageOK, `"ok"`, `"stale"`, 1), `"seq":5`, `"seq":4`, 1),
		"bad over since":   strings.Replace(storageOK, `"over_since":null`, `"over_since":0`, 1),
		"trailing data":    storageOK + `{}`, "huge body": strings.Repeat(" ", maxBody+1),
	} {
		t.Run(name, func(t *testing.T) {
			c := storageClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			got, err := c.ReportStorage(context.Background(), storageRequest())
			if err == nil || got != nil {
				t.Fatalf("accepted malformed answer: %+v %v", got, err)
			}
		})
	}
}
func TestStorageStaleAndUnknown(t *testing.T) {
	for _, body := range []string{strings.Replace(strings.Replace(storageOK, `"ok"`, `"stale"`, 1), `"seq":5`, `"seq":40`, 1), `{"results":[{"org_id":"` + storageOrg + `","result":"unknown_org"}]}`} {
		c := storageClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
		got, err := c.ReportStorage(context.Background(), storageRequest())
		if err != nil || len(got) != 1 {
			t.Fatalf("result: %+v %v", got, err)
		}
	}
}
func TestStorageDoesNotFollowRedirects(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	c := storageClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	c.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	if _, err := c.ReportStorage(context.Background(), storageRequest()); err == nil {
		t.Fatal("followed redirect")
	}
	if calls.Load() != 0 {
		t.Fatal("redirected authenticated request")
	}
	c.Issuer = "https://user:secret@example.com"
	if _, err := c.ReportStorage(context.Background(), storageRequest()); !errors.Is(err, ErrInsecureIssuer) {
		t.Fatalf("userinfo: %v", err)
	}
}
