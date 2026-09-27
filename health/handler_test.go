package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/logging"
)

func testLogger(t *testing.T) (*logging.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	lg, err := logging.New(logging.Config{App: "kytest", Out: &buf})
	if err != nil {
		t.Fatal(err)
	}
	return lg, &buf
}

var t0 = time.Date(2026, 9, 26, 10, 41, 0, 500_000_000, time.UTC)

func serve(h http.Handler, method string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/healthz", nil))
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, rec.Body.String())
	}
	return resp
}

func TestHandlerServesTheContract(t *testing.T) {
	lg, _ := testLogger(t)
	h := newHandler("kyvault", lg, func() time.Time { return t0 }, []Check{
		{Name: "database", Run: ok},
		{Name: "audit", Run: func(context.Context) error { return Degrade(appendDisabled) }},
	})
	rec := serve(h, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	for k, want := range map[string]string{
		"Content-Type":           "application/json",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	want := `{"schema":"ky.health/1","service":"kyvault","status":"degraded","time":"2026-09-26T10:41:00Z","checks":[{"name":"database","status":"ok"},{"name":"audit","status":"degraded","reason":"append_disabled"}]}`
	if got := rec.Body.String(); got != want {
		t.Fatalf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestNoChecksIsOKWithAnEmptyList(t *testing.T) {
	lg, _ := testLogger(t)
	rec := serve(newHandler("kynotes", lg, func() time.Time { return t0 }, nil), http.MethodGet)
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) || !strings.Contains(rec.Body.String(), `"checks":[]`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestDownIs503(t *testing.T) {
	lg, _ := testLogger(t)
	h := newHandler("kyvault", lg, func() time.Time { return t0 }, []Check{
		{Name: "database", Run: func(context.Context) error { return errors.New("refused") }},
	})
	rec := serve(h, http.MethodGet)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d", rec.Code)
	}
	if decode(t, rec).Status != Down {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestErrorTextNeverReachesTheResponse(t *testing.T) {
	lg, logs := testLogger(t)
	secret := "postgres://pulse:hunter2@db.internal:5432/kyvault"
	h := newHandler("kyvault", lg, func() time.Time { return t0 }, []Check{
		{Name: "database", Run: func(context.Context) error { return errors.New("connect " + secret + ": refused") }},
	})
	rec := serve(h, http.MethodGet)
	for _, leak := range []string{"hunter2", "db.internal", "refused", "postgres"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("response leaks %q: %s", leak, rec.Body.String())
		}
	}
	// The response is the guarantee; the stderr line follows logging.Err's limit, which
	// drops wrapper text but keeps a leaf's text. The operator still gets a line saying
	// which check failed.
	var line map[string]any
	if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
		t.Fatalf("log is not one JSON line: %v\n%s", err, logs.String())
	}
	if line["event"] != "health_check_failed" || line["health_check"] != "database" {
		t.Fatalf("log line = %v", line)
	}
}

func TestHeadHasStatusAndNoBody(t *testing.T) {
	lg, _ := testLogger(t)
	h := newHandler("kyvault", lg, func() time.Time { return t0 }, []Check{
		{Name: "database", Run: func(context.Context) error { return errors.New("x") }},
	})
	rec := serve(h, http.MethodHead)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.Len() != 0 {
		t.Fatalf("code = %d, body = %q", rec.Code, rec.Body.String())
	}
}

func TestOtherMethodsAre405(t *testing.T) {
	lg, _ := testLogger(t)
	rec := serve(newHandler("kyvault", lg, time.Now, nil), http.MethodPost)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("code = %d, Allow = %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestOneEvaluationAnswersRequestsWithinCacheFor(t *testing.T) {
	lg, _ := testLogger(t)
	var runs atomic.Int32
	now := t0
	h := newHandler("kyvault", lg, func() time.Time { return now }, []Check{
		{Name: "database", Run: func(context.Context) error { runs.Add(1); return nil }},
	})
	serve(h, http.MethodGet)
	now = t0.Add(CacheFor - time.Millisecond)
	serve(h, http.MethodGet)
	if n := runs.Load(); n != 1 {
		t.Fatalf("ran %d times inside CacheFor, want 1", n)
	}
	now = t0.Add(CacheFor)
	serve(h, http.MethodGet)
	if n := runs.Load(); n != 2 {
		t.Fatalf("ran %d times after CacheFor, want 2", n)
	}
}

func TestConcurrentRequestsShareOneEvaluation(t *testing.T) {
	lg, _ := testLogger(t)
	var runs atomic.Int32
	h := Handler("kyvault", lg, Check{Name: "database", Run: func(context.Context) error {
		runs.Add(1)
		time.Sleep(20 * time.Millisecond)
		return nil
	}})
	done := make(chan struct{})
	for range 20 {
		go func() { serve(h, http.MethodGet); done <- struct{}{} }()
	}
	for range 20 {
		<-done
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("20 concurrent requests ran the check %d times, want 1", n)
	}
}

func TestClientHangupDoesNotCancelChecks(t *testing.T) {
	lg, _ := testLogger(t)
	h := newHandler("kyvault", lg, func() time.Time { return t0 }, []Check{
		{Name: "database", Run: func(ctx context.Context) error { time.Sleep(10 * time.Millisecond); return ctx.Err() }},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil).WithContext(ctx))
	if decode(t, rec).Status != OK {
		t.Fatalf("a cancelled request context reached the check: %s", rec.Body.String())
	}
}

func TestHandlerRejectsBadConstruction(t *testing.T) {
	lg, _ := testLogger(t)
	cases := map[string]func(){
		"bad service":     func() { Handler("ky vault", lg) },
		"empty service":   func() { Handler("", lg) },
		"nil logger":      func() { Handler("kyvault", nil) },
		"bad check name":  func() { Handler("kyvault", lg, Check{Name: "Database", Run: ok}) },
		"duplicate check": func() { Handler("kyvault", lg, Check{Name: "db", Run: ok}, Check{Name: "db", Run: ok}) },
		"nil run":         func() { Handler("kyvault", lg, Check{Name: "db"}) },
		"timeout over max": func() {
			Handler("kyvault", lg, Check{Name: "db", Timeout: MaxTimeout + time.Millisecond, Run: ok})
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("did not panic")
				}
			}()
			f()
		})
	}
}
