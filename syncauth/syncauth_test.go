package syncauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var key = bytes.Repeat([]byte{9}, 32)

func TestSignVerifyRoundTrip(t *testing.T) {
	body := []byte(`{"user":{"id":"u1"}}`)
	now := time.Date(2026, 9, 4, 23, 0, 0, 0, time.UTC)
	h, err := Sign(key, now, "user.deprovisioned", "evt-1", body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.Signature, "v1=") || h.Timestamp != "2026-09-04T23:00:00Z" {
		t.Fatalf("%+v", h)
	}
	ev, err := Verify(key, h, body, Options{Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil || ev.Type != "user.deprovisioned" || ev.ID != "evt-1" || !ev.At.Equal(now) {
		t.Fatalf("%v %+v", err, ev)
	}
}

func TestVerifyBindsEveryField(t *testing.T) {
	body := []byte(`{"a":1}`)
	now := time.Date(2026, 9, 4, 23, 0, 7, 0, time.UTC)
	h, _ := Sign(key, now, "user.created", "evt-1", body)
	cases := map[string]func(Headers, []byte) (Headers, []byte){
		"body":       func(h Headers, b []byte) (Headers, []byte) { return h, []byte(`{"a":2}`) },
		"event type": func(h Headers, b []byte) (Headers, []byte) { h.EventType = "user.deleted"; return h, b },
		"event id":   func(h Headers, b []byte) (Headers, []byte) { h.EventID = "evt-2"; return h, b },
		"timestamp": func(h Headers, b []byte) (Headers, []byte) {
			h.Timestamp = now.Add(time.Second).UTC().Format(time.RFC3339)
			return h, b
		},
		"signature bit": func(h Headers, b []byte) (Headers, []byte) {
			replacement := "0"
			if strings.HasSuffix(h.Signature, replacement) {
				replacement = "1"
			}
			h.Signature = h.Signature[:len(h.Signature)-1] + replacement
			return h, b
		},
		"other key": func(h Headers, b []byte) (Headers, []byte) {
			o, _ := Sign(bytes.Repeat([]byte{8}, 32), now, "user.created", "evt-1", b)
			return o, b
		},
	}
	for name, mutate := range cases {
		mh, mb := mutate(h, body)
		if _, err := Verify(key, mh, mb, Options{Now: func() time.Time { return now }}); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
}

func TestVerifyRefusesMissingStaleAndShort(t *testing.T) {
	body := []byte("x")
	now := time.Now()
	h, _ := Sign(key, now, "t", "id", body)
	if _, err := Verify(key, Headers{Timestamp: h.Timestamp, EventType: "t", EventID: "id"}, body, Options{}); !errors.Is(err, ErrNoSignature) {
		t.Errorf("no signature: %v", err)
	}
	bad := h
	bad.Timestamp = "yesterday"
	if _, err := Verify(key, bad, body, Options{}); !errors.Is(err, ErrBadTimestamp) {
		t.Errorf("bad timestamp: %v", err)
	}
	if _, err := Verify(key, h, body, Options{Now: func() time.Time { return now.Add(6 * time.Minute) }}); !errors.Is(err, ErrStale) {
		t.Errorf("stale: %v", err)
	}
	if _, err := Verify(key, h, body, Options{Now: func() time.Time { return now.Add(-6 * time.Minute) }}); !errors.Is(err, ErrStale) {
		t.Errorf("future: %v", err)
	}
	if _, err := Verify(make([]byte, 8), h, body, Options{}); !errors.Is(err, ErrShortKey) {
		t.Errorf("short key: %v", err)
	}
	if _, err := Sign(key, now, "", "id", body); !errors.Is(err, ErrMissingFields) {
		t.Errorf("empty type signed: %v", err)
	}
	if _, err := Sign(key, now, "t\nx", "id", body); !errors.Is(err, ErrMissingFields) {
		t.Errorf("newline in type signed: %v", err)
	}
}

func TestReplayGuard(t *testing.T) {
	body := []byte("x")
	now := time.Now()
	h, _ := Sign(key, now, "t", "evt-1", body)
	rp := NewMemoryReplay(time.Minute, 2)
	o := Options{Replay: rp, Now: func() time.Time { return now }}
	if _, err := Verify(key, h, body, o); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(key, h, body, o); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
	// Full of IDs still inside the window: refuse rather than forget one.
	h2, _ := Sign(key, now, "t", "evt-2", body)
	if _, err := Verify(key, h2, body, o); err != nil {
		t.Fatal(err)
	}
	h3, _ := Sign(key, now, "t", "evt-3", body)
	if _, err := Verify(key, h3, body, o); !errors.Is(err, ErrReplayGuardFull) {
		t.Fatalf("full guard: %v", err)
	}
	if _, err := Verify(key, h, body, o); !errors.Is(err, ErrReplay) {
		t.Fatalf("a full guard forgot an ID inside the window: %v", err)
	}
	// Once entries leave the window they are forgotten and room returns.
	old := NewMemoryReplay(time.Millisecond, 1)
	if err := old.Check("a", now); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := old.Check("b", now); err != nil {
		t.Fatalf("expired entry not evicted: %v", err)
	}
}

func TestVerifyRefusesNewlinesInHeaders(t *testing.T) {
	body := []byte("x")
	now := time.Now()
	h, _ := Sign(key, now, "t", "id", body)
	h.EventType = "t\nx"
	if _, err := Verify(key, h, body, Options{Now: func() time.Time { return now }}); !errors.Is(err, ErrMissingFields) {
		t.Fatalf("%v", err)
	}
}

func TestMiddlewareVerifiesAndReplaysTheBodyToTheHandler(t *testing.T) {
	body := []byte(`{"users":[]}`)
	var got []byte
	var ev Event
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		ev, _ = EventFromContext(r)
		w.WriteHeader(http.StatusNoContent)
	})
	var rejected []error
	mw := Middleware(func(*http.Request) ([]byte, error) { return key, nil }, Options{}, 1024, func(_ *http.Request, err error) { rejected = append(rejected, err) })
	srv := mw(next)

	h, _ := Sign(key, time.Now(), "user.created", "evt-9", body)
	req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	h.Apply(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent || !bytes.Equal(got, body) || ev.ID != "evt-9" {
		t.Fatalf("%d %q %+v", w.Code, got, ev)
	}

	req = httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || len(rejected) != 1 || !errors.Is(rejected[0], ErrNoSignature) || !strings.Contains(w.Body.String(), "invalid_signature") {
		t.Fatalf("unsigned: %d %v %s", w.Code, rejected, w.Body.String())
	}

	big := bytes.Repeat([]byte("x"), 2048)
	hb, _ := Sign(key, time.Now(), "t", "evt-10", big)
	req = httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(big))
	hb.Apply(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || !errors.Is(rejected[len(rejected)-1], ErrBodyTooLarge) {
		t.Fatalf("oversized: %d %v", w.Code, rejected)
	}

	unconfigured := Middleware(func(*http.Request) ([]byte, error) { return nil, fmt.Errorf("not configured") }, Options{}, 0, nil)(next)
	req = httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	h.Apply(req)
	w = httptest.NewRecorder()
	unconfigured.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unconfigured receiver accepted: %d", w.Code)
	}
}

func FuzzVerify(f *testing.F) {
	body := []byte(`{"a":1}`)
	h, _ := Sign(key, time.Now(), "t", "id", body)
	f.Add(h.Signature, h.Timestamp, h.EventType, h.EventID, body)
	f.Fuzz(func(t *testing.T, sig, ts, et, id string, b []byte) {
		hh := Headers{Signature: sig, Timestamp: ts, EventType: et, EventID: id}
		_, err := Verify(key, hh, b, Options{})
		if err == nil {
			// Only the exact original tuple verifies.
			if sig != h.Signature || ts != h.Timestamp || et != "t" || id != "id" || !bytes.Equal(b, body) {
				t.Fatalf("forged tuple verified: %+v", hh)
			}
		}
	})
}
