package syncauth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestMiddlewareReleasesFailedEventsAndAcksDuplicates(t *testing.T) {
	body := []byte(`{"user":{"id":"u1"}}`)
	status := http.StatusServiceUnavailable
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if status == 0 {
			panic("handler blew up")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
	})
	var rejected []error
	srv := Middleware(func(*http.Request) ([]byte, error) { return key, nil },
		Options{Replay: NewMemoryReplay(time.Minute, 1)}, 0,
		func(_ *http.Request, err error) { rejected = append(rejected, err) })(next)
	h, _ := Sign(key, time.Now(), "user.deprovisioned", "evt-1", body)
	send := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
		h.Apply(req)
		w := httptest.NewRecorder()
		func() {
			defer func() { _ = recover() }()
			srv.ServeHTTP(w, req)
		}()
		return w
	}

	// A failed delivery releases the ID, so the sender's retry reaches the handler.
	if w := send(); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("first delivery: %d", w.Code)
	}
	status = 0 // a panicking handler releases it too
	send()
	// The guard holds one ID; a released one must not still occupy the slot.
	status = http.StatusOK // writes nothing: net/http answers 200
	if w := send(); w.Code != http.StatusOK || calls != 3 {
		t.Fatalf("retry after failures: %d, handler calls %d", w.Code, calls)
	}
	// Once processed, a retry is acknowledged without running the handler again.
	w := send()
	if w.Code != http.StatusOK || calls != 3 || !strings.Contains(w.Body.String(), "duplicate_event") {
		t.Fatalf("duplicate: %d %s, handler calls %d", w.Code, w.Body.String(), calls)
	}
	if len(rejected) != 1 || !errors.Is(rejected[0], ErrReplay) {
		t.Fatalf("onReject: %v", rejected)
	}
}

func TestMemoryReplayForgetFreesTheSlot(t *testing.T) {
	// The forgotten ID is not at the head, so only removing it from the order frees its
	// slot; the head sweep would not.
	rp := NewMemoryReplay(time.Minute, 2).(Forgetter)
	now := time.Now()
	for _, id := range []string{"a", "b"} {
		if err := rp.Check(id, now); err != nil {
			t.Fatal(err)
		}
	}
	rp.Forget("b")
	rp.Forget("never-seen")
	if err := rp.Check("c", now); err != nil {
		t.Fatalf("forgotten ID still holds the slot: %v", err)
	}
	if err := rp.Check("a", now); !errors.Is(err, ErrReplay) {
		t.Fatalf("forget dropped another ID: %v", err)
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

func TestMiddlewareKeepsFlusherBehindAForgetter(t *testing.T) {
	body := []byte("x")
	flushed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if ok {
			f.Flush()
		}
		flushed = ok
	})
	srv := Middleware(func(*http.Request) ([]byte, error) { return key, nil }, Options{Replay: NewMemoryReplay(0, 0)}, 0, nil)(next)
	h, _ := Sign(key, time.Now(), "t", "evt-f", body)
	req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
	h.Apply(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !flushed || !w.Flushed || w.Code != http.StatusOK {
		t.Fatalf("flusher %v, recorder flushed %v, code %d", flushed, w.Flushed, w.Code)
	}
}

// plainWriter can neither flush nor unwrap, like an outer middleware's wrapper.
type plainWriter struct{ w http.ResponseWriter }

func (p plainWriter) Header() http.Header         { return p.w.Header() }
func (p plainWriter) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p plainWriter) WriteHeader(code int)        { p.w.WriteHeader(code) }

// A flush that did nothing must not count as a 200: the handler's later 503 still
// releases the ID.
func TestMiddlewareFailedFlushDoesNotCountAsSuccess(t *testing.T) {
	body := []byte("x")
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.(http.Flusher).Flush()
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mw := Middleware(func(*http.Request) ([]byte, error) { return key, nil }, Options{Replay: NewMemoryReplay(0, 0)}, 0, nil)(next)
	srv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mw.ServeHTTP(plainWriter{w}, r) })
	h, _ := Sign(key, time.Now(), "t", "evt-nf", body)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
		h.Apply(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("delivery %d: %d", i+1, w.Code)
		}
	}
	if calls != 2 {
		t.Fatalf("the retry of a failed event did not reach the handler: %d calls", calls)
	}
}

func TestMiddlewareReportsAFlushTheWriterCannotDo(t *testing.T) {
	var flushErr error
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flushErr = http.NewResponseController(w).Flush()
	})
	mw := Middleware(func(*http.Request) ([]byte, error) { return key, nil }, Options{Replay: NewMemoryReplay(0, 0)}, 0, nil)(next)
	h, _ := Sign(key, time.Now(), "t", "evt-fe", []byte("x"))
	req := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader([]byte("x")))
	h.Apply(req)
	mw.ServeHTTP(plainWriter{httptest.NewRecorder()}, req)
	if !errors.Is(flushErr, http.ErrNotSupported) {
		t.Fatalf("flush through the controller: %v, want http.ErrNotSupported", flushErr)
	}
}

func TestMiddlewareDoesNotAcknowledgeInFlightDelivery(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			body := []byte(`{"user":{"id":"u1"}}`)
			h, _ := Sign(key, time.Now(), "user.deprovisioned", "overlap", body)
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ev, _ := EventFromContext(r)
				if ev.ID != "overlap" {
					return
				}
				if calls.Add(1) == 1 {
					close(started)
					<-release
					switch outcome {
					case "failure":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "panic":
						panic("failed first delivery")
					}
				}
			})
			server := Middleware(func(*http.Request) ([]byte, error) { return key, nil },
				Options{Replay: NewMemoryReplay(0, 10)}, 0, nil)(next)
			send := func(headers Headers) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/sync", bytes.NewReader(body))
				headers.Apply(r)
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				return w
			}
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				send(h)
			}()
			<-started
			pending := send(h)
			forged := h
			forged.Signature = "v1=invalid"
			unauthorized := send(forged)
			other, _ := Sign(key, time.Now(), "user.created", "unrelated", body)
			unrelated := send(other)
			close(release)
			<-done
			if pending.Code != http.StatusServiceUnavailable || pending.Header().Get("Retry-After") == "" {
				t.Fatalf("in-flight retry acknowledged: %d %s", pending.Code, pending.Body.String())
			}
			if unauthorized.Code != http.StatusUnauthorized || unrelated.Code != http.StatusOK {
				t.Fatalf("forged=%d unrelated=%d", unauthorized.Code, unrelated.Code)
			}
			if w := send(h); w.Code != http.StatusOK {
				t.Fatalf("retry after completion: %d", w.Code)
			}
			want := int32(2)
			if outcome == "success" {
				want = 1
			}
			if w := send(h); w.Code != http.StatusOK || calls.Load() != want || !strings.Contains(w.Body.String(), "duplicate_event") {
				t.Fatalf("completed duplicate=%d calls=%d, want%d", w.Code, calls.Load(), want)
			}
		})
	}
}

func TestMemoryReplayCoversVerifierClockAndWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"wider_window", time.Now().Add(-8 * time.Minute).Truncate(time.Second)},
		{"verifier_clock", time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("signed")
			h, _ := Sign(key, tc.at, "user.updated", "clock-window", body)
			now := tc.at.Add(8 * time.Minute)
			opts := Options{Window: 15 * time.Minute, Now: func() time.Time { return now }, Replay: NewMemoryReplay(5*time.Minute, 2)}
			if _, err := Verify(key, h, body, opts); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(key, h, body, opts); !errors.Is(err, ErrReplay) {
				t.Fatalf("accepted replay still inside verifier window: %v", err)
			}
		})
	}
}

func TestMemoryReplayRetainsInclusiveExpiryAndReclaimsCapacity(t *testing.T) {
	body := []byte("signed")
	at := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	now := at
	window := 10 * time.Minute
	reads := 0
	opts := Options{Window: window, Replay: NewMemoryReplay(time.Minute, 2), Now: func() time.Time {
		reads++
		return now
	}}
	verify := func(id string, stamp time.Time) error {
		t.Helper()
		h, err := Sign(key, stamp, "user.updated", id, body)
		if err != nil {
			t.Fatal(err)
		}
		before := reads
		_, err = Verify(key, h, body, opts)
		if reads-before != 1 {
			t.Fatalf("verification sampled its clock%d times", reads-before)
		}
		return err
	}
	if err := verify("future", at.Add(window)); err != nil {
		t.Fatal(err)
	}
	if err := verify("old", at.Add(-window)); err != nil {
		t.Fatal(err)
	}
	now = at.Add(time.Nanosecond)
	if err := verify("new", at); err != nil {
		t.Fatalf("expired non-head ID did not release capacity: %v", err)
	}
	now = at.Add(2 * window)
	if err := verify("future", at.Add(window)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay at last accepted instant: %v", err)
	}
	now = now.Add(time.Nanosecond)
	if err := verify("future", at.Add(window)); !errors.Is(err, ErrStale) {
		t.Fatalf("event after acceptance window: %v", err)
	}
}

func TestMemoryReplayCannotReinsertAfterConcurrentExpiry(t *testing.T) {
	body := []byte("signed")
	at := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	window := time.Minute
	expiry := at.Add(window)
	rp := NewMemoryReplay(window, 1).(*memoryReplay)
	h, _ := Sign(key, at, "user.updated", "original", body)
	if _, err := Verify(key, h, body, Options{Window: window, Replay: rp, Now: func() time.Time { return at }}); err != nil {
		t.Fatal(err)
	}
	fresh, _ := Sign(key, expiry, "user.updated", "fresh", body)
	done := make(chan error, 1)
	clock := func() time.Time {
		// Schedule a fresh delivery after expiry between an unprotected clock
		// sample and admission. Protected sampling makes it wait until this
		// replay has been rejected. TryLock avoids sleeps or a scheduler race.
		unprotected := rp.mu.TryLock()
		if unprotected {
			rp.mu.Unlock()
		}
		go func() {
			_, err := Verify(key, fresh, body, Options{Window: window, Replay: rp, Now: func() time.Time { return expiry.Add(time.Nanosecond) }})
			if err == nil {
				// A failed fresh handler releases its one slot before the paused
				// replay resumes, rather than merely masking it with a full guard.
				rp.Forget("fresh")
			}
			done <- err
		}()
		if unprotected {
			if err := <-done; err != nil {
				done <- err
				return expiry.Add(-time.Nanosecond)
			}
			done <- nil
		}
		return expiry.Add(-time.Nanosecond)
	}
	_, replayErr := Verify(key, h, body, Options{Window: window, Replay: rp, Now: clock})
	if err := <-done; err != nil {
		t.Fatalf("fresh concurrent delivery: %v", err)
	}
	if !errors.Is(replayErr, ErrReplay) {
		t.Fatalf("paused replay reinserted after expiry/eviction: %v", replayErr)
	}
}
