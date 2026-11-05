// Package syncauth is the one definition of how KySignOn signs a directory-sync event and how
// a product verifies it. KySignOn calls Sign; every receiver installs Middleware. Before this
// package the sender signed timestamp+"."+body and at least one receiver verified body alone,
// so the two sides could not agree, and a receiver that accepts a forged deprovision cannot
// tell it from a real one.
//
// Scheme v1: HMAC-SHA256 over
//
//	"ky-sync-v1\n" + timestamp(RFC3339, UTC) + "\n" + eventType + "\n" + eventID + "\n" + hex(sha256(body))
//
// carried in X-KySignOn-Signature as "v1=" + hex(mac), with X-KySignOn-Timestamp,
// X-KySignOn-Event-Type and X-KySignOn-Event-ID alongside. The HMAC key is the sync secret
// and travels nowhere: no Authorization header carries it. Event type and ID are bound so a
// captured event cannot be replayed as a different type, and the ID is what the receiver's
// replay guard remembers.
package syncauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	HeaderSignature = "X-KySignOn-Signature"
	HeaderTimestamp = "X-KySignOn-Timestamp"
	HeaderEventType = "X-KySignOn-Event-Type"
	HeaderEventID   = "X-KySignOn-Event-ID"

	version = "v1"
	prefix  = "ky-sync-v1\n"

	// DefaultWindow is how far a timestamp may sit from the receiver's clock. Homelab clocks
	// drift; five minutes is the usual bound and the error names which side is off.
	DefaultWindow = 5 * time.Minute
	// DefaultMaxBody bounds what a receiver reads before verifying. A directory event with
	// a few thousand users fits in far less.
	DefaultMaxBody = 4 << 20
	// MinKeyBytes is the shortest sync secret accepted. KySignOn mints 32 random bytes.
	MinKeyBytes = 16
)

var (
	ErrNoSignature  = errors.New("syncauth: no signature")
	ErrBadSignature = errors.New("syncauth: signature does not match")
	ErrBadTimestamp = errors.New("syncauth: timestamp missing or not RFC3339")
	ErrStale        = errors.New("syncauth: timestamp outside the accepted window")
	ErrReplay       = errors.New("syncauth: event already seen")
	// ErrReplayGuardFull means the in-memory guard holds max IDs all still inside the window
	// and cannot admit another without forgetting one it must remember. The receiver logs
	// that the guard is undersized; a persistent Replay backed by its processed-events table
	// is the fix for sustained volume.
	ErrReplayGuardFull = errors.New("syncauth: replay guard is full of events still inside the window")
	ErrMissingFields   = errors.New("syncauth: event type and event id are required")
	ErrShortKey        = fmt.Errorf("syncauth: key must be at least %d bytes", MinKeyBytes)
	ErrBodyTooLarge    = errors.New("syncauth: body exceeds the limit")
)

// Event is what a verified request says about itself.
type Event struct {
	Type string
	ID   string
	At   time.Time
}

// Headers are the four headers a signed request carries.
type Headers struct {
	Signature string
	Timestamp string
	EventType string
	EventID   string
}

// Apply sets the headers on a request.
func (h Headers) Apply(r *http.Request) {
	r.Header.Set(HeaderSignature, h.Signature)
	r.Header.Set(HeaderTimestamp, h.Timestamp)
	r.Header.Set(HeaderEventType, h.EventType)
	r.Header.Set(HeaderEventID, h.EventID)
}

// FromRequest reads the headers off a request.
func FromRequest(r *http.Request) Headers {
	return Headers{
		Signature: r.Header.Get(HeaderSignature),
		Timestamp: r.Header.Get(HeaderTimestamp),
		EventType: r.Header.Get(HeaderEventType),
		EventID:   r.Header.Get(HeaderEventID),
	}
}

func canonical(ts, eventType, eventID string, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b bytes.Buffer
	b.WriteString(prefix)
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(eventType)
	b.WriteByte('\n')
	b.WriteString(eventID)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return b.Bytes()
}

func mac(key []byte, msg []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return version + "=" + hex.EncodeToString(m.Sum(nil))
}

// Sign produces the headers for one event. eventType and eventID must be non-empty and free
// of newlines; eventID is stable across retries of the same event, so a receiver that saw
// the request but whose response was lost recognises the replay instead of acting twice.
func Sign(key []byte, at time.Time, eventType, eventID string, body []byte) (Headers, error) {
	if len(key) < MinKeyBytes {
		return Headers{}, ErrShortKey
	}
	if eventType == "" || eventID == "" || strings.ContainsAny(eventType+eventID, "\r\n") {
		return Headers{}, ErrMissingFields
	}
	ts := at.UTC().Format(time.RFC3339)
	return Headers{
		Signature: mac(key, canonical(ts, eventType, eventID, body)),
		Timestamp: ts,
		EventType: eventType,
		EventID:   eventID,
	}, nil
}

// Options tunes Verify.
type Options struct {
	// Window bounds |now - timestamp|. Zero means DefaultWindow.
	Window time.Duration
	// Now is the receiver's clock; nil means time.Now.
	Now func() time.Time
	// Replay, when set, is asked whether the event ID was already accepted inside the
	// window; a receiver with a table supplies its own, others use NewMemoryReplay.
	// Custom guards retain IDs through at+Window, inclusive, using the receiver's clock.
	Replay Replay
}

// Replay remembers accepted event IDs. Check returns nil and records id when it is new,
// ErrReplay when it was already recorded, or another error when it cannot decide (a guard
// that is full, a table that is down); any error refuses the event. Implementations must be
// safe for concurrent use.
type Replay interface {
	Check(id string, at time.Time) error
}

// Forgetter is a Replay that can release an ID Check recorded, so the sender's retry of an
// event the receiver failed to process is accepted again instead of refused as a replay.
// Middleware releases the ID itself when the handler answers anything but 2xx; a receiver
// that calls Verify directly calls Forget when it fails to process the event. The guard
// NewMemoryReplay returns implements it.
type Forgetter interface {
	Replay
	Forget(id string)
}

// Verify checks the headers against the body and the key. Every failure is one of the
// exported errors; the receiver answers 401 to all of them and logs which, except
// ErrReplay, which it acknowledges with 2xx without acting again. A receiver that then fails
// to process the event calls Forget on a Forgetter Replay so the sender's retry is accepted.
func Verify(key []byte, h Headers, body []byte, o Options) (Event, error) {
	if len(key) < MinKeyBytes {
		return Event{}, ErrShortKey
	}
	if h.Signature == "" {
		return Event{}, ErrNoSignature
	}
	if h.EventType == "" || h.EventID == "" || strings.ContainsAny(h.EventType+h.EventID, "\r\n") {
		return Event{}, ErrMissingFields
	}
	at, err := time.Parse(time.RFC3339, h.Timestamp)
	if err != nil {
		return Event{}, ErrBadTimestamp
	}
	want := mac(key, canonical(h.Timestamp, h.EventType, h.EventID, body))
	if !hmac.Equal([]byte(h.Signature), []byte(want)) {
		return Event{}, ErrBadSignature
	}
	ev := Event{Type: h.EventType, ID: h.EventID, At: at}
	if err := checkReplay(ev, o); err != nil {
		return Event{}, err
	}
	return ev, nil
}

func checkReplay(ev Event, o Options) error {
	clock := o.Now
	if clock == nil {
		clock = time.Now
	}
	window := o.Window
	if window == 0 {
		window = DefaultWindow
	}
	if m, ok := o.Replay.(*memoryReplay); ok {
		m.mu.Lock()
		defer m.mu.Unlock()
		now := clock()
		if err := checkTimestamp(ev.At, now, window); err != nil {
			return err
		}
		return m.check(ev.ID, ev.At.Add(max(m.window, window)), now)
	}
	if err := checkTimestamp(ev.At, clock(), window); err != nil {
		return err
	}
	if o.Replay != nil {
		return o.Replay.Check(ev.ID, ev.At)
	}
	return nil
}

func checkTimestamp(at, now time.Time, window time.Duration) error {
	if d := now.Sub(at); d > window || d < -window {
		return fmt.Errorf("%w: event %s, receiver %s", ErrStale, at.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// memoryReplay is a bounded in-process replay guard. It forgets IDs only once their
// timestamp has left the window; when it holds max IDs that are all still inside the window
// it refuses with ErrReplayGuardFull rather than forgetting one, because a forgotten ID is a
// replay the signature alone cannot stop.
type memoryReplay struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	seen   map[string]time.Time // last accepted instant for each event
}

// NewMemoryReplay returns a Replay that remembers up to max IDs for window; it also
// implements Forgetter. Verify uses its own clock and retains each ID for at least
// its accepted Window, even when that is wider than the guard's window.
// Use it when the receiver has no table of processed events; a
// restart forgets everything, which is the window's job to bound. Size max above the events one sender can emit in a window, or the
// guard refuses under load.
func NewMemoryReplay(window time.Duration, max int) Replay {
	if window <= 0 {
		window = DefaultWindow
	}
	if max <= 0 {
		max = 10000
	}
	return &memoryReplay{window: window, max: max, seen: map[string]time.Time{}}
}

func (m *memoryReplay) Check(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.check(id, at.Add(m.window), time.Now())
}

// The caller holds mu. Verify samples and validates its clock under the same lock,
// so a paused verification cannot reinsert an ID another request just expired.
func (m *memoryReplay) check(id string, expiry, now time.Time) error {
	if old, ok := m.seen[id]; ok {
		if !old.Before(now) {
			if expiry.After(old) {
				m.seen[id] = expiry
			}
			return ErrReplay
		}
		delete(m.seen, id)
	}
	if len(m.seen) >= m.max {
		for id, expiry := range m.seen {
			if expiry.Before(now) {
				delete(m.seen, id)
			}
		}
	}
	if len(m.seen) >= m.max {
		return ErrReplayGuardFull
	}
	m.seen[id] = expiry
	return nil
}

// Forget releases the ID and its capacity immediately.
func (m *memoryReplay) Forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.seen, id)
}

type ctxKey struct{}

// EventFromContext returns the verified Event Middleware stored.
func EventFromContext(r *http.Request) (Event, bool) {
	e, ok := r.Context().Value(ctxKey{}).(Event)
	return e, ok
}

// Middleware reads a bounded body, verifies it, and passes the request on with the same
// bytes replaced on r.Body so the handler decodes exactly what was signed. keyFn resolves
// the sync secret for this request (one per deployment, or per sender); an error from it is
// a 401 too, so an unconfigured receiver fails closed. Failures answer 401 with a fixed
// body; the reason goes only to onReject, for the receiver's log.
//
// An event ID the Replay already accepted answers 200 {"status":"duplicate_event"} without
// calling the handler: the sender's retry of an event that was processed is done, not a
// signature failure. onReject still sees ErrReplay. When o.Replay is a Forgetter and the
// handler answers anything but 2xx (or panics), Middleware forgets the ID so the sender's
// retry runs the handler again. A retry that arrives while the first delivery is still
// running receives retryable 503 with Retry-After, not a completion acknowledgement.
// In-flight tracking is local to this middleware instance, not shared across processes. Event IDs are
// unique per sender only: when keyFn serves several senders, give each its own Replay.
// A Replay that is not a Forgetter is never released here, so the retry of a failed event
// is acknowledged as a duplicate and lost; such a Replay must drop the ID itself when the
// handler fails.
func Middleware(keyFn func(r *http.Request) ([]byte, error), o Options, maxBody int64, onReject func(r *http.Request, err error)) func(http.Handler) http.Handler {
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	var pending sync.Map
	reject := func(w http.ResponseWriter, r *http.Request, err error) {
		if onReject != nil {
			onReject(r, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_signature"}`))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, err := keyFn(r)
			if err != nil || len(key) < MinKeyBytes {
				reject(w, r, fmt.Errorf("syncauth: key unavailable: %w", errors.Join(err, ErrShortKey)))
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
			if err != nil {
				reject(w, r, err)
				return
			}
			if int64(len(body)) > maxBody {
				reject(w, r, ErrBodyTooLarge)
				return
			}
			verifyOptions := o
			verifyOptions.Replay = nil
			ev, err := Verify(key, FromRequest(r), body, verifyOptions)
			if err != nil {
				reject(w, r, err)
				return
			}
			if o.Replay != nil {
				if _, active := pending.LoadOrStore(ev.ID, struct{}{}); active {
					if onReject != nil {
						onReject(r, ErrReplay)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"status":"event_pending"}`))
					return
				}
				defer pending.Delete(ev.ID)
				err = checkReplay(ev, o)
			}
			if errors.Is(err, ErrReplay) {
				if onReject != nil {
					onReject(r, err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"duplicate_event"}`))
				return
			}
			if err != nil {
				reject(w, r, err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			f, ok := o.Replay.(Forgetter)
			if !ok {
				next.ServeHTTP(w, r.WithContext(contextWith(r, ev)))
				return
			}
			sw := &statusWriter{ResponseWriter: w}
			processed := false
			defer func() {
				if !processed {
					f.Forget(ev.ID)
				}
			}()
			next.ServeHTTP(sw, r.WithContext(contextWith(r, ev)))
			// A handler that returns without writing gets 200 from net/http.
			processed = sw.status == 0 || (sw.status >= 200 && sw.status <= 299)
		})
	}
}

// statusWriter records the final (non-1xx) status the handler sent; 0 means none yet.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush keeps http.Flusher working for handlers behind the wrapper. Only a flush that
// happened sends the implicit 200, so only that one is recorded.
func (s *statusWriter) Flush() { _ = s.FlushError() }

// FlushError is what http.ResponseController calls, so its caller still sees a flush the
// writer underneath cannot do.
func (s *statusWriter) FlushError() error {
	err := http.NewResponseController(s.ResponseWriter).Flush()
	if err == nil && s.status == 0 {
		s.status = http.StatusOK
	}
	return err
}

// Unwrap lets http.ResponseController reach Flush and deadlines on the real writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
