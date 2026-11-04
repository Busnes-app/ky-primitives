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
	Replay Replay
}

// Replay remembers accepted event IDs. Check returns nil and records id when it is new,
// ErrReplay when it was already recorded, or another error when it cannot decide (a guard
// that is full, a table that is down); any error refuses the event. Implementations must be
// safe for concurrent use.
type Replay interface {
	Check(id string, at time.Time) error
}

// Verify checks the headers against the body and the key. Every failure is one of the
// exported errors; the receiver answers 401 to all of them and logs which.
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
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	window := o.Window
	if window == 0 {
		window = DefaultWindow
	}
	if d := now().Sub(at); d > window || d < -window {
		return Event{}, fmt.Errorf("%w: event %s, receiver %s", ErrStale, at.UTC().Format(time.RFC3339), now().UTC().Format(time.RFC3339))
	}
	want := mac(key, canonical(h.Timestamp, h.EventType, h.EventID, body))
	if !hmac.Equal([]byte(h.Signature), []byte(want)) {
		return Event{}, ErrBadSignature
	}
	if o.Replay != nil {
		if err := o.Replay.Check(h.EventID, at); err != nil {
			return Event{}, err
		}
	}
	return Event{Type: h.EventType, ID: h.EventID, At: at}, nil
}

// memoryReplay is a bounded in-process replay guard. It forgets IDs only once their
// timestamp has left the window; when it holds max IDs that are all still inside the window
// it refuses with ErrReplayGuardFull rather than forgetting one, because a forgotten ID is a
// replay the signature alone cannot stop.
type memoryReplay struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	seen   map[string]time.Time
	order  []string
}

// NewMemoryReplay returns a Replay that remembers up to max IDs for window. Use it when the
// receiver has no table of processed events; a restart forgets everything, which is the
// window's job to bound. Size max above the events one sender can emit in a window, or the
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
	cutoff := time.Now().Add(-m.window)
	for len(m.order) > 0 {
		oldest := m.order[0]
		if t, ok := m.seen[oldest]; ok && t.After(cutoff) {
			break
		}
		delete(m.seen, oldest)
		m.order = m.order[1:]
	}
	if _, ok := m.seen[id]; ok {
		return ErrReplay
	}
	if len(m.order) >= m.max {
		return ErrReplayGuardFull
	}
	m.seen[id] = at
	m.order = append(m.order, id)
	return nil
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
func Middleware(keyFn func(r *http.Request) ([]byte, error), o Options, maxBody int64, onReject func(r *http.Request, err error)) func(http.Handler) http.Handler {
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
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
			ev, err := Verify(key, FromRequest(r), body, o)
			if err != nil {
				reject(w, r, err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r.WithContext(contextWith(r, ev)))
		})
	}
}
