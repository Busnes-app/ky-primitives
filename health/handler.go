package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Busnes-app/ky-primitives/logging"
)

// CacheFor is how long one evaluation answers every request. The route is public, so
// without it each request would run every check against the service's dependencies.
const CacheFor = 5 * time.Second

var (
	checkFailed = logging.DeclareEvent("health_check_failed", "health check failed", slog.LevelWarn)
	checkName   = logging.DeclareString("health_check")
)

type handler struct {
	service string
	lg      *logging.Logger
	runners []*runner
	now     func() time.Time

	mu   sync.Mutex
	at   time.Time
	resp Response
}

// Handler serves GET and HEAD for service's /healthz. Failed checks are logged to lg with
// the error kind; the response carries only status and reason codes. It panics on an
// invalid service or check name, a duplicate check name, a nil Run or a nil logger.
func Handler(service string, lg *logging.Logger, checks ...Check) http.Handler {
	return newHandler(service, lg, time.Now, checks)
}

func newHandler(service string, lg *logging.Logger, now func() time.Time, checks []Check) *handler {
	if !servicePattern.MatchString(service) {
		panic("health: service " + strconv.Quote(service) + " must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
	}
	if lg == nil {
		panic("health: a logger is required; failed checks are logged, not shown")
	}
	h := &handler{service: service, lg: lg, now: now}
	seen := map[string]bool{}
	for _, c := range checks {
		if !namePattern.MatchString(c.Name) {
			panic("health: check " + strconv.Quote(c.Name) + " must match [a-z][a-z0-9_]{0,63}")
		}
		if seen[c.Name] {
			panic("health: check " + c.Name + " is declared twice")
		}
		if c.Run == nil {
			panic("health: check " + c.Name + " has no Run")
		}
		if c.Timeout > MaxTimeout {
			panic("health: check " + c.Name + " timeout exceeds MaxTimeout")
		}
		seen[c.Name] = true
		h.runners = append(h.runners, &runner{check: c})
	}
	return h
}

// current returns the cached response, evaluating when it is older than CacheFor.
// Concurrent callers wait on the one evaluation instead of starting their own.
func (h *handler) current(ctx context.Context) Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if !h.at.IsZero() && now.Sub(h.at) < CacheFor {
		return h.resp
	}
	// Not the request context: the result is shared, so one client hanging up must not
	// cancel the checks every other client sees.
	status, results, errs := evaluate(context.Background(), h.runners)
	for i, res := range results {
		if res.Status != OK {
			fields := []logging.Field{checkName(res.Name)}
			if res.Reason != "" {
				fields = append(fields, logging.ReasonCode(res.Reason))
			}
			fields = append(fields, logging.Err(errs[i]))
			h.lg.Log(ctx, checkFailed, fields...)
		}
	}
	h.at = now
	h.resp = Response{
		Schema:  Schema,
		Service: h.service,
		Status:  status,
		Time:    now.UTC().Truncate(time.Second),
		Checks:  results,
	}
	return h.resp
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := h.current(r.Context())
	body, err := json.Marshal(resp)
	if err != nil {
		panic("health: marshal: " + err.Error()) // fixed types; cannot fail
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	code := http.StatusOK
	if resp.Status == Down {
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}
