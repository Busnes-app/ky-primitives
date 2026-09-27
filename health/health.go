// Package health serves the suite's ky.health/1 endpoint: one public JSON shape that says
// whether a service works, without saying anything an attacker could use.
package health

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"time"
)

// Schema is the value of Response.Schema.
const Schema = "ky.health/1"

// DefaultTimeout bounds a check whose Timeout is zero.
const DefaultTimeout = 2 * time.Second

// Status is the state of one check or of the whole service.
type Status string

const (
	OK       Status = "ok"
	Degraded Status = "degraded"
	Down     Status = "down"
)

func (s Status) rank() int {
	switch s {
	case OK:
		return 0
	case Degraded:
		return 1
	}
	return 2
}

var (
	codePattern    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	namePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	servicePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

// Reason is a fixed code anyone who can reach /healthz may read. Its field is unexported,
// so the only reasons that exist are ones DeclareReason validated.
type Reason struct{ code string }

// DeclareReason admits a reason code. Call it once, at package level, so a bad code panics
// at startup rather than inside a running check.
func DeclareReason(code string) Reason {
	if !codePattern.MatchString(code) {
		panic("health: reason " + strconv.Quote(code) + " must match [a-z0-9_]{1,64}")
	}
	return Reason{code: code}
}

// Timeout is the reason for a check that missed its deadline.
var Timeout = DeclareReason("timeout")

type outcome struct {
	status Status
	reason Reason
}

func (o outcome) Error() string { return string(o.status) + ": " + o.reason.code }

// Degrade reports the check degraded, with r.
func Degrade(r Reason) error { return outcome{Degraded, r} }

// Fail reports the check down, with r.
func Fail(r Reason) error { return outcome{Down, r} }

// classify maps a check's return to what the response may show. An error that did not
// come from Degrade or Fail is down with no reason: its text never reaches the response.
func classify(err error) (Status, string) {
	if err == nil {
		return OK, ""
	}
	var o outcome
	if errors.As(err, &o) {
		return o.status, o.reason.code
	}
	return Down, ""
}

// Check is one dependency the service needs. Run must honour ctx.
type Check struct {
	Name    string        // [a-z][a-z0-9_]{0,63}, unique per handler
	Timeout time.Duration // zero means DefaultTimeout
	Run     func(ctx context.Context) error
}

// Response is the ky.health/1 body.
type Response struct {
	Schema  string        `json:"schema"`
	Service string        `json:"service"`
	Status  Status        `json:"status"`
	Time    time.Time     `json:"time"`
	Checks  []CheckResult `json:"checks"`
}

// CheckResult is one check in a Response.
type CheckResult struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`
}
