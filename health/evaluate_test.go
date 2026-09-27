package health

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func runners(checks ...Check) []*runner {
	rs := make([]*runner, len(checks))
	for i, c := range checks {
		rs[i] = &runner{check: c}
	}
	return rs
}

func ok(context.Context) error { return nil }

func TestEvaluateStatusIsTheWorstCheck(t *testing.T) {
	cases := []struct {
		name   string
		checks []Check
		want   Status
	}{
		{"no checks", nil, OK},
		{"all ok", []Check{{Name: "a", Run: ok}, {Name: "b", Run: ok}}, OK},
		{"one degraded", []Check{{Name: "a", Run: ok}, {Name: "b", Run: func(context.Context) error { return Degrade(appendDisabled) }}}, Degraded},
		{"down beats degraded", []Check{
			{Name: "a", Run: func(context.Context) error { return Degrade(appendDisabled) }},
			{Name: "b", Run: func(context.Context) error { return errors.New("boom") }},
		}, Down},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, results, _ := evaluate(context.Background(), runners(tc.checks...))
			if status != tc.want {
				t.Fatalf("status = %q, want %q", status, tc.want)
			}
			if len(results) != len(tc.checks) {
				t.Fatalf("got %d results for %d checks", len(results), len(tc.checks))
			}
		})
	}
}

func TestEvaluateKeepsDeclaredOrder(t *testing.T) {
	_, results, _ := evaluate(context.Background(), runners(
		Check{Name: "database", Run: func(context.Context) error { time.Sleep(20 * time.Millisecond); return nil }},
		Check{Name: "audit", Run: ok},
	))
	if results[0].Name != "database" || results[1].Name != "audit" {
		t.Fatalf("order = %q, %q", results[0].Name, results[1].Name)
	}
}

func TestCheckPastItsDeadlineIsDownWithTimeout(t *testing.T) {
	_, results, errs := evaluate(context.Background(), runners(Check{
		Name:    "slow",
		Timeout: 20 * time.Millisecond,
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}))
	if results[0].Status != Down || results[0].Reason != "timeout" {
		t.Fatalf("result = %+v", results[0])
	}
	if !errors.Is(errs[0], context.DeadlineExceeded) {
		t.Fatalf("err = %v", errs[0])
	}
}

func TestHungCheckIsNotStartedAgain(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var starts atomic.Int32
	rs := runners(Check{
		Name:    "hung",
		Timeout: 10 * time.Millisecond,
		Run: func(context.Context) error {
			starts.Add(1)
			<-release // ignores its context
			return nil
		},
	})
	for i := range 3 {
		_, results, errs := evaluate(context.Background(), rs)
		if results[0].Status != Down || results[0].Reason != "timeout" {
			t.Fatalf("result = %+v", results[0])
		}
		// The first evaluation actually started the check and waited, so its error is the
		// real deadline. Later evaluations find it still running and get the sentinel.
		if i == 0 {
			if !errors.Is(errs[0], context.DeadlineExceeded) {
				t.Fatalf("err = %v", errs[0])
			}
		} else if !errors.Is(errs[0], errStillRunning) {
			t.Fatalf("err = %v", errs[0])
		}
	}
	if n := starts.Load(); n != 1 {
		t.Fatalf("check started %d times, want 1", n)
	}
}

func TestPanickingCheckIsDownAndReportsThePanic(t *testing.T) {
	var calls atomic.Int32
	rs := runners(Check{
		Name: "bad",
		Run: func(context.Context) error {
			if calls.Add(1) == 1 {
				panic("nil map")
			}
			return nil
		},
	})
	_, results, errs := evaluate(context.Background(), rs)
	if results[0].Status != Down || results[0].Reason != "" {
		t.Fatalf("result = %+v", results[0])
	}
	if !errors.Is(errs[0], errPanicked) {
		t.Fatalf("err = %v", errs[0])
	}
	// The same runner is free again: the next evaluation runs the check rather than
	// reporting it hung.
	_, results, _ = evaluate(context.Background(), rs)
	if results[0].Status != OK {
		t.Fatalf("second run = %+v", results[0])
	}
}
