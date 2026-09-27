package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var errPanicked = errors.New("health: check panicked")

type runner struct {
	check Check
	busy  atomic.Bool
}

// run executes the check once. The error is the check's raw return, for the log only.
func (r *runner) run(ctx context.Context) (CheckResult, error) {
	res := CheckResult{Name: r.check.Name}
	// A previous run that ignored its context is still going. Starting another would
	// stack one goroutine per poll on a hung dependency.
	if !r.busy.CompareAndSwap(false, true) {
		res.Status, res.Reason = Down, Timeout.code
		return res, context.DeadlineExceeded
	}
	timeout := r.check.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		err := r.safeRun(ctx)
		// Free the runner before reporting, so the next evaluation never sees a
		// finished check as still running.
		r.busy.Store(false)
		done <- err
	}()
	select {
	case err := <-done:
		res.Status, res.Reason = classify(err)
		return res, err
	case <-ctx.Done():
		res.Status, res.Reason = Down, Timeout.code
		return res, ctx.Err()
	}
}

func (r *runner) safeRun(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = errPanicked
		}
	}()
	return r.check.Run(ctx)
}

// evaluate runs every check concurrently. The service status is the worst check status.
func evaluate(ctx context.Context, runners []*runner) (Status, []CheckResult, []error) {
	results := make([]CheckResult, len(runners))
	errs := make([]error, len(runners))
	var wg sync.WaitGroup
	for i, r := range runners {
		wg.Go(func() { results[i], errs[i] = r.run(ctx) })
	}
	wg.Wait()
	status := OK
	for _, res := range results {
		if res.Status.rank() > status.rank() {
			status = res.Status
		}
	}
	return status, results, errs
}
