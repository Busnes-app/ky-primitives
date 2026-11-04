package recoveryclient

import (
	"errors"
	"testing"
	"time"
)

func TestSetIntervalBoundsSeconds(t *testing.T) {
	s := memSettings{}
	for _, bad := range []int64{1, 899, -3600, 36028797018963968, int64(MaxInterval/time.Second) + 1} {
		if err := SetInterval(s, bad); !errors.Is(err, ErrBadInterval) {
			t.Errorf("%d: %v", bad, err)
		}
	}
	for _, ok := range []int64{0, 900, 3600, int64(MaxInterval / time.Second)} {
		if err := SetInterval(s, ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
}

func TestIntervalFallsBackToDefault(t *testing.T) {
	s := memSettings{}
	if d, err := Interval(24*time.Hour, s); err != nil || d != 24*time.Hour {
		t.Fatalf("%v %v", d, err)
	}
	_ = SetInterval(s, 3600)
	if d, _ := Interval(24*time.Hour, s); d != time.Hour {
		t.Fatalf("%v", d)
	}
}

func TestNextRunCountsFromLastAttempt(t *testing.T) {
	s := memSettings{}
	if _, on, _ := NextRun(0, s); on {
		t.Fatal("off schedule reported on")
	}
	_ = SetInterval(s, 3600)
	next, on, err := NextRun(0, s)
	if err != nil || !on || next.After(time.Now()) {
		t.Fatalf("never attempted: %v %v %v", next, on, err)
	}
	if err := markAttempt(s); err != nil {
		t.Fatal(err)
	}
	next, on, _ = NextRun(0, s)
	if !on || next.Before(time.Now().Add(59*time.Minute)) {
		t.Fatalf("after attempt: %v", next)
	}
}

// A row written before this package, or by hand, gets the same bound on the way in.
func TestIntervalRefusesAStoredValueOutsideTheBound(t *testing.T) {
	for _, raw := range []string{"36028797018963968", "-3600", "1", "31622401"} {
		s := memSettings{settingInterval: raw}
		if d, err := Interval(24*time.Hour, s); !errors.Is(err, ErrBadInterval) || d != 0 {
			t.Errorf("%s: %v %v", raw, d, err)
		}
		next, on, err := NextRun(24*time.Hour, s)
		if !errors.Is(err, ErrBadInterval) || on || !next.IsZero() {
			t.Errorf("%s: NextRun %v %v %v", raw, next, on, err)
		}
	}
	if d, err := Interval(24*time.Hour, memSettings{settingInterval: "0"}); err != nil || d != 0 {
		t.Errorf("stored off: %v %v", d, err)
	}
}

// A clock that once ran a year ahead left a future stamp; once corrected, the next run is now,
// not a year away.
func TestNextRunTreatsAFutureStampAsDue(t *testing.T) {
	s := memSettings{settingLastAttempt: time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)}
	next, ok, err := NextRun(time.Hour, s)
	if err != nil || !ok || time.Until(next) > time.Minute {
		t.Fatalf("next %v ok %v err %v", next, ok, err)
	}
}
