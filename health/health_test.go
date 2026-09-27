package health

import (
	"errors"
	"fmt"
	"testing"
)

var (
	appendDisabled = DeclareReason("append_disabled")
	dbUnreachable  = DeclareReason("db_unreachable")
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus Status
		wantReason string
	}{
		{"nil is ok", nil, OK, ""},
		{"degrade", Degrade(appendDisabled), Degraded, "append_disabled"},
		{"fail", Fail(dbUnreachable), Down, "db_unreachable"},
		{"wrapped fail keeps its reason", fmt.Errorf("ping: %w", Fail(dbUnreachable)), Down, "db_unreachable"},
		{"plain error is down with no reason", errors.New("dial tcp 10.0.0.5:5432: connection refused"), Down, ""},
		{"zero reason degrades without a code", Degrade(Reason{}), Degraded, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := classify(tc.err)
			if status != tc.wantStatus || reason != tc.wantReason {
				t.Fatalf("classify = (%q, %q), want (%q, %q)", status, reason, tc.wantStatus, tc.wantReason)
			}
		})
	}
}

func TestDeclareReasonRejectsCodesOutsideThePattern(t *testing.T) {
	for _, code := range []string{"", "Upper", "has space", "db@host", "a-b", string(make([]byte, 65))} {
		t.Run(fmt.Sprintf("%q", code), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("DeclareReason(%q) did not panic", code)
				}
			}()
			DeclareReason(code)
		})
	}
}

func TestDeclareReasonAcceptsTheLongestCode(t *testing.T) {
	code := ""
	for range 64 {
		code += "a"
	}
	if got := DeclareReason(code).code; got != code {
		t.Fatalf("code = %q", got)
	}
}
