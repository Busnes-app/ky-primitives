package recoveryclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// Check is one drill assertion and its verdict.
type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// DrillResult is what a restore drill reports.
type DrillResult struct {
	Passed       bool    `json:"passed"`
	Checks       []Check `json:"checks"`
	ErrorMessage string  `json:"error_message,omitempty"`
	DurationMs   int64   `json:"duration_ms"`
	SizeBytes    int     `json:"size_bytes"`
}

// drillPrefix names scratch directories so a killed drill's residue is recognised and
// removed by the next one.
const drillPrefix = "recoveryclient-drill-"

// ErrNoScratchRoot is returned when Drill is given no scratch root. The decrypted payload
// must land under a directory the operator provisioned and protected, the product's data
// directory, never under the system temp directory.
var ErrNoScratchRoot = errors.New("recoveryclient: drill needs a scratch root inside the data directory")

// Drill proves the payload restores: it seals to a throwaway key generated and discarded
// inside this call, opens the capsule into a 0700 scratch directory under scratchRoot wiped
// on return, and appends the product's checks. Checks receive the opened manifest; its
// recipe and dependency values are authenticated but caller-authored, so product code must
// type-check them and reject paths that are not clean relative paths inside dir before
// acting on them. Stale scratch directories left under scratchRoot by a killed drill are
// removed first. The suite key is never involved, so a passing drill says the format
// restores, not that the custodians' cards do; that is what the product's restore runbook
// is for.
func Drill(ctx context.Context, scratchRoot string, payload Payload, checks func(dir string, opened capsule.Manifest) []Check) (*DrillResult, error) {
	if scratchRoot == "" {
		return nil, ErrNoScratchRoot
	}
	sweepStaleDrills(scratchRoot)
	start := time.Now()
	result := &DrillResult{}
	fail := func(name, msg string) {
		result.Checks = append(result.Checks, Check{Name: name, Passed: false, Message: msg})
	}
	pass := func(name, msg string) {
		result.Checks = append(result.Checks, Check{Name: name, Passed: true, Message: msg})
	}
	finish := func() (*DrillResult, error) {
		result.DurationMs = time.Since(start).Milliseconds()
		result.Passed = len(result.Checks) > 0
		for _, c := range result.Checks {
			if !c.Passed {
				result.Passed = false
				if result.ErrorMessage == "" {
					result.ErrorMessage = c.Name + ": " + c.Message
				}
			}
		}
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	throwaway, err := recoverykey.Generate()
	if err != nil {
		return nil, err
	}
	raw, m, err := Seal(payload, RecoveryKey{Public: throwaway.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		fail("Seal", AuditSafe(err.Error()))
		return finish()
	}
	result.SizeBytes = len(raw)
	pass("Seal", fmt.Sprintf("%d files, %d bytes, capsule %s", len(payload.Files), len(raw), m.CapsuleID))

	dir, err := os.MkdirTemp(scratchRoot, drillPrefix+"*")
	if err != nil {
		fail("Sandbox", AuditSafe(err.Error()))
		return finish()
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		fail("Sandbox", AuditSafe(err.Error()))
		return finish()
	}
	opened, files, err := capsule.Open(raw, throwaway, dir)
	if err != nil {
		fail("Directory Unpack", AuditSafe(err.Error()))
		return finish()
	}
	if opened.CapsuleID != m.CapsuleID {
		fail("Directory Unpack", "opened manifest does not name the sealed capsule")
		return finish()
	}
	pass("Directory Unpack", fmt.Sprintf("%d files extracted into a 0700 sandbox", len(files)))
	if checks != nil {
		result.Checks = append(result.Checks, checks(dir, opened)...)
	}
	return finish()
}

// staleDrill is how old a drill directory must be before the sweep treats it as residue of
// a killed run rather than a drill still in flight beside this one.
const staleDrill = time.Hour

func sweepStaleDrills(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), drillPrefix) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > staleDrill {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}
