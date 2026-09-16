package kyprimitives

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// allowed is the module's entire dependency budget.
//
// The rule used to be "no dependencies, ever", so that products with minimal trees could
// import capsule and shamir for free — kypassword-server's go.mod named no third-party
// module at all, and now names exactly one: this library. Argon2 broke the rule: the suite
// standardised on it for password hashing, and it is not in the standard library and not
// on a proposal track.
//
// So the budget is x/crypto and the x/sys it drags in, and nothing else. Every other
// package in this module stays standard-library-only; a consumer that only wants capsule
// still compiles none of this, though it does inherit the requirement in its go.mod.
var allowed = map[string]bool{
	"golang.org/x/crypto": true,
	"golang.org/x/sys":    true,
}

var requireLine = regexp.MustCompile(`^([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+)\s+v`)

const selfModule = "github.com/Busnes-app/ky-primitives"

// importsOf returns every quoted import path in src that starts with prefix.
func importsOf(src, prefix string) []string {
	var found []string
	for _, chunk := range strings.Split(src, `"`+prefix)[1:] {
		if end := strings.Index(chunk, `"`); end >= 0 {
			found = append(found, prefix+chunk[:end])
		}
	}
	return found
}

func TestModuleDependenciesAreAllowlisted(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		text := strings.TrimSpace(line)
		if idx := strings.Index(text, "//"); idx >= 0 {
			text = strings.TrimSpace(text[:idx])
		}
		switch {
		case strings.HasPrefix(text, "replace ") || strings.HasPrefix(text, "exclude "):
			t.Errorf("go.mod:%d: %s", i+1, text)
			continue
		case strings.HasPrefix(text, "module ") || strings.HasPrefix(text, "go ") || strings.HasPrefix(text, "toolchain "):
			continue
		}
		text = strings.TrimPrefix(text, "require ")
		m := requireLine.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if !allowed[m[1]] {
			t.Errorf("go.mod:%d requires %s, which is not in the dependency budget", i+1, m[1])
		}
	}
}

// Only the password package may import outside the standard library. This is the check
// that keeps the budget from spreading once it exists.
//
// It discovers packages rather than listing them, so a package added later is covered
// without anyone remembering to add it here.
//
// The walk is recursive on purpose. It used to read one directory level, so cmd/ was
// listed and cmd/kyauditverify/ — where every command actually lives — was never opened:
// an x/crypto import placed there passed this test and TestModuleDependenciesAreAllowlisted
// alike, because x/crypto is already a permitted require. A one-level scan cannot make the
// "covered without anyone remembering" promise the paragraph above makes.
func TestOnlyPasswordImportsADependency(t *testing.T) {
	checked := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// A nested module owns its own dependency budget. Walking into it would
			// make this root-module test reject dependencies its go.mod cannot expose.
			if path != "." {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return fs.SkipDir
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			name := d.Name()
			if path != "." && (name == "password" || name == "testdata" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		// This file names the allowed modules as string literals, so scanning it for
		// import paths would report its own allowlist as a violation.
		if !strings.HasSuffix(path, ".go") || path == "nodeps_test.go" {
			return nil
		}
		checked++
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, dep := range []string{"golang.org/x/", "github.com/"} {
			for _, imp := range importsOf(string(src), dep) {
				// The module importing itself is not a dependency.
				if strings.HasPrefix(imp, selfModule) {
					continue
				}
				t.Errorf("%s imports %s; only password may", path, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no package files were checked, so this test proves nothing")
	}
	t.Logf("checked %d files outside password", checked)
}
