package password_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/password"
)

func TestHashWithRoundTripsAtALowerCost(t *testing.T) {
	p := password.Params{Memory: 8 * 1024, Time: 1, Threads: 1}
	encoded, err := password.HashWith("correct horse battery staple", p)
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	if !strings.Contains(encoded, "m=8192,t=1,p=1") {
		t.Errorf("encoded = %q, want the requested parameters", encoded)
	}
	ok, err := password.Verify("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify rejected a hash HashWith just minted")
	}
}

func TestHashWithRefusesWhatVerifyWouldRefuse(t *testing.T) {
	// Below the 8 MiB floor parse accepts. Minting it would produce a hash that
	// verifies nowhere, which is worse than refusing.
	cases := map[string]password.Params{
		"memory below floor": {Memory: 4 * 1024, Time: 3, Threads: 4},
		"memory above cap":   {Memory: 512 * 1024, Time: 3, Threads: 4},
		"time zero":          {Memory: 64 * 1024, Time: 0, Threads: 4},
		"time above cap":     {Memory: 64 * 1024, Time: 11, Threads: 4},
		"threads zero":       {Memory: 64 * 1024, Time: 3, Threads: 0},
		"threads above cap":  {Memory: 64 * 1024, Time: 3, Threads: 17},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := password.HashWith("hunter2", p); err == nil {
				t.Errorf("HashWith accepted %+v", p)
			}
		})
	}
}

func TestHashWithDefaultParamsMatchesHash(t *testing.T) {
	a, err := password.HashWith("hunter2", password.DefaultParams())
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	b, err := password.Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	// Different salts, so not equal — but the parameter segment must match.
	if strings.Split(a, "$")[3] != strings.Split(b, "$")[3] {
		t.Errorf("HashWith(DefaultParams()) params %q != Hash params %q",
			strings.Split(a, "$")[3], strings.Split(b, "$")[3])
	}
}

// HashWith exists for tests and for a product that must match an existing deployment.
// Production code in this repository mints at the suite parameters, through Hash.
func TestHashWithIsNotCalledOutsideTests(t *testing.T) {
	root := ".."
	self, err := filepath.Abs("password.go")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	visited := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		visited++
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Compare resolved paths, not a suffix: a same-named password.go in any other
		// package must not get a free pass.
		if strings.Contains(string(src), "HashWith(") && abs != self {
			t.Errorf("%s calls HashWith; production code mints through Hash", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if visited == 0 {
		t.Fatal("walk visited zero non-test .go files; the walk is broken, not passing")
	}
}
