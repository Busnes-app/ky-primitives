// Package guardtest pins the decrypt boundary of a product: nothing in the server may open a
// capsule sealed to the suite key, combine shares or rebuild the key from a seed, except the
// functions the product names. Products call NoDecryptOutside from one test.
package guardtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// forbidden maps the last path element of a watched import to the selectors that decrypt.
// recoveryclient.Drill is not here: it opens only a capsule sealed to a key it generated and
// dropped inside the call.
var forbidden = map[string]map[string]bool{
	"capsule":        {"Open": true},
	"recoverykey":    {"Combine": true, "FromSeed": true},
	"recoveryclient": {"Restore": true},
}

const importPrefix = "github.com/Busnes-app/ky-primitives/"

// MinFiles is how many Go files a walk must see before its verdict counts. A guard that
// walked nothing passes vacuously, which the first draft of this test did.
const MinFiles = 10

// NoDecryptOutside walks every non-test Go file under repoRoot (absolute) and fails t for
// each call of a forbidden selector outside allowed, which maps a repo-relative file path to
// the names of functions inside it that may make such calls.
func NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string) {
	t.Helper()
	if !filepath.IsAbs(repoRoot) {
		t.Fatalf("guardtest: repo root must be absolute, got %q", repoRoot)
	}
	seen := 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Only directories that cannot hold the product's own Go code are skipped by
			// name. web/ and dist/ are walked: some layouts keep Go there.
			if path != repoRoot && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		seen++
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repoRoot, path)
		aliases := map[string]string{} // local name -> package key
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(p, importPrefix) {
				continue
			}
			key := p[strings.LastIndex(p, "/")+1:]
			if _, watched := forbidden[key]; !watched {
				continue
			}
			local := key
			if imp.Name != nil {
				local = imp.Name.Name
			}
			if local == "." {
				// A dot-import makes every forbidden call a bare identifier the alias table
				// cannot resolve, so the file is refused outright.
				t.Errorf("guardtest: %s dot-imports %s; import it by name so its calls can be checked", rel, p)
				continue
			}
			aliases[local] = key
		}
		if len(aliases) == 0 {
			return nil
		}
		// Every declaration is inspected, not only function bodies: a package-level var
		// initialiser can call a forbidden function too. A hit outside any function is
		// attributed to the file and never allowed.
		for _, decl := range f.Decls {
			enclosing := ""
			var body ast.Node = decl
			if fn, ok := decl.(*ast.FuncDecl); ok {
				if fn.Body == nil {
					continue
				}
				enclosing, body = fn.Name.Name, fn.Body
			}
			ast.Inspect(body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				key, watched := aliases[id.Name]
				if !watched || !forbidden[key][sel.Sel.Name] {
					return true
				}
				if enclosing != "" && slices.Contains(allowed[rel], enclosing) {
					return true
				}
				where := "at package level"
				if enclosing != "" {
					where = "inside " + enclosing
				}
				t.Errorf("guardtest: %s calls %s.%s %s, which is not allowed to decrypt", fset.Position(sel.Pos()), key, sel.Sel.Name, where)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("guardtest: walking %s: %v", repoRoot, err)
	}
	if seen < MinFiles {
		t.Fatalf("guardtest: walked only %d Go files under %s; the guard is not looking at the repository", seen, repoRoot)
	}
}
