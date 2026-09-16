package guardtest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
)

type recorder struct {
	testing.TB
	errors []string
	fatal  string
}

type stop struct{}

func (r *recorder) Helper()                   {}
func (r *recorder) Errorf(f string, a ...any) { r.errors = append(r.errors, fmt.Sprintf(f, a...)) }
func (r *recorder) Fatalf(f string, a ...any) { r.fatal = fmt.Sprintf(f, a...); panic(stop{}) }
func (r *recorder) Fatal(a ...any)            { r.fatal = fmt.Sprint(a...); panic(stop{}) }

func run(rec *recorder, root string, allowed map[string][]string) {
	defer func() {
		if x := recover(); x != nil {
			if _, ok := x.(stop); !ok {
				panic(x)
			}
		}
	}()
	guardtest.NoDecryptOutside(rec, root, allowed)
}

func write(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGuardCatchesPlantedOpen(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 11; i++ {
		write(t, root, fmt.Sprintf("p%d/p.go", i), "package p\n")
	}
	write(t, root, "cmd/x/main.go", `package main

import (
	caps "github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func restore() { _ = caps.Open; _ = recoverykey.Combine }
func other()   { _ = caps.Open }
func fine()    { _ = recoverykey.Generate }
`)
	rec := &recorder{}
	run(rec, root, map[string][]string{filepath.Join("cmd", "x", "main.go"): {"restore"}})
	if rec.fatal != "" || len(rec.errors) != 1 || !strings.Contains(rec.errors[0], "other") || !strings.Contains(rec.errors[0], "capsule.Open") {
		t.Fatalf("fatal=%q errors=%v", rec.fatal, rec.errors)
	}
}

func TestGuardSeesWebDirsPackageLevelInitialisersAndDotImports(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 11; i++ {
		write(t, root, fmt.Sprintf("p%d/p.go", i), "package p\n")
	}
	write(t, root, "web/x.go", `package web

import "github.com/Busnes-app/ky-primitives/capsule"

func serve() { _ = capsule.Open }
`)
	write(t, root, "cmd/y/main.go", `package main

import "github.com/Busnes-app/ky-primitives/recoverykey"

var combine = recoverykey.Combine

func restore() { _ = recoverykey.Combine }
`)
	write(t, root, "cmd/z/main.go", `package main

import . "github.com/Busnes-app/ky-primitives/capsule"

func restore() { _ = Open }
`)
	rec := &recorder{}
	run(rec, root, map[string][]string{filepath.Join("cmd", "y", "main.go"): {"restore"}, filepath.Join("cmd", "z", "main.go"): {"restore"}})
	joined := strings.Join(rec.errors, "\n")
	if rec.fatal != "" || len(rec.errors) != 3 || !strings.Contains(joined, "web/x.go") || !strings.Contains(joined, "at package level") || !strings.Contains(joined, "dot-imports") {
		t.Fatalf("fatal=%q errors=%v", rec.fatal, rec.errors)
	}
}

func TestGuardFailsOnRelativeRootOrTooFewFiles(t *testing.T) {
	rec := &recorder{}
	run(rec, "relative/path", nil)
	if !strings.Contains(rec.fatal, "absolute") {
		t.Fatalf("relative root: %q", rec.fatal)
	}
	root := t.TempDir()
	write(t, root, "a/a.go", "package a\n")
	rec = &recorder{}
	run(rec, root, nil)
	if !strings.Contains(rec.fatal, "walked only 1") {
		t.Fatalf("too few files: %q", rec.fatal)
	}
}
