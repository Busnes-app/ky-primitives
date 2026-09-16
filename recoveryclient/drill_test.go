package recoveryclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
)

func TestDrillOpensWhatItSealedAndWipesScratch(t *testing.T) {
	var seen string
	res, err := Drill(context.Background(), t.TempDir(), testPayload(), func(dir string, _ capsule.Manifest) []Check {
		seen = dir
		b, err := os.ReadFile(filepath.Join(dir, "data", "app.db"))
		info, _ := os.Stat(dir)
		return []Check{{Name: "db", Passed: err == nil && len(b) > 0 && info.Mode().Perm() == 0700}}
	})
	if err != nil || !res.Passed || len(res.Checks) != 3 || res.SizeBytes == 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := os.Stat(seen); !os.IsNotExist(err) {
		t.Fatalf("scratch dir %s survived", seen)
	}
}

func TestDrillFailsWhenAProductCheckFails(t *testing.T) {
	res, err := Drill(context.Background(), t.TempDir(), testPayload(), func(string, capsule.Manifest) []Check {
		return []Check{{Name: "admin", Passed: false, Message: "no active admin"}}
	})
	if err != nil || res.Passed || res.ErrorMessage != "admin: no active admin" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestDrillReportsASealItCannotPerform(t *testing.T) {
	res, err := Drill(context.Background(), t.TempDir(), Payload{ServiceName: "Svc"}, nil)
	if err != nil || res.Passed || len(res.Checks) != 1 || res.Checks[0].Name != "Seal" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestDrillUsesTheCallerScratchRoot(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, drillPrefix+"stale")
	if err := os.MkdirAll(stale, 0700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(stale, old, old)
	live := filepath.Join(root, drillPrefix+"live")
	if err := os.MkdirAll(live, 0700); err != nil {
		t.Fatal(err)
	}
	var seen string
	res, err := Drill(context.Background(), root, testPayload(), func(dir string, _ capsule.Manifest) []Check {
		seen = dir
		return []Check{{Name: "ok", Passed: true}}
	})
	if err != nil || !res.Passed {
		t.Fatalf("%v %+v", err, res)
	}
	if filepath.Dir(seen) != root {
		t.Errorf("scratch %s not under %s", seen, root)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale drill directory survived")
	}
	if _, err := os.Stat(live); err != nil {
		t.Error("a drill still in flight beside this one was removed")
	}
	if _, err := Drill(context.Background(), "", testPayload(), nil); err != ErrNoScratchRoot {
		t.Errorf("empty root: %v", err)
	}
}

// The recipe reaches the checks as the opened capsule carries it, JSON types and all, so a
// drill exercises the same shape a real restore reads.
func TestDrillHandsChecksTheOpenedManifest(t *testing.T) {
	p := testPayload()
	p.VerificationRecipe = map[string]any{"required_files": []string{"data/app.db", "../escape"}, "check": true}
	var got capsule.Manifest
	res, err := Drill(context.Background(), t.TempDir(), p, func(_ string, m capsule.Manifest) []Check {
		got = m
		return []Check{{Name: "ok", Passed: true}}
	})
	if err != nil || !res.Passed {
		t.Fatalf("%v %+v", err, res)
	}
	recipe, ok := got.VerificationRecipe.(map[string]any)
	if !ok || got.ServiceName != "Svc" {
		t.Fatalf("manifest %+v", got)
	}
	files, ok := recipe["required_files"].([]any)
	if !ok || len(files) != 2 || files[0] != "data/app.db" || files[1] != "../escape" {
		t.Fatalf("recipe after the round trip is %T %v; checks must handle the JSON shape", recipe["required_files"], recipe["required_files"])
	}
}
