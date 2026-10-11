//go:build linux

package applysetup

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStageBoundary(t *testing.T) {
	const id = "271333e2-c221-4601-b249-563b3d828530"
	raw := []byte(`{"schema":"ky.product-setup/1","service":"kydrive","setupId":"271333e2-c221-4601-b249-563b3d828530"}`)
	data := t.TempDir()
	file := filepath.Join(data, "installer", id, "setup.json")
	if _, err := Stage(data, file, id, raw, true); err == nil {
		t.Fatal("missing inspection accepted")
	}
	if _, err := os.Stat(filepath.Join(data, "installer")); !os.IsNotExist(err) {
		t.Fatal("inspection created state")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, err := Stage(data, file, id, raw, false)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if status == "created" {
				created++
			} else if status != "present" {
				t.Error("unexpected preparation receipt")
			}
		}()
	}
	wg.Wait()
	if created != 1 {
		t.Fatal("parallel immutable preparation did not publish exactly once", created)
	}
	if status, err := Stage(data, file, id, raw, true); err != nil || status != "present" {
		t.Fatal("retained inspection failed", err)
	}
	changed := append(bytes.Clone(raw), ' ')
	for _, check := range []bool{false, true} {
		if _, err := Stage(data, file, id, changed, check); err == nil {
			t.Fatal("changed intent accepted")
		}
	}
	actual, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("changed intent replaced retained metadata")
	}
	if _, err := Stage(data, filepath.Join(data, "foreign.json"), id, raw, false); err == nil {
		t.Fatal("arbitrary write path accepted")
	}
	if _, err := os.Stat(filepath.Join(data, "foreign.json")); !os.IsNotExist(err) {
		t.Fatal("arbitrary path mutated")
	}
	if os.Chmod(file, 0644) != nil {
		t.Fatal("fixture chmod failed")
	}
	if _, err := Stage(data, file, id, raw, true); err == nil {
		t.Fatal("shared retained metadata accepted")
	}
	if os.Chmod(file, 0600) != nil {
		t.Fatal("fixture chmod failed")
	}
	if os.Remove(file) != nil || os.Symlink(filepath.Join(data, "victim.json"), file) != nil {
		t.Fatal("fixture symlink failed")
	}
	if _, err := Stage(data, file, id, raw, false); err == nil {
		t.Fatal("symlinked metadata accepted")
	}
	if _, err := os.Stat(filepath.Join(data, "victim.json")); !os.IsNotExist(err) {
		t.Fatal("symlink victim mutated")
	}
}

func TestStageUnsafeAncestors(t *testing.T) {
	const id = "271333e2-c221-4601-b249-563b3d828530"
	for _, mode := range []string{"linked-data", "writable-parent", "shared-installer", "linked-installer"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			data := filepath.Join(base, "data")
			if os.Mkdir(data, 0700) != nil {
				t.Fatal("mkdir")
			}
			switch mode {
			case "linked-data":
				if os.Rename(data, filepath.Join(base, "real")) != nil || os.Symlink(filepath.Join(base, "real"), data) != nil {
					t.Fatal("symlink")
				}
			case "writable-parent":
				if os.Chmod(base, 0777) != nil {
					t.Fatal("chmod")
				}
			case "shared-installer":
				if os.Mkdir(filepath.Join(data, "installer"), 0755) != nil {
					t.Fatal("mkdir")
				}
			case "linked-installer":
				if os.Symlink(base, filepath.Join(data, "installer")) != nil {
					t.Fatal("symlink")
				}
			}
			if _, err := Stage(data, filepath.Join(data, "installer", id, "setup.json"), id, []byte(`{"valid":"opaque metadata"}`), false); err == nil {
				t.Fatal("unsafe ancestor accepted")
			}
			if _, err := os.Stat(filepath.Join(base, id)); !os.IsNotExist(err) {
				t.Fatal("symlink target mutated")
			}
		})
	}
}

func TestPreparationFlagOptIn(t *testing.T) {
	args := []string{"--stage", "--check", "--file", "/data/installer/setup.json"}
	if _, err := Parse(args); err == nil {
		t.Fatal("unqualified product accepted stage as ordinary setup")
	}
	if o, err := ParsePreparation(args); err != nil || !o.Stage || !o.Check {
		t.Fatal("prepared product refused flags", err)
	}
	for _, args := range [][]string{{"--stage", "--capabilities"}, {"--stage", "--restart"}, {"--stage"}} {
		if _, err := ParsePreparation(args); err == nil {
			t.Fatal("incompatible stage flags accepted")
		}
	}
}

func TestPreparationCredentialReferences(t *testing.T) {
	const file = "/data/installer/271333e2-c221-4601-b249-563b3d828530/setup.json"
	b := Common{Schema: Schema, Service: "kydrive", SetupID: "271333e2-c221-4601-b249-563b3d828530", SSO: &SSO{IssuerURL: "https://identity.example.test", ClientID: "drive", RedirectURI: "https://drive.example.test/api/sso/kysignon/callback", ClientSecretFile: "/data/client.secret", SCIMTokenFile: "/data/scim.secret"}}
	if err := b.ValidatePreparation("kydrive", "/api/sso/kysignon/callback", file); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, "relative.secret", "/data/../foreign.secret", "/data/control\nsecret", "/data/scim.secret"} {
		changed := b
		s := *b.SSO
		changed.SSO = &s
		changed.SSO.ClientSecretFile = path
		if err := changed.ValidatePreparation("kydrive", "/api/sso/kysignon/callback", file); err == nil {
			t.Fatal("unsafe or aliased credential reference accepted")
		}
	}
}
