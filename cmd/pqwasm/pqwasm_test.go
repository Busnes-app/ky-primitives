//go:build !js && go1.27

package main_test

import (
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWASMUnderNode builds pqwasm for js/wasm and runs testdata/*.check.js against it in
// Node, through Go's own lib/wasm/wasm_exec_node.js. Without node on PATH it skips, unless
// KY_REQUIRE_WASM=1 (CI's wasm job), where a skip would hide a broken browser build.
// It needs Go 1.27, where hybridsig exists; browsers build pqwasm with 1.27 too.
func TestWASMUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("KY_REQUIRE_WASM") == "1" {
			t.Fatal("KY_REQUIRE_WASM=1 but node is not on PATH")
		}
		t.Skip("node not on PATH")
	}
	wasm := filepath.Join(t.TempDir(), "pqwasm.wasm")
	build := exec.Command("go", "build", "-trimpath", "-o", wasm, ".")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("GOOS=js GOARCH=wasm go build: %v\n%s", err, out)
	}
	b, err := os.ReadFile(wasm)
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	w.Write(b)
	w.Close()
	t.Logf("pqwasm.wasm: %d bytes, %d gzipped (%s)", len(b), gz.Len(), runtime.Version())

	execNode := filepath.Join(runtime.GOROOT(), "lib", "wasm", "wasm_exec_node.js")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	run := exec.Command(node, "testdata/run.js", execNode, wasm, root)
	// wasm_exec passes the environment to Go. Go has no FIPS 140 mode on js/wasm and panics
	// under CI's GODEBUG=fips140=on leg; a browser never sets GODEBUG, so drop it here.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GODEBUG=") {
			run.Env = append(run.Env, kv)
		}
	}
	out, err := run.CombinedOutput()
	t.Logf("%s\n%s", node, out)
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	if !bytes.Contains(out, []byte("checks passed")) {
		t.Fatal("node exited without running the checks")
	}
}
