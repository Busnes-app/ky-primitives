package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/auditchain"
)

func buildChain(t *testing.T, key []byte, n int) (string, auditchain.Anchor) {
	t.Helper()
	chain, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for i := 0; i < n; i++ {
		rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, "auth.login", "user1")
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("Encode failed: %v", err)
		}
	}
	return sb.String(), chain.Anchor()
}

func TestVerifiesAChainFromLines(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	lines, anchor := buildChain(t, key, 3)

	if err := auditchain.VerifyStream(key, records(strings.NewReader(lines)), anchor); err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
}

func TestTruncatedInputIsReported(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	lines, anchor := buildChain(t, key, 3)
	kept := strings.SplitAfter(lines, "\n")[0]

	err := auditchain.VerifyStream(key, records(strings.NewReader(kept)), anchor)
	if !errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
}

// A malformed line must fail the verification, not quietly end the walk and let a
// half-read log look like a complete short one.
func TestMalformedLineFailsRatherThanTruncates(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	lines, anchor := buildChain(t, key, 3)
	broken := strings.SplitAfter(lines, "\n")[0] + "{not json\n"

	err := auditchain.VerifyStream(key, records(strings.NewReader(broken)), anchor)
	if err == nil || errors.Is(err, auditchain.ErrTruncated) {
		t.Fatalf("want a read failure, got %v", err)
	}
}

func TestParseAnchor(t *testing.T) {
	a, err := parseAnchor("42:9f3c")
	if err != nil || a.Count != 42 || a.Hash != "9f3c" {
		t.Fatalf("parseAnchor = %+v, %v", a, err)
	}
	if _, err := parseAnchor("nope"); err == nil {
		t.Fatal("anchor without a colon should be rejected")
	}
}

func TestLoadKeyRequiresAFile(t *testing.T) {
	if _, err := loadKey("0123456789abcdef"); err == nil {
		t.Fatal("inline key was accepted")
	}
	path := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(path, []byte("0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := loadKey("@" + path)
	if err != nil || len(key) != 8 {
		t.Fatalf("file key = %x, %v", key, err)
	}
}
