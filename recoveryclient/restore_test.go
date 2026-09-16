package recoveryclient

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky-primitives/shamir"
)

func sealedFixture(t *testing.T) (string, []string) {
	t.Helper()
	priv, k := testKey(t)
	shares, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := Seal(testPayload(), k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "x.kycap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, s := range shares {
		lines = append(lines, s.String())
	}
	return path, lines
}

func TestRestoreRoundTrip(t *testing.T) {
	path, shares := sealedFixture(t)
	target := filepath.Join(t.TempDir(), "out")
	var out bytes.Buffer
	if err := Restore(path, target, "Svc", shares[:2], &out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(target, "data", "app.db")); err != nil || len(b) == 0 {
		t.Fatalf("restored file: %v", err)
	}
	if !strings.Contains(out.String(), "service:      Svc") || !strings.Contains(out.String(), "recovery key:") {
		t.Errorf("manifest not printed: %s", out.String())
	}
	if err := Restore(path, target, "Svc", shares[:2], &out); err == nil {
		t.Error("restored into a non-empty directory")
	}
}

func TestRestoreNeedsThreshold(t *testing.T) {
	path, shares := sealedFixture(t)
	err := Restore(path, filepath.Join(t.TempDir(), "out"), "Svc", shares[:1], &bytes.Buffer{})
	if err == nil || !errors.Is(err, shamir.ErrNotEnoughShares) && !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("%v", err)
	}
}

func TestRestoreRefusesOtherServiceBeforeCombine(t *testing.T) {
	path, _ := sealedFixture(t)
	err := Restore(path, filepath.Join(t.TempDir(), "out"), "Other", []string{"garbage"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `for service "Svc"`) {
		t.Fatalf("%v", err)
	}
}

func TestReadSharesSkipsBlankLines(t *testing.T) {
	shares, err := ReadShares(strings.NewReader("\n ky2-a \n\nky2-b\n"))
	if err != nil || len(shares) != 2 || shares[0] != "ky2-a" {
		t.Fatalf("%v %v", shares, err)
	}
}

func TestRestorePrintsOnlyPrintableManifestFields(t *testing.T) {
	priv, k := testKey(t)
	shares, _ := recoverykey.Split(priv, 2, 3)
	p := testPayload()
	p.AppVersion = "1.0\x1b[2J\x07evil"
	raw, _, err := Seal(p, k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "x.kycap")
	_ = os.WriteFile(path, raw, 0600)
	var out bytes.Buffer
	if err := Restore(path, filepath.Join(t.TempDir(), "out"), "Svc", []string{shares[0].String(), shares[1].String()}, &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.String() {
		if r != '\n' && r != ' ' && !unicode.IsPrint(r) {
			t.Fatalf("control rune %q reached the operator's terminal: %q", r, out.String())
		}
	}
}
