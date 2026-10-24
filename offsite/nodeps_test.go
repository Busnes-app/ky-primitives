package offsite

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var allowedModules = map[string]bool{
	"github.com/cloudsoda/go-smb2": true,
	"github.com/pkg/sftp":          true,
	"golang.org/x/crypto":          true,
}

var moduleLine = regexp.MustCompile(`^([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+)\s+v`)

func TestDependencyBudget(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "replace ") {
			t.Fatalf("go.mod:%d: replace directives are not allowed", i+1)
		}
		text = strings.TrimPrefix(text, "require ")
		if match := moduleLine.FindStringSubmatch(text); match != nil && !strings.Contains(text, "// indirect") && !allowedModules[match[1]] {
			t.Errorf("go.mod:%d requires %s outside the dependency budget", i+1, match[1])
		}
	}
}
