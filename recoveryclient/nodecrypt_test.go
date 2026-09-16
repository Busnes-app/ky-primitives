package recoveryclient

import (
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
)

// The lib itself must obey the boundary it hands products: only Restore combines shares and
// opens a capsule sealed to the suite key; Drill opens one sealed to a key it made and dropped.
func TestNothingOutsideRestoreAndDrillDecrypts(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("recoveryclient", "restore.go"): {"Restore"},
		filepath.Join("recoveryclient", "drill.go"):   {"Drill"},
	})
}
