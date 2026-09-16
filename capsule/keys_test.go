package capsule_test

import (
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

func testRecoveryKey(t *testing.T) recoverykey.PrivateKey {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
