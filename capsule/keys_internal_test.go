package capsule

import (
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// testRecoveryKey is a fresh keypair per test. Generation is fast enough that sharing one
// across tests would only add a way for them to interfere.
func testRecoveryKey(t *testing.T) recoverykey.PrivateKey {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
