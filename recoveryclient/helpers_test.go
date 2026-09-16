package recoveryclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

type memSettings map[string]string

func (m memSettings) Get(k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (m memSettings) Set(k, v string) error { m[k] = v; return nil }
func (m memSettings) Delete(k string) error { delete(m, k); return nil }

func testKey(t *testing.T) (recoverykey.PrivateKey, RecoveryKey) {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return priv, RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}
}

func testSealer(t *testing.T) Sealer {
	t.Helper()
	s, err := NewAESGCMSealer(make([]byte, 32), "test:setting:kyrecovery_token")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pair pins a key and stores a pairing, the way the product's pair handler does.
func pair(t *testing.T, dataDir string, s Settings) recoverykey.PrivateKey {
	t.Helper()
	priv, k := testKey(t)
	if err := StoreRecoveryKey(dataDir, s, k); err != nil {
		t.Fatal(err)
	}
	if err := StorePairing(s, testSealer(t), "https://recovery.example.test", "kyrec_live_t"); err != nil {
		t.Fatal(err)
	}
	return priv
}

func testPayload() Payload {
	return Payload{ServiceName: "Svc", AppVersion: "1.0.0", Files: []File{
		{Path: "data/app.db", Data: []byte("SQLite format 3\x00 rows"), Mode: 0600},
		{Path: "data/secret.key", Data: make([]byte, 32), Mode: 0600},
	}, Dependencies: map[string]any{}, VerificationRecipe: map[string]any{}}
}

// fakeDepositor is kyrecovery's side of a deposit: it answers with the receipt the real
// server would for the bytes it received, or with err.
type fakeDepositor struct {
	url, token string
	container  []byte
	err        error
	calls      int
}

func (f *fakeDepositor) Deposit(_ context.Context, serverURL, apiToken string, container []byte) (Receipt, error) {
	f.calls++
	f.url, f.token, f.container = serverURL, apiToken, container
	if f.err != nil {
		return Receipt{}, f.err
	}
	m, err := capsule.ReadUnverifiedManifest(container)
	if err != nil {
		return Receipt{}, err
	}
	sum := sha256.Sum256(container)
	return Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now().UTC()}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
