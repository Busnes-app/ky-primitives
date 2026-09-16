package derive_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/Busnes-app/ky-primitives/derive"
)

func TestAuthSecretContextMatchesAuthSecret(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	const pw = "correct horse battery staple"

	want, err := derive.AuthSecret(pw, salt, 100_000, "kynotes/auth/v1")
	if err != nil {
		t.Fatalf("AuthSecret: %v", err)
	}
	got, err := derive.AuthSecretContext(context.Background(), pw, salt, 100_000, "kynotes/auth/v1")
	if err != nil {
		t.Fatalf("AuthSecretContext: %v", err)
	}
	if got != want {
		t.Errorf("AuthSecretContext = %q, AuthSecret = %q; the two must not diverge", got, want)
	}
}

func TestConcurrencyBudgetIsVisible(t *testing.T) {
	if derive.MaxConcurrent < 1 {
		t.Errorf("MaxConcurrent = %d, want a positive slot count", derive.MaxConcurrent)
	}
}
