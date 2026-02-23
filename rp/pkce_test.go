package rp

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	got, err := generateCodeVerifier(strings.NewReader(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatalf("generateCodeVerifier() failed: %v", err)
	}
	if err := validateCodeVerifier(got); err != nil {
		t.Fatalf("validateCodeVerifier() failed: %v", err)
	}
}

func TestCodeChallengeS256_KnownVector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	got, err := codeChallengeS256(verifier)
	if err != nil {
		t.Fatalf("codeChallengeS256() failed: %v", err)
	}
	if got != want {
		t.Fatalf("codeChallengeS256() mismatch: want %q got %q", want, got)
	}
}

func TestCodeChallengeS256_InvalidVerifier(t *testing.T) {
	_, err := codeChallengeS256("bad space")
	if err == nil {
		t.Fatalf("codeChallengeS256() expected error")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error mismatch: got %v", err)
	}
}
