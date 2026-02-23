package rp

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	pkceVerifierMinLength = 43
	pkceVerifierMaxLength = 128
)

func generateCodeVerifier(reader io.Reader) (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", fmt.Errorf("failed to read random verifier bytes: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(buf)
	if err := validateCodeVerifier(verifier); err != nil {
		return "", err
	}

	return verifier, nil
}

func codeChallengeS256(verifier string) (string, error) {
	if err := validateCodeVerifier(verifier); err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func validateCodeVerifier(verifier string) error {
	if len(verifier) < pkceVerifierMinLength || len(verifier) > pkceVerifierMaxLength {
		return fmt.Errorf("%w: code_verifier length must be between %d and %d", ErrInvalidConfiguration, pkceVerifierMinLength, pkceVerifierMaxLength)
	}

	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for _, r := range verifier {
		if !strings.ContainsRune(allowed, r) {
			return fmt.Errorf("%w: code_verifier contains invalid character %q", ErrInvalidConfiguration, r)
		}
	}

	return nil
}
