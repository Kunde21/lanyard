package rp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateDPoPProof_IncludesExpectedClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	r := &RP{
		clientKeyProvider:  NewStaticClientKeyProvider(key, "kid-1", "PS256", nil),
		resolvedAuthMethod: AuthMethodPrivateKeyJWT,
		randReader:         bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)),
		now:                func() time.Time { return time.Unix(1712100000, 0).UTC() },
	}

	proof, err := r.generateDPoPProof(http.MethodPost, "https://issuer.test/token", "access-token", "nonce-123")
	if err != nil {
		t.Fatalf("generateDPoPProof() failed: %v", err)
	}

	header, payload := decodeProofParts(t, proof)

	if diff := cmp.Diff("dpop+jwt", header.Typ); diff != "" {
		t.Fatalf("typ mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(http.MethodPost, payload.HTM); diff != "" {
		t.Fatalf("htm mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://issuer.test/token", payload.HTU); diff != "" {
		t.Fatalf("htu mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("nonce-123", payload.Nonce); diff != "" {
		t.Fatalf("nonce mismatch (-want +got):\n%s", diff)
	}
	if payload.ATH == "" {
		t.Fatalf("expected ath to be set")
	}
	if payload.JTI == "" {
		t.Fatalf("expected jti to be set")
	}
	if payload.IAT == 0 {
		t.Fatalf("expected iat to be set")
	}
}

func decodeProofParts(t *testing.T, proof string) (dpopHeader, dpopPayload) {
	t.Helper()

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof should have 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header dpopHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var payload dpopPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	return header, payload
}
