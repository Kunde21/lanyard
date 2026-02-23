package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestValidateIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		issuer,
		"client-id",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	baseClaims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}

	goodToken := signIDToken(t, key, "kid-1", baseClaims)
	if _, err := r.validateIDToken(context.Background(), goodToken, "nonce-123"); err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}

	tests := []struct {
		name   string
		claims map[string]any
		nonce  string
		kid    string
	}{
		{name: "issuer mismatch", claims: cloneClaims(baseClaims, "iss", "https://other.test"), nonce: "nonce-123", kid: "kid-1"},
		{name: "audience mismatch", claims: cloneClaims(baseClaims, "aud", []string{"other-client"}), nonce: "nonce-123", kid: "kid-1"},
		{name: "expired", claims: cloneClaims(baseClaims, "exp", now.Add(-10*time.Minute).Unix()), nonce: "nonce-123", kid: "kid-1"},
		{name: "iat too far future", claims: cloneClaims(baseClaims, "iat", now.Add(10*time.Minute).Unix()), nonce: "nonce-123", kid: "kid-1"},
		{name: "nonce mismatch", claims: cloneClaims(baseClaims, "nonce", "wrong"), nonce: "nonce-123", kid: "kid-1"},
		{name: "azp required", claims: cloneClaims(baseClaims, "aud", []string{"client-id", "other"}), nonce: "nonce-123", kid: "kid-1"},
		{name: "azp mismatch", claims: cloneClaims(cloneClaims(baseClaims, "aud", []string{"client-id", "other"}), "azp", "other"), nonce: "nonce-123", kid: "kid-1"},
		{name: "unknown kid", claims: baseClaims, nonce: "nonce-123", kid: "other-kid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signIDToken(t, key, tt.kid, tt.claims)
			_, err := r.validateIDToken(context.Background(), token, tt.nonce)
			if err == nil {
				t.Fatalf("validateIDToken() expected error")
			}
		})
	}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{KeyID: kid, Key: key}}, nil)
	if err != nil {
		t.Fatalf("NewSigner() failed: %v", err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize() failed: %v", err)
	}

	return raw
}

func cloneClaims(src map[string]any, key string, value any) map[string]any {
	copy := make(map[string]any, len(src)+1)
	for k, v := range src {
		copy[k] = v
	}
	copy[key] = value
	return copy
}
