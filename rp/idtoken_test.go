package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		context.Background(),
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
	if _, err := r.validateIDToken(context.Background(), goodToken, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}

	missingKIDToken := signIDToken(t, key, "", baseClaims)
	if _, err := r.validateIDToken(context.Background(), missingKIDToken, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() with single signing key and missing kid failed: %v", err)
	}

	unsignedToken := signUnsecuredIDToken(t, baseClaims)

	rNoUnsecured := &RP{
		issuer:                 issuer,
		clientID:               "client-id",
		httpClient:             ts.Client(),
		oidcClient:             r.oidcClient,
		now:                    func() time.Time { return now },
		allowUnsecuredIDTokens: false,
	}
	if _, err := rNoUnsecured.validateIDToken(context.Background(), unsignedToken, "nonce-123", issuer+"/jwks", nil); err == nil {
		t.Fatalf("validateIDToken() with alg=none and allowUnsecuredIDTokens=false expected error")
	}

	rAllow := &RP{
		issuer:                 issuer,
		clientID:               "client-id",
		httpClient:             ts.Client(),
		oidcClient:             r.oidcClient,
		now:                    func() time.Time { return now },
		allowUnsecuredIDTokens: true,
	}
	if _, err := rAllow.validateIDToken(context.Background(), unsignedToken, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() with alg=none and allowUnsecuredIDTokens=true failed: %v", err)
	}

	rFAPI := &RP{
		issuer:                 issuer,
		clientID:               "client-id",
		httpClient:             ts.Client(),
		oidcClient:             r.oidcClient,
		now:                    func() time.Time { return now },
		fapiProfile:            fapiProfilePlainFAPI,
		allowUnsecuredIDTokens: true,
	}
	if _, err := rFAPI.validateIDToken(context.Background(), unsignedToken, "nonce-123", issuer+"/jwks", nil); err == nil {
		t.Fatalf("validateIDToken() with alg=none and FAPI profile expected error")
	}

	tests := []struct {
		name   string
		claims map[string]any
		nonce  string
		kid    string
	}{
		{name: "issuer mismatch", claims: cloneClaims(baseClaims, "iss", "https://other.test"), nonce: "nonce-123", kid: "kid-1"},
		{name: "audience mismatch", claims: cloneClaims(baseClaims, "aud", []string{"other-client"}), nonce: "nonce-123", kid: "kid-1"},
		{name: "missing exp", claims: removeClaim(baseClaims, "exp"), nonce: "nonce-123", kid: "kid-1"},
		{name: "missing iat", claims: removeClaim(baseClaims, "iat"), nonce: "nonce-123", kid: "kid-1"},
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
			_, err := r.validateIDToken(context.Background(), token, tt.nonce, issuer+"/jwks", nil)
			if err == nil {
				t.Fatalf("validateIDToken() expected error")
			}
		})
	}
}

func TestValidateIDTokenRejectsAlgorithmNotInProviderList(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":   "https://issuer.test",
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}

	token := signIDTokenWithAlg(t, key, "kid-1", claims, jose.RS256)

	r := &RP{
		issuer:     "https://issuer.test",
		clientID:   "client-id",
		httpClient: http.DefaultClient,
		now:        func() time.Time { return now },
	}

	_, err = r.validateIDToken(context.Background(), token, "nonce-123", "", []string{"ES256"})
	if err == nil {
		t.Fatalf("validateIDToken() expected error when algorithm not in provider list")
	}
	if !strings.Contains(err.Error(), "not in provider's advertised algorithms") {
		t.Fatalf("validateIDToken() error = %v, want algorithm mismatch error", err)
	}
}

func TestValidateIDTokenMissingKIDWithMultipleSigningKeysTriesAllKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(key1) failed: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(key2) failed: %v", err)
	}

	pub1 := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key1.PublicKey}
	pub2 := jose.JSONWebKey{KeyID: "kid-2", Algorithm: string(jose.RS256), Use: "sig", Key: &key2.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub1, pub2}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
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

	claims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}

	token := signIDToken(t, key1, "", claims)
	if _, err := r.validateIDToken(context.Background(), token, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signIDTokenWithAlg(t, key, kid, claims, jose.RS256)
}

func signIDTokenWithAlg(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any, alg jose.SignatureAlgorithm) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{KeyID: kid, Key: key}}, nil)
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

func removeClaim(src map[string]any, key string) map[string]any {
	copy := make(map[string]any, len(src))
	for k, v := range src {
		if k == key {
			continue
		}
		copy[k] = v
	}
	return copy
}

func signUnsecuredIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "none"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("Marshal(header) failed: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal(claims) failed: %v", err)
	}

	enc := base64.RawURLEncoding
	return enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payloadJSON) + "."
}
