package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestHandleCallbackValidation(t *testing.T) {
	r, err := New("https://issuer.test", "client", "secret", "https://rp.test/callback")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if _, err := r.HandleCallback(context.Background(), "code", ""); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("missing state should return ErrInvalidState, got %v", err)
	}
	if _, err := r.HandleCallback(context.Background(), "", "state"); !errors.Is(err, ErrMissingCode) {
		t.Fatalf("missing code should return ErrMissingCode, got %v", err)
	}
	if _, err := r.HandleCallback(context.Background(), "code", "state"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown state should return ErrInvalidState, got %v", err)
	}
}

func TestHandleCallbackFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	issuer := ""
	now := time.Now().UTC()

	var tokenStatus int
	var tokenBody string
	var userInfoBody string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			if tokenStatus != 0 {
				w.WriteHeader(tokenStatus)
				_, _ = w.Write([]byte(tokenBody))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenBody))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(userInfoBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

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

	r.stateStore.Save("state", StateData{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now})
	tokenStatus = http.StatusBadRequest
	tokenBody = `{"error":"invalid_grant"}`
	if _, err := r.HandleCallback(context.Background(), "code", "state"); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("token error should return ErrTokenExchangeFailed, got %v", err)
	}

	r.stateStore.Save("state", StateData{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now})
	tokenStatus = 0
	badClaims := map[string]any{"iss": "https://wrong.test", "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
	tokenBody = `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", badClaims) + `"}`
	userInfoBody = `{"sub":"sub-123"}`
	if _, err := r.HandleCallback(context.Background(), "code", "state"); !errors.Is(err, ErrIDTokenValidationFailed) {
		t.Fatalf("invalid id token should return ErrIDTokenValidationFailed, got %v", err)
	}

	r.stateStore.Save("state", StateData{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now})
	goodClaims := map[string]any{"iss": issuer, "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
	tokenBody = `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", goodClaims) + `"}`
	userInfoBody = `{"sub":"other"}`
	if _, err := r.HandleCallback(context.Background(), "code", "state"); !errors.Is(err, ErrUserInfoValidationFailed) {
		t.Fatalf("userinfo mismatch should return ErrUserInfoValidationFailed, got %v", err)
	}
}

func providerMetadataJSONWithEndpoints(issuer string) string {
	return `{"issuer":"` + issuer + `","authorization_endpoint":"` + issuer + `/authorize","token_endpoint":"` + issuer + `/token","userinfo_endpoint":"` + issuer + `/userinfo","jwks_uri":"` + issuer + `/jwks","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`
}
