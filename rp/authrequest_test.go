package rp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationURL(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		"client-123",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	rec := httptest.NewRecorder()
	authURL, err := r.AuthorizationURL(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(authURL) failed: %v", err)
	}
	if parsed.String() == "" {
		t.Fatalf("authorization URL is empty")
	}
	if parsed.Scheme != "https" {
		t.Fatalf("authorization URL scheme mismatch: %s", parsed.Scheme)
	}
	if parsed.Path != "/authorize" {
		t.Fatalf("authorization URL path mismatch: %s", parsed.Path)
	}

	q := parsed.Query()
	required := map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"redirect_uri":          "https://rp.test/callback",
		"scope":                 "openid",
		"code_challenge_method": "S256",
	}
	for key, want := range required {
		if got := q.Get(key); got != want {
			t.Fatalf("query %q mismatch: want %q got %q", key, want, got)
		}
	}

	for _, key := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(key) == "" {
			t.Fatalf("query %q must be present", key)
		}
	}

	state := q.Get("state")
	stored, ok, err := r.stateStore.LoadState(context.Background(), nil, state)
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}
	if !ok {
		t.Fatalf("state was not stored")
	}
	if stored.Correlation.Nonce != q.Get("nonce") {
		t.Fatalf("stored nonce mismatch")
	}
	if stored.Correlation.CodeVerifier == "" {
		t.Fatalf("stored code verifier missing")
	}
}

func providerMetadataJSON(issuer string) string {
	return fmt.Sprintf(`{
		"issuer": %q,
		"authorization_endpoint": %q,
		"jwks_uri": %q,
		"response_types_supported": ["code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256"]
	}`, issuer, issuer+"/authorize", issuer+"/jwks")
}
