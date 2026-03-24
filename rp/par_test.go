package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/oidc"
)

func TestAuthorizationURL_UsesClientAssertionFormFieldsForPAR(t *testing.T) {
	var gotBody string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(body) failed: %v", err)
		}
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:test:request-uri", "expires_in": 90})
	}))
	defer ts.Close()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerWithAuthorizationAndPAR(ts.URL, "private_key_jwt")),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(privateKey, "kid-1", "PS256", nil)),
		WithRequirePAR(true),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	w := httptest.NewRecorder()
	if _, err := r.AuthorizationURL(context.Background(), w, req); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("ParseQuery(body) failed: %v", err)
	}
	assertion := values.Get("client_assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion is not a compact JWT: %q", assertion)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("DecodeString(claims) failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("Unmarshal(claims) failed: %v", err)
	}
	if got := values.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("client_assertion_type = %q", got)
	}
	if got := claims["aud"]; got != "https://issuer.test" {
		t.Fatalf("client_assertion aud = %#v, want issuer audience", got)
	}
	if authz := values.Get("client_id"); authz != "client" {
		t.Fatalf("client_id = %q, want client", authz)
	}
}

func TestAuthorizationURL_UsesMTLSAliasForPARWhenTLSClientAuth(t *testing.T) {
	var gotPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:test:request-uri", "expires_in": 90})
	}))
	defer ts.Close()

	provider := providerWithAuthorizationAndPAR(ts.URL+"/par", "tls_client_auth")
	provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint = ts.URL + "/mtls/par"

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
		WithRequirePAR(true),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	w := httptest.NewRecorder()
	if _, err := r.AuthorizationURL(context.Background(), w, req); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	if gotPath != "/mtls/par" {
		t.Fatalf("PAR path = %q, want /mtls/par", gotPath)
	}
}

func providerWithAuthorizationAndPAR(parEndpoint string, methods ...string) oidc.ProviderMetadata {
	provider := providerForAuthMethods(methods...)
	provider.AuthorizationEndpoint = "https://issuer.test/authorize"
	provider.PushedAuthorizationRequestEndpoint = parEndpoint
	return provider
}
