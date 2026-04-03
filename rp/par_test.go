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
	"github.com/google/go-cmp/cmp"
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
		WithSenderConstrain("mtls"),
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

func TestAuthorizationURL_OAuthOnlySkipsMTLSAliasForDerivedPAR(t *testing.T) {
	var gotPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:test:request-uri", "expires_in": 90})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		ts.URL,
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithScopes("accounts"),
		WithAuthMethod(AuthMethodTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
		WithSenderConstrain("mtls"),
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

	if gotPath != "/par" {
		t.Fatalf("PAR path = %q, want /par", gotPath)
	}
}

func TestPushAuthorizationRequest_RetriesWithDpopNonce(t *testing.T) {
	key := testRSAKey(t)
	requests := 0
	var firstProof string
	var secondProof string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstProof = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondProof = proof
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:test:request-uri", "expires_in": 90})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerWithAuthorizationAndPAR(ts.URL, "private_key_jwt")),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain("dpop"),
		WithRequirePAR(true),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	params := r.buildAuthorizationParameters("state", "nonce", "verifier", "challenge", "")
	parResp, err := r.pushAuthorizationRequest(context.Background(), params)
	if err != nil {
		t.Fatalf("pushAuthorizationRequest() failed: %v", err)
	}
	if parResp.RequestURI != "urn:test:request-uri" {
		t.Fatalf("request_uri = %q, want urn:test:request-uri", parResp.RequestURI)
	}

	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("request count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(true, firstProof != ""); diff != "" {
		t.Fatalf("first DPoP proof missing (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(true, secondProof != ""); diff != "" {
		t.Fatalf("second DPoP proof missing (-want +got):\n%s", diff)
	}
	if firstProof == secondProof {
		t.Fatalf("expected second proof to differ from first proof (should include new nonce)")
	}
}

func TestPushAuthorizationRequest_IncludesAuthorizationDetailsWhenConfigured(t *testing.T) {
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

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerWithAuthorizationAndPAR(ts.URL)),
		WithRequirePAR(true),
		WithScopes("accounts"),
		WithAuthorizationDetails([]map[string]any{
			{"type": "account_information"},
		}),
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
	if got := values.Get("authorization_details"); got == "" {
		t.Fatal("authorization_details must be present in PAR body")
	}
}

func TestPushAuthorizationRequest_SetAuthorizationDetailsOverridesConfiguredValue(t *testing.T) {
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

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerWithAuthorizationAndPAR(ts.URL)),
		WithRequirePAR(true),
		WithScopes("accounts"),
		WithAuthorizationDetails([]map[string]any{{"type": "account_information"}}),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	w := httptest.NewRecorder()
	if _, err := r.AuthorizationURL(context.Background(), w, req, SetAuthorizationDetails([]map[string]any{{"type": "payment_initiation"}})); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("ParseQuery(body) failed: %v", err)
	}
	got := values.Get("authorization_details")
	if got == "" {
		t.Fatal("authorization_details must be present in PAR body")
	}
	if strings.Contains(got, "account_information") {
		t.Fatalf("authorization_details should be overridden, got %q", got)
	}
	if !strings.Contains(got, "payment_initiation") {
		t.Fatalf("authorization_details should include override, got %q", got)
	}
}

func providerWithAuthorizationAndPAR(parEndpoint string, methods ...string) oidc.ProviderMetadata {
	provider := providerForAuthMethods(methods...)
	provider.AuthorizationEndpoint = "https://issuer.test/authorize"
	provider.PushedAuthorizationRequestEndpoint = parEndpoint
	return provider
}
