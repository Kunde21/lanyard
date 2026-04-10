package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
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

func TestAuthorizationURLDoesNotRediscoverAfterNew(t *testing.T) {
	issuer := ""
	discoveryCalls := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		discoveryCalls++
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
		WithOIDCClient(metadata.NewClient(
			metadata.WithHTTPClient(ts.Client()),
			metadata.WithConformanceFreshDiscovery(true),
		)),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	rec := httptest.NewRecorder()
	if _, err := r.AuthorizationURL(context.Background(), rec, req); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	if discoveryCalls != 1 {
		t.Fatalf("expected 1 discovery call, got %d", discoveryCalls)
	}
}

func TestAuthorizationURL_IncludesAuthorizationDetailsWhenConfigured(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		WithScopes("accounts"),
		WithAuthorizationDetails([]map[string]any{
			{"type": "account_information"},
		}),
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
	if got := parsed.Query().Get("authorization_details"); got == "" {
		t.Fatal("authorization_details must be present")
	}
}

func TestAuthorizationURL_SetAuthorizationDetailsOverridesConfiguredValue(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		WithScopes("accounts"),
		WithAuthorizationDetails([]map[string]any{{"type": "account_information"}}),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	rec := httptest.NewRecorder()
	authURL, err := r.AuthorizationURL(context.Background(), rec, req, SetAuthorizationDetails([]map[string]any{{"type": "payment_initiation", "locations": []string{"https://rs.example.com"}}}))
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(authURL) failed: %v", err)
	}
	got := parsed.Query().Get("authorization_details")
	if got == "" {
		t.Fatal("authorization_details must be present")
	}
	if strings.Contains(got, "account_information") {
		t.Fatalf("authorization_details should be overridden, got %q", got)
	}
	if !strings.Contains(got, "payment_initiation") {
		t.Fatalf("authorization_details should include override, got %q", got)
	}
}

func TestAuthorizationURL_SetAuthParamAddsCustomQueryValue(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	authURL, err := r.AuthorizationURL(context.Background(), rec, req, SetAuthParam("resource", "urn:example:api"))
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(authURL) failed: %v", err)
	}
	if got := parsed.Query().Get("resource"); got != "urn:example:api" {
		t.Fatalf("resource mismatch: got %q", got)
	}
}

func TestAuthorizationURL_SignedRequestObjectByValueUsesRequestParameter(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client-123",
		"secret",
		"https://rp.test/callback",
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 "https://issuer.test",
			AuthorizationEndpoint:  "https://issuer.test/authorize",
			TokenEndpoint:          "https://issuer.test/token",
			JWKSURI:                "https://issuer.test/jwks",
			ResponseTypesSupported: []string{"code"},
		}}),
		WithClientKeyProvider(NewStaticClientKeyProvider(privateKey, "kid-1", "PS256", nil)),
		WithRequestMethod("signed_non_repudiation"),
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

	q := parsed.Query()
	if q.Get("request") == "" {
		t.Fatal("request must be present for signed request objects")
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want %q", q.Get("response_type"), "code")
	}
	if q.Get("client_id") != "client-123" {
		t.Fatalf("client_id = %q, want %q", q.Get("client_id"), "client-123")
	}
	if q.Get("scope") != "openid" {
		t.Fatalf("scope = %q, want %q", q.Get("scope"), "openid")
	}
	if q.Get("state") == "" {
		t.Fatal("state must be sent alongside the request object")
	}
	if q.Get("nonce") == "" {
		t.Fatal("nonce must be sent alongside the request object")
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("code_challenge must be sent alongside the request object")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want %q", q.Get("code_challenge_method"), "S256")
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

func TestAuthorizationURL_WithResponseMode(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		WithResponseMode("form_post"),
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
	if got := parsed.Query().Get("response_mode"); got != "form_post" {
		t.Fatalf("response_mode mismatch: got %q, want %q", got, "form_post")
	}
}

func TestAuthorizationURL_NoResponseModeByDefault(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if got := parsed.Query().Get("response_mode"); got != "" {
		t.Fatalf("response_mode should be empty by default, got %q", got)
	}
}

func TestAuthorizationURL_WithRequestURIMode(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	var storedURI string

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client-123",
		"secret",
		"https://rp.test/callback",
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 "https://issuer.test",
			AuthorizationEndpoint:  "https://issuer.test/authorize",
			TokenEndpoint:          "https://issuer.test/token",
			JWKSURI:                "https://issuer.test/jwks",
			ResponseTypesSupported: []string{"code"},
		}}),
		WithClientKeyProvider(NewStaticClientKeyProvider(privateKey, "kid-1", "PS256", nil)),
		WithRequestMethod("signed_non_repudiation"),
		WithRequestURIMode(func(signedJWT string) (string, error) {
			storedURI = "https://rp.localhost/request/stored-id-" + signedJWT[:10]
			return storedURI, nil
		}),
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

	q := parsed.Query()

	if q.Get("request_uri") == "" {
		t.Fatal("request_uri must be present when requestURIHandler is set")
	}
	if diff := cmp.Diff(storedURI, q.Get("request_uri")); diff != "" {
		t.Fatalf("request_uri mismatch (-want +got):\n%s", diff)
	}
	if q.Get("request") != "" {
		t.Fatal("request must not be present when requestURIHandler is set")
	}
	if q.Get("client_id") != "client-123" {
		t.Fatalf("client_id = %q, want %q", q.Get("client_id"), "client-123")
	}
	if q.Get("scope") != "openid" {
		t.Fatalf("scope = %q, want %q", q.Get("scope"), "openid")
	}
	if q.Get("state") != "" {
		t.Fatal("state must not be in query when using request_uri (it's in the request object)")
	}
	if q.Get("nonce") != "" {
		t.Fatal("nonce must not be in query when using request_uri (it's in the request object)")
	}
}

func TestAuthorizationURL_WithRequestURIMode_IncludesResponseMode(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client-123",
		"secret",
		"https://rp.test/callback",
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 "https://issuer.test",
			AuthorizationEndpoint:  "https://issuer.test/authorize",
			TokenEndpoint:          "https://issuer.test/token",
			JWKSURI:                "https://issuer.test/jwks",
			ResponseTypesSupported: []string{"code"},
		}}),
		WithClientKeyProvider(NewStaticClientKeyProvider(privateKey, "kid-1", "PS256", nil)),
		WithRequestMethod("signed_non_repudiation"),
		WithResponseMode("form_post"),
		WithRequestURIMode(func(signedJWT string) (string, error) {
			return "https://rp.localhost/request/test-id", nil
		}),
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

	q := parsed.Query()
	if q.Get("response_mode") != "form_post" {
		t.Fatalf("response_mode = %q, want %q", q.Get("response_mode"), "form_post")
	}
}

func TestAuthorizationURL_RequestURIHandlerNil_PreservesRequestByValue(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client-123",
		"secret",
		"https://rp.test/callback",
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 "https://issuer.test",
			AuthorizationEndpoint:  "https://issuer.test/authorize",
			TokenEndpoint:          "https://issuer.test/token",
			JWKSURI:                "https://issuer.test/jwks",
			ResponseTypesSupported: []string{"code"},
		}}),
		WithClientKeyProvider(NewStaticClientKeyProvider(privateKey, "kid-1", "PS256", nil)),
		WithRequestMethod("signed_non_repudiation"),
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

	q := parsed.Query()
	if q.Get("request") == "" {
		t.Fatal("request must be present when requestURIHandler is nil")
	}
	if q.Get("request_uri") != "" {
		t.Fatal("request_uri must not be present when requestURIHandler is nil")
	}
}
