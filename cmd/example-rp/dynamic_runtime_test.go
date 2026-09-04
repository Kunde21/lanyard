package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

// dynamicRegistrationIssuer serves discovery + registration endpoints for the
// example RP's dynamic runtime tests.
func dynamicRegistrationIssuer(t *testing.T, registrations *[]rp.ClientMetadata) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			issuer := "https://" + r.Host + "/test/a/alias-dyn"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/jwks",
				"registration_endpoint":                 issuer + "/register",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			})
		case strings.HasSuffix(r.URL.Path, "/register"):
			body, _ := io.ReadAll(r.Body)
			var meta rp.ClientMetadata
			_ = json.Unmarshal(body, &meta)
			mu.Lock()
			*registrations = append(*registrations, meta)
			count := len(*registrations)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id":     "dyn-client-" + string(rune('0'+count)),
				"client_secret": "dyn-secret-" + string(rune('0'+count)),
				"redirect_uris": meta.RedirectURIs,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRuntimeRegistryRegisterAllowsDynamicWithoutClientID(t *testing.T) {
	registry := newRuntimeRegistry()

	err := registry.Register(rpRuntimeConfig{Alias: "a1", RedirectURI: "https://rp.test/callback"})
	if err == nil || !strings.Contains(err.Error(), "client_id is required") {
		t.Fatalf("Register() without client_id error = %v, want client_id required", err)
	}

	err = registry.Register(rpRuntimeConfig{
		Alias:                     "a1",
		RedirectURI:               "https://rp.test/callback",
		DynamicClientRegistration: true,
	})
	if err != nil {
		t.Fatalf("Register() dynamic without client_id failed: %v", err)
	}
}

func TestEnsureDynamicClientRegistrationPerModule(t *testing.T) {
	resetDynamicRegistrations()
	var registrations []rp.ClientMetadata
	server := dynamicRegistrationIssuer(t, &registrations)

	// Point the runtime at the test issuer; the registration request flows to
	// the test server via newRPHTTPClient, which must trust its self-signed
	// cert. RP_INSECURE_TLS is honored by newRPHTTPClient; set it for the test.
	t.Setenv("RP_INSECURE_TLS", "true")

	cfg := rpRuntimeConfig{
		Alias:                     "alias-dyn",
		Issuer:                    server.URL + "/test/a/alias-dyn",
		RedirectURI:               "https://rp.localhost/callback/alias-dyn",
		DynamicClientRegistration: true,
	}

	clientID, clientSecret, provider, err := ensureDynamicClientRegistration(context.Background(), cfg, "module-a")
	if err != nil {
		t.Fatalf("ensureDynamicClientRegistration() failed: %v", err)
	}
	if diff := cmp.Diff("dyn-client-1", clientID); diff != "" {
		t.Fatalf("clientID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("dyn-secret-1", clientSecret); diff != "" {
		t.Fatalf("clientSecret mismatch (-want +got):\n%s", diff)
	}

	// Same module window: reuse, no new registration.
	clientID2, _, _, err := ensureDynamicClientRegistration(context.Background(), cfg, "module-a")
	if err != nil {
		t.Fatalf("ensureDynamicClientRegistration() same module failed: %v", err)
	}
	if diff := cmp.Diff(clientID, clientID2); diff != "" {
		t.Fatalf("same module clientID mismatch (-want +got):\n%s", diff)
	}
	if len(registrations) != 1 {
		t.Fatalf("registrations = %d, want 1", len(registrations))
	}
	if provider == nil {
		t.Fatal("provider = nil, want cached provider metadata")
	}

	// Callback (no module name): reuse latest.
	clientID3, _, provider3, err := ensureDynamicClientRegistration(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("ensureDynamicClientRegistration() callback failed: %v", err)
	}
	if diff := cmp.Diff(clientID, clientID3); diff != "" {
		t.Fatalf("callback clientID mismatch (-want +got):\n%s", diff)
	}
	if len(registrations) != 1 {
		t.Fatalf("registrations after callback = %d, want 1", len(registrations))
	}
	if provider3 == nil {
		t.Fatal("provider3 = nil, want cached provider on callback reuse")
	}

	// New module window: fresh registration with fresh credentials.
	clientID4, clientSecret4, _, err := ensureDynamicClientRegistration(context.Background(), cfg, "module-b")
	if err != nil {
		t.Fatalf("ensureDynamicClientRegistration() new module failed: %v", err)
	}
	if diff := cmp.Diff("dyn-client-2", clientID4); diff != "" {
		t.Fatalf("new module clientID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("dyn-secret-2", clientSecret4); diff != "" {
		t.Fatalf("new module clientSecret mismatch (-want +got):\n%s", diff)
	}
	if len(registrations) != 2 {
		t.Fatalf("registrations after new module = %d, want 2", len(registrations))
	}

	// Registration metadata shape (RFC 7591) the suite mock validates.
	last := registrations[len(registrations)-1]
	if len(last.RedirectURIs) != 1 || last.RedirectURIs[0] != cfg.RedirectURI {
		t.Fatalf("registered redirect_uris = %v, want [%s]", last.RedirectURIs, cfg.RedirectURI)
	}
	if last.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("registered token_endpoint_auth_method = %q, want client_secret_basic", last.TokenEndpointAuthMethod)
	}
}

func TestApplyRuntimeConfigDynamicUsesIssuedCredentials(t *testing.T) {
	resetDynamicRegistrations()
	var registrations []rp.ClientMetadata
	server := dynamicRegistrationIssuer(t, &registrations)
	t.Setenv("RP_INSECURE_TLS", "true")

	registry := newRuntimeRegistry()
	cfg := rpRuntimeConfig{
		Alias:                     "alias-dyn",
		Issuer:                    server.URL + "/test/a/alias-dyn",
		RedirectURI:               "https://rp.localhost/callback/alias-dyn",
		DynamicClientRegistration: true,
		Scopes:                    []string{"openid"},
	}
	if err := registry.Register(cfg); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	resolved, err := applyRuntimeConfig(resolvedRPRequest{
		issuer: cfg.Issuer,
		scopes: []string{"openid"},
	}, cfg, "module-a")
	if err != nil {
		t.Fatalf("applyRuntimeConfig() failed: %v", err)
	}
	if diff := cmp.Diff("dyn-client-1", resolved.clientID); diff != "" {
		t.Fatalf("resolved clientID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("dyn-secret-1", resolved.clientSecret); diff != "" {
		t.Fatalf("resolved clientSecret mismatch (-want +got):\n%s", diff)
	}
}
