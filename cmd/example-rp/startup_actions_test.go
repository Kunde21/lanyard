package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

func TestExecuteStartupAction_FullFlowPreparesAuthorizationURL(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"issuer": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q,
				"jwks_uri": %q,
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"]
			}`, serverURL, serverURL+"authorize", serverURL+"token", serverURL+"jwks")
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL + "/"

	cfg := rpRuntimeConfig{
		Alias:         "test",
		ClientID:      "client-id",
		ClientSecret:  "secret",
		RedirectURI:   "https://rp.localhost/callback/test",
		Issuer:        serverURL,
		StartupAction: "full_flow",
	}
	resolved := resolvedRPRequest{
		issuer:            serverURL,
		clientID:          "client-id",
		clientSecret:      "secret",
		redirectURI:       "https://rp.localhost/callback/test",
		startupAction:     startupActionFullFlow,
		stateStore:        sharedStateStore,
		userInfoTransport: rp.UserInfoTokenTransportHeader,
		scopes:            []string{"openid"},
		profile:           "oidc",
		discoveryMode:     "oidc",
	}
	startup, err := executeStartupAction(context.Background(), cfg, resolved)
	if err != nil {
		t.Fatalf("executeStartupAction for full_flow should return nil, got err: %v", err)
	}
	if startup.AuthorizationURL == "" {
		t.Fatal("expected authorization url for full_flow startup")
	}
	if !strings.Contains(startup.AuthorizationURL, "client_id=client-id") {
		t.Fatalf("authorization url = %q, want client_id", startup.AuthorizationURL)
	}
	if len(startup.Cookies) == 0 {
		t.Fatal("expected startup cookies for full_flow startup")
	}
}

func TestExecuteStartupAction_DiscoveryOnlyDiscoversProvider(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	discoveryCalled := false
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryCalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"issuer": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q,
				"jwks_uri": %q,
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"]
			}`, serverURL, serverURL+"authorize", serverURL+"token", serverURL+"jwks")
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL + "/"

	resolved := resolvedRPRequest{
		issuer:            serverURL,
		clientID:          "client-id",
		clientSecret:      "secret",
		redirectURI:       "https://rp.localhost/callback/test-disc",
		startupAction:     startupActionDiscoveryOnly,
		stateStore:        sharedStateStore,
		userInfoTransport: rp.UserInfoTokenTransportHeader,
		profile:           "oidc",
		discoveryMode:     "oidc",
	}

	if err := executeDiscoveryOnly(context.Background(), resolved); err != nil {
		t.Fatalf("executeDiscoveryOnly failed: %v", err)
	}
	if !discoveryCalled {
		t.Fatal("expected discovery endpoint to be called")
	}
}

func TestExecuteStartupAction_DiscoveryOnlyUsesOAuth2DiscoveryMode(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	oauthCalled := false
	oidcCalled := false
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			oauthCalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"issuer": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q,
				"jwks_uri": %q,
				"response_types_supported": ["code"]
			}`, serverURL, serverURL+"authorize", serverURL+"token", serverURL+"jwks")
		case "/.well-known/openid-configuration":
			oidcCalled = true
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL + "/"

	resolved := resolvedRPRequest{
		issuer:            serverURL,
		clientID:          "client-id",
		clientSecret:      "secret",
		redirectURI:       "https://rp.localhost/callback/test-disc",
		startupAction:     startupActionDiscoveryOnly,
		stateStore:        sharedStateStore,
		userInfoTransport: rp.UserInfoTokenTransportHeader,
		profile:           "oauth2",
		discoveryMode:     "oauth2",
	}

	if err := executeDiscoveryOnly(context.Background(), resolved); err != nil {
		t.Fatalf("executeDiscoveryOnly failed: %v", err)
	}
	if !oauthCalled {
		t.Fatal("expected oauth2 discovery endpoint to be called")
	}
	if oidcCalled {
		t.Fatal("did not expect oidc discovery endpoint to be called")
	}
}

func TestExecuteStartupAction_DiscoveryAndJWKSFetchesKeys(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	jwksCalled := false
	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{
				"issuer": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q,
				"jwks_uri": %q,
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"]
			}`, serverURL, serverURL+"authorize", serverURL+"token", serverURL+"jwks")
			return
		}
		if r.URL.Path == "/jwks" {
			jwksCalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL + "/"

	resolved := resolvedRPRequest{
		issuer:            serverURL,
		clientID:          "client-id",
		clientSecret:      "secret",
		redirectURI:       "https://rp.localhost/callback/test-jwks",
		startupAction:     startupActionDiscoveryAndJWKS,
		stateStore:        sharedStateStore,
		userInfoTransport: rp.UserInfoTokenTransportHeader,
		profile:           "oidc",
		discoveryMode:     "oidc",
	}

	if err := executeDiscoveryAndJWKS(context.Background(), resolved); err != nil {
		t.Fatalf("executeDiscoveryAndJWKS failed: %v", err)
	}
	if !jwksCalled {
		t.Fatal("expected jwks endpoint to be called")
	}
}

func TestParseStartupActionFromRuntimeConfig(t *testing.T) {
	tests := []struct {
		name      string
		rawAction string
		want      startupAction
	}{
		{"full_flow", "full_flow", startupActionFullFlow},
		{"discovery_only", "discovery_only", startupActionDiscoveryOnly},
		{"discovery_and_jwks", "discovery_and_jwks", startupActionDiscoveryAndJWKS},
		{"empty defaults to full_flow", "", startupActionFullFlow},
		{"unknown defaults to full_flow", "unknown_action", startupActionFullFlow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := rpRuntimeConfig{StartupAction: tt.rawAction}
			got := cfg.startupAction()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("startupAction() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
