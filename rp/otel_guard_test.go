package rp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
)

func newTestRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func newTestLoginRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
}

func metadataProviderWithRegistrationEndpoint(endpoint string) metadata.Provider {
	return metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:               "https://issuer.test",
			RegistrationEndpoint: endpoint,
		},
	}
}

// TestTelemetryGuardCrossFlow exercises every public span-emitting operation
// against one issuer with one recorder and sweeps all resulting spans for
// the sentinelized secrets used in the fixtures. It is the consolidated
// enforcement point for the telemetry redaction guarantee; individual flow
// tests assert their exact span trees.
func TestTelemetryGuardCrossFlow(t *testing.T) {
	server, sr, r := otelIssuerServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/introspect":
			_, _ = io.WriteString(w, `{"active":true,"sub":"SECRET-SUB"}`)
		case "/grants/grant-1":
			if req.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_, _ = io.WriteString(w, `{"scopes":[{"scope":"openid"}]}`)
		case "/token":
			_, _ = io.WriteString(w, `{"access_token":"SECRET-ACCESS","token_type":"Bearer","expires_in":3600,"refresh_token":"SECRET-ROTATED"}`)
		case "/register":
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"client_id":"cid","client_secret":"SECRET-ISSUED"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_ = server

	ctx := context.Background()

	// Authorization request (plain query mode; the redirect URL never
	// enters telemetry).
	if _, err := r.AuthorizationURL(newTestRecorder(), newTestLoginRequest()); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	// Refresh with rotation.
	if _, err := r.RefreshToken(ctx, "SECRET-REFRESH"); err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}

	// Introspection.
	if _, err := r.IntrospectToken(ctx, IntrospectionRequest{Token: "SECRET-INTROSPECTED"}); err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}

	// Grant management.
	if _, err := r.QueryGrant(ctx, "SECRET-GM-TOKEN", "grant-1"); err != nil {
		t.Fatalf("QueryGrant() failed: %v", err)
	}
	if err := r.RevokeGrant(ctx, "SECRET-GM-TOKEN", "grant-1"); err != nil {
		t.Fatalf("RevokeGrant() failed: %v", err)
	}

	// Dynamic registration.
	registrar, err := NewRegistrar(ctx, "https://issuer.test",
		WithTracerProvider(sr.provider),
		WithHTTPClient(server.Client()),
		WithProviderMetadata(metadataProviderWithRegistrationEndpoint(server.URL+"/register")),
	)
	if err != nil {
		t.Fatalf("NewRegistrar() failed: %v", err)
	}
	if _, err := registrar.Register(ctx, ClientMetadata{RedirectURIs: []string{"https://rp.test/callback"}}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	// Every flow emitted its span.
	wantSubset := []string{
		"rp.authorization_url",
		"rp.refresh_token",
		"rp.introspection",
		"rp.grant_query",
		"rp.grant_revoke",
		"rp.registration_register",
	}
	names := sr.spanNames()
	for _, want := range wantSubset {
		found := false
		for _, name := range names {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("span %q missing; got %v", want, names)
		}
	}

	// The consolidated sweep: none of the secrets used above appear anywhere.
	assertNoSecrets(t, sr.spans(), []string{
		"SECRET-CLIENT-SECRET",
		"SECRET-REFRESH",
		"SECRET-ROTATED",
		"SECRET-ACCESS",
		"SECRET-INTROSPECTED",
		"SECRET-GM-TOKEN",
		"SECRET-ISSUED",
		"SECRET-SUB",
	})
}

// TestTelemetryGuardNoQueryStrings asserts no recorded attribute anywhere in
// the cross-flow spans contains a URL query string.
func TestTelemetryGuardNoQueryStrings(t *testing.T) {
	_, sr, r := otelIssuerServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	if _, err := r.AuthorizationURL(newTestRecorder(), newTestLoginRequest()); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	for _, span := range sr.spans() {
		for _, kv := range span.Attributes() {
			assertValueQueryFree(t, span.Name(), string(kv.Key), kv.Value.AsString())
		}
		for _, event := range span.Events() {
			for _, kv := range event.Attributes {
				assertValueQueryFree(t, span.Name(), event.Name, kv.Value.AsString())
			}
		}
	}

	if len(sr.spans()) == 0 {
		t.Fatal("no spans recorded")
	}
}

func assertValueQueryFree(t *testing.T, span, key, value string) {
	t.Helper()
	if len(value) > 0 && containsByte(value, '?') {
		t.Fatalf("span %q %s contains a query string: %q", span, key, value)
	}
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
