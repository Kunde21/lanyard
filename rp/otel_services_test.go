package rp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func otelIssuerServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *spanRecorder, *RP) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	sr := newSpanRecorder(t)
	r, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("SECRET-CLIENT-SECRET"),
		WithRedirectURI("https://rp.test/callback"),
		WithTracerProvider(sr.provider),
		WithHTTPClient(server.Client()),
		WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                            "https://issuer.test",
				AuthorizationEndpoint:             "https://issuer.test/authorize",
				TokenEndpoint:                     server.URL + "/token",
				JWKSURI:                           "https://issuer.test/jwks",
				IntrospectionEndpoint:             server.URL + "/introspect",
				RegistrationEndpoint:              server.URL + "/register",
				ResponseTypesSupported:            []string{"code"},
				TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
			GrantManagementEndpoint:          server.URL + "/grants",
		}),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return server, sr, r
}

func TestIntrospectionSpan(t *testing.T) {
	server, sr, r := otelIssuerServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"active":true,"sub":"SECRET-SUB"}`)
	})

	if _, err := r.IntrospectToken(context.Background(), IntrospectionRequest{Token: "SECRET-INTROSPECTED-TOKEN"}); err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	_ = server

	if diff := cmp.Diff([]string{"rp.introspection"}, sr.spanNames()); diff != "" {
		t.Fatalf("span names mismatch (-want +got):\n%s", diff)
	}

	activeRecorded := false
	for _, span := range sr.spans() {
		for _, kv := range span.Attributes() {
			if string(kv.Key) == "lanyard.active" && kv.Value.AsBool() {
				activeRecorded = true
			}
		}
	}
	if !activeRecorded {
		t.Fatal("introspection span missing active attribute")
	}

	assertNoSecrets(t, sr.spans(), []string{"SECRET-INTROSPECTED-TOKEN", "SECRET-SUB", "SECRET-CLIENT-SECRET"})
}

func TestGrantManagementSpans(t *testing.T) {
	_, sr, r := otelIssuerServer(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"scopes":[{"scope":"openid"}],"updated_by":"client"}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	})

	if _, err := r.QueryGrant(context.Background(), "SECRET-GM-TOKEN", "grant-1"); err != nil {
		t.Fatalf("QueryGrant() failed: %v", err)
	}
	if err := r.RevokeGrant(context.Background(), "SECRET-GM-TOKEN", "grant-1"); err != nil {
		t.Fatalf("RevokeGrant() failed: %v", err)
	}

	if diff := cmp.Diff([]string{"rp.grant_query", "rp.grant_revoke"}, sr.spanNames()); diff != "" {
		t.Fatalf("span names mismatch (-want +got):\n%s", diff)
	}
	assertNoSecrets(t, sr.spans(), []string{"SECRET-GM-TOKEN", "SECRET-CLIENT-SECRET"})
}

func TestRegistrationSpans(t *testing.T) {
	server, sr, _ := otelIssuerServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"client_id":"SECRET-CLIENT-ID","client_secret":"SECRET-ISSUED-SECRET"}`)
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"client_id":"SECRET-CLIENT-ID","client_secret":"SECRET-ROTATED"}`)
		case http.MethodPut:
			_, _ = io.WriteString(w, `{"client_id":"SECRET-CLIENT-ID","client_secret":"SECRET-ROTATED"}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	})

	registrar, err := NewRegistrar(context.Background(), "https://issuer.test",
		WithTracerProvider(sr.provider),
		WithHTTPClient(server.Client()),
		WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:               "https://issuer.test",
				RegistrationEndpoint: server.URL + "/register",
			},
		}),
	)
	if err != nil {
		t.Fatalf("NewRegistrar() failed: %v", err)
	}

	if _, err := registrar.Register(context.Background(), ClientMetadata{
		RedirectURIs: []string{"https://rp.test/callback"},
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	if _, err := registrar.Read(context.Background(), server.URL+"/register/c1", "SECRET-RAT"); err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if _, err := registrar.Update(context.Background(), server.URL+"/register/c1", "SECRET-RAT", ClientUpdate{
		ClientMetadata: ClientMetadata{RedirectURIs: []string{"https://rp.test/callback"}},
		ClientID:       "c1",
	}); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	if err := registrar.Delete(context.Background(), server.URL+"/register/c1", "SECRET-RAT"); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	want := []string{
		"rp.registration_register",
		"rp.registration_read",
		"rp.registration_update",
		"rp.registration_delete",
	}
	if diff := cmp.Diff(want, sr.spanNames()); diff != "" {
		t.Fatalf("span names mismatch (-want +got):\n%s", diff)
	}

	rotated := false
	for _, span := range sr.spans() {
		for _, event := range span.Events() {
			if event.Name == "secret_rotated" {
				rotated = true
			}
		}
	}
	if !rotated {
		t.Fatal("secret_rotated event missing on update span")
	}

	assertNoSecrets(t, sr.spans(), []string{
		"SECRET-ISSUED-SECRET", "SECRET-ROTATED", "SECRET-RAT", "SECRET-CLIENT-ID",
	})
}
