package rp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func grantManagerTestServer(t *testing.T, handler http.HandlerFunc) *GrantManager {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			TokenEndpoint:                     server.URL + "/token",
			JWKSURI:                           server.URL + "/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		GrantManagementEndpoint:          server.URL + "/grants",
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	m, err := NewGrantManager(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithHTTPClient(server.Client()),
	)
	if err != nil {
		t.Fatalf("NewGrantManager() failed: %v", err)
	}
	return m
}

func TestGrantManager_QueryGrant(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"scopes": [
				{"scope": "contacts read", "resource": ["https://rs.example.com/api1"]},
				{"scope": "write", "resource": ["https://rs.example.com/api2", "https://rs.example.com/api3"]},
				{"scope": "openid"}
			],
			"claims": ["given_name", "email"],
			"authorization_details": [{"type": "account_information"}],
			"created_at": 1356123600,
			"last_updated_at": 1356123601,
			"expires_at": 1356129600,
			"updated_by": "client"
		}`)
	})

	status, err := m.QueryGrant(context.Background(), "gm-access-token", "TSdqirmAxDa0")
	if err != nil {
		t.Fatalf("QueryGrant() failed: %v", err)
	}

	if gotMethod != http.MethodGet || gotPath != "/grants/TSdqirmAxDa0" {
		t.Fatalf("request = %s %s, want GET /grants/TSdqirmAxDa0", gotMethod, gotPath)
	}
	if gotAuth != "Bearer gm-access-token" {
		t.Fatalf("Authorization = %q, want Bearer gm-access-token", gotAuth)
	}

	want := GrantStatus{
		Scopes: []GrantScope{
			{Scope: "contacts read", Resource: []string{"https://rs.example.com/api1"}},
			{Scope: "write", Resource: []string{"https://rs.example.com/api2", "https://rs.example.com/api3"}},
			{Scope: "openid"},
		},
		Claims:               []string{"given_name", "email"},
		AuthorizationDetails: []byte(`[{"type": "account_information"}]`),
		CreatedAt:            int64Ptr(1356123600),
		LastUpdated:          int64Ptr(1356123601),
		ExpiresAt:            int64Ptr(1356129600),
		UpdatedBy:            "client",
	}
	if diff := cmp.Diff(want.Scopes, status.Scopes); diff != "" {
		t.Fatalf("Scopes mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.Claims, status.Claims); diff != "" {
		t.Fatalf("Claims mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.CreatedAt, status.CreatedAt); diff != "" {
		t.Fatalf("CreatedAt mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.LastUpdated, status.LastUpdated); diff != "" {
		t.Fatalf("LastUpdated mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.ExpiresAt, status.ExpiresAt); diff != "" {
		t.Fatalf("ExpiresAt mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.UpdatedBy, status.UpdatedBy); diff != "" {
		t.Fatalf("UpdatedBy mismatch (-want +got):\n%s", diff)
	}

	var extra struct {
		UpdatedBy string `json:"updated_by"`
	}
	if err := status.DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("client", extra.UpdatedBy); diff != "" {
		t.Fatalf("DecodeRaw updated_by mismatch (-want +got):\n%s", diff)
	}
}

func TestGrantManager_QueryGrantLastUpdatedAlias(t *testing.T) {
	m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"scopes":[{"scope":"openid"}],"last_updated":1356123601}`)
	})

	status, err := m.QueryGrant(context.Background(), "gm-access-token", "g1")
	if err != nil {
		t.Fatalf("QueryGrant() failed: %v", err)
	}
	if diff := cmp.Diff(int64Ptr(1356123601), status.LastUpdated); diff != "" {
		t.Fatalf("LastUpdated mismatch (-want +got):\n%s", diff)
	}
}

func TestGrantManager_QueryGrantResourcesAlias(t *testing.T) {
	m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"scopes":[{"scope":"read","resources":["https://rs.example.com/api"]}]}`)
	})

	status, err := m.QueryGrant(context.Background(), "gm-access-token", "g1")
	if err != nil {
		t.Fatalf("QueryGrant() failed: %v", err)
	}
	want := []GrantScope{{Scope: "read", Resource: []string{"https://rs.example.com/api"}}}
	if diff := cmp.Diff(want, status.Scopes); diff != "" {
		t.Fatalf("Scopes mismatch (-want +got):\n%s", diff)
	}
}

func TestGrantManager_QueryGrantErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		message    string
	}{
		{name: "not found", statusCode: http.StatusNotFound, message: "404"},
		{name: "unauthorized", statusCode: http.StatusUnauthorized, body: `{"error":"invalid_token"}`, message: "invalid_token"},
		{name: "forbidden", statusCode: http.StatusForbidden, message: "403"},
		{name: "server error", statusCode: http.StatusInternalServerError, message: "500"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := m.QueryGrant(context.Background(), "gm-access-token", "g1")
			if !errors.Is(err, ErrGrantManagementFailed) {
				t.Fatalf("QueryGrant() error = %v, want ErrGrantManagementFailed", err)
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("QueryGrant() error = %v, want message containing %q", err, tc.message)
			}
			if tc.body != "" {
				var oauthErr *OAuthError
				if !errors.As(err, &oauthErr) {
					t.Fatalf("QueryGrant() error = %v, want *OAuthError", err)
				}
			}
		})
	}
}

func TestGrantManager_RevokeGrant(t *testing.T) {
	var gotMethod, gotPath string
	m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	if err := m.RevokeGrant(context.Background(), "gm-access-token", "TSdqirmAxDa0"); err != nil {
		t.Fatalf("RevokeGrant() failed: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/grants/TSdqirmAxDa0" {
		t.Fatalf("request = %s %s, want DELETE /grants/TSdqirmAxDa0", gotMethod, gotPath)
	}
}

func TestGrantManager_RevokeGrantError(t *testing.T) {
	m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := m.RevokeGrant(context.Background(), "gm-access-token", "g1"); !errors.Is(err, ErrGrantManagementFailed) {
		t.Fatalf("RevokeGrant() error = %v, want ErrGrantManagementFailed", err)
	}
}

func TestGrantManager_Validation(t *testing.T) {
	m := grantManagerTestServer(t, func(w http.ResponseWriter, r *http.Request) {})

	if _, err := m.QueryGrant(context.Background(), "", "g1"); !errors.Is(err, ErrGrantManagementFailed) {
		t.Fatalf("QueryGrant(empty token) error = %v, want ErrGrantManagementFailed", err)
	}
	if _, err := m.QueryGrant(context.Background(), "at", "  "); !errors.Is(err, ErrGrantManagementFailed) {
		t.Fatalf("QueryGrant(empty grant id) error = %v, want ErrGrantManagementFailed", err)
	}
	if err := m.RevokeGrant(context.Background(), "", "g1"); !errors.Is(err, ErrGrantManagementFailed) {
		t.Fatalf("RevokeGrant(empty token) error = %v, want ErrGrantManagementFailed", err)
	}
}

func TestNewGrantManager_RequiresEndpoint(t *testing.T) {
	_, err := NewGrantManager(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:        "https://issuer.test",
			TokenEndpoint: "https://issuer.test/token",
		}}),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewGrantManager() error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "grant management endpoint") {
		t.Fatalf("NewGrantManager() error = %v, want endpoint message", err)
	}
}
