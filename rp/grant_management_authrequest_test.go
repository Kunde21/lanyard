package rp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func grantManagementTestRP(t *testing.T, actionRequired bool) *RP {
	t.Helper()
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     "https://issuer.test/token",
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		GrantManagementActionsSupported:  []string{"query", "revoke", "create", "merge", "replace"},
	}
	if actionRequired {
		provider.GrantManagementActionRequired = &[]bool{true}[0]
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		withRandReader(strings.NewReader(strings.Repeat("a", 512))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return r
}

func TestAuthorizationURL_GrantManagementParameters(t *testing.T) {
	r := grantManagementTestRP(t, false)

	authURL, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil),
		SetGrantManagementAction(GrantActionMerge, "TSdqirmAxDa0"),
	)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}
	if diff := cmp.Diff("merge", parsed.Query().Get("grant_management_action")); diff != "" {
		t.Fatalf("grant_management_action mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("TSdqirmAxDa0", parsed.Query().Get("grant_id")); diff != "" {
		t.Fatalf("grant_id mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthorizationURL_GrantManagementActionRequired(t *testing.T) {
	r := grantManagementTestRP(t, true)

	_, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil))
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("AuthorizationURL() error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "grant_management_action") {
		t.Fatalf("AuthorizationURL() error = %v, want grant_management_action message", err)
	}

	_, err = r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil),
		SetGrantID("TSdqirmAxDa0"),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("AuthorizationURL() with grant_id only error = %v, want ErrInvalidConfiguration", err)
	}

	authURL, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil),
		SetGrantManagementAction(GrantActionMerge, "TSdqirmAxDa0"),
	)
	if err != nil {
		t.Fatalf("AuthorizationURL() with action failed: %v", err)
	}
	if !strings.Contains(authURL, "grant_management_action=merge") {
		t.Fatalf("AuthorizationURL() = %q, want grant_management_action parameter", authURL)
	}
}

func TestAuthorizationURL_GrantManagementActionNotAdvertised(t *testing.T) {
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     "https://issuer.test/token",
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		GrantManagementActionsSupported:  []string{"query", "revoke"},
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		withRandReader(strings.NewReader(strings.Repeat("a", 512))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil),
		SetGrantManagementAction(GrantActionCreate, ""),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("AuthorizationURL() error = %v, want ErrInvalidConfiguration for unadvertised action", err)
	}
	if !strings.Contains(err.Error(), "grant_management_actions_supported") {
		t.Fatalf("AuthorizationURL() error = %v, want supported-actions message", err)
	}
}

func TestHandleCallback_AuthorizationErrorResponse(t *testing.T) {
	r := grantManagementTestRP(t, false)

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/callback?error=access_denied&error_description=user+refused", nil)
	_, err := r.HandleCallback(httptest.NewRecorder(), req)
	if !errors.Is(err, ErrAuthorizationFailed) {
		t.Fatalf("HandleCallback() error = %v, want ErrAuthorizationFailed", err)
	}
	if !strings.Contains(err.Error(), "access_denied") || !strings.Contains(err.Error(), "user refused") {
		t.Fatalf("HandleCallback() error = %v, want code and description", err)
	}
}

func TestHandleCallback_InvalidGrantID(t *testing.T) {
	r := grantManagementTestRP(t, false)

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/callback?error=invalid_grant_id", nil)
	_, err := r.HandleCallback(httptest.NewRecorder(), req)
	if !errors.Is(err, ErrInvalidGrantID) {
		t.Fatalf("HandleCallback() error = %v, want ErrInvalidGrantID", err)
	}
	if !errors.Is(err, ErrAuthorizationFailed) {
		t.Fatalf("HandleCallback() error = %v, want ErrAuthorizationFailed chain", err)
	}
}
