package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

func TestGrantManagementOptionsFromRequest(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantOption  bool
		wantErrText string
	}{
		{name: "no parameters", url: "/login"},
		{name: "action and grant id", url: "/login?grant_management_action=merge&grant_id=g1", wantOption: true},
		{name: "grant id only", url: "/login?grant_id=g1", wantOption: true},
		{name: "create without grant id", url: "/login?grant_management_action=create", wantOption: true},
		{
			name:        "create with grant id",
			url:         "/login?grant_management_action=create&grant_id=g1",
			wantErrText: "must not be combined",
		},
		{
			name:        "merge without grant id",
			url:         "/login?grant_management_action=merge",
			wantErrText: "requires grant_id",
		},
		{
			name:        "replace without grant id",
			url:         "/login?grant_management_action=replace",
			wantErrText: "requires grant_id",
		},
		{
			name:        "unknown action",
			url:         "/login?grant_management_action=delete&grant_id=g1",
			wantErrText: "unknown grant_management_action",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			opt, err := grantManagementOptionsFromRequest(req)
			if tc.wantErrText != "" {
				if err == nil {
					t.Fatalf("grantManagementOptionsFromRequest() = nil error, want %q", tc.wantErrText)
				}
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("grantManagementOptionsFromRequest() failed: %v", err)
			}
			if tc.wantOption && opt == nil {
				t.Fatal("option = nil, want non-nil")
			}
			if !tc.wantOption && opt != nil {
				t.Fatal("option = non-nil, want nil")
			}
		})
	}
}

type recordingLoginFlow struct {
	stubFlow
	captured []rp.AuthorizationURLOption
}

func (f *recordingLoginFlow) AuthorizationURL(w http.ResponseWriter, r *http.Request, opts ...rp.AuthorizationURLOption) (string, error) {
	f.captured = opts
	return f.authURL, f.authErr
}

func TestLoginGrantManagementParameters(t *testing.T) {
	flow := &recordingLoginFlow{stubFlow: stubFlow{authURL: "https://issuer.test/authorize"}}
	h := newMuxForTest(flow)

	req := httptest.NewRequest(http.MethodGet, "/login?grant_management_action=merge&grant_id=g1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %s)", w.Code, http.StatusFound, w.Body.String())
	}
	if len(flow.captured) != 1 {
		t.Fatalf("captured options = %d, want 1", len(flow.captured))
	}

	flow.captured = nil
	req = httptest.NewRequest(http.MethodGet, "/login?grant_management_action=create&grant_id=g1", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if len(flow.captured) != 0 {
		t.Fatalf("captured options = %d, want 0 on invalid params", len(flow.captured))
	}
}

func grantDemoIssuerServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func grantDemoRP(t *testing.T, issuerServer *httptest.Server) *rp.RP {
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
		GrantManagementEndpoint:          issuerServer.URL + "/grants",
	}

	r, err := rp.New(
		context.Background(),
		"https://issuer.test",
		rp.WithClientID("client"),
		rp.WithClientSecret("secret"),
		rp.WithRedirectURI("https://rp.localhost/callback"),
		rp.WithProviderMetadata(provider),
		rp.WithAuthMethod(rp.AuthMethodBasic),
		rp.WithHTTPClient(issuerServer.Client()),
	)
	if err != nil {
		t.Fatalf("rp.New() failed: %v", err)
	}
	return r
}

func serveGrantsWithRP(t *testing.T, issuerServer *httptest.Server) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		handleGrantsWithBuild(w, r, func(*http.Request) (*rp.RP, error) {
			return grantDemoRP(t, issuerServer), nil
		})
	}
}

func TestHandleGrantsQuery(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	issuer := grantDemoIssuerServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"scopes":[{"scope":"openid"}],"updated_by":"client"}`)
	})

	req := httptest.NewRequest(http.MethodGet, "/grants/g1", nil)
	req.Header.Set("Authorization", "Bearer gm-token")
	w := httptest.NewRecorder()
	serveGrantsWithRP(t, issuer)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if gotMethod != http.MethodGet || gotPath != "/grants/g1" {
		t.Fatalf("upstream request = %s %s, want GET /grants/g1", gotMethod, gotPath)
	}
	if diff := cmp.Diff("Bearer gm-token", gotAuth); diff != "" {
		t.Fatalf("Authorization mismatch (-want +got):\n%s", diff)
	}
	if !strings.Contains(w.Body.String(), `"openid"`) {
		t.Fatalf("body = %s, want scopes JSON", w.Body.String())
	}
}

func TestHandleGrantsRevoke(t *testing.T) {
	var gotMethod string
	issuer := grantDemoIssuerServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodDelete, "/grants/g1", nil)
	req.Header.Set("Authorization", "Bearer gm-token")
	w := httptest.NewRecorder()
	serveGrantsWithRP(t, issuer)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body: %s)", w.Code, w.Body.String())
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("upstream method = %s, want DELETE", gotMethod)
	}
}

func TestHandleGrantsValidation(t *testing.T) {
	issuer := grantDemoIssuerServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream call: %s %s", r.Method, r.URL.Path)
	})
	handler := serveGrantsWithRP(t, issuer)

	tests := []struct {
		name       string
		method     string
		target     string
		authHeader string
		wantStatus int
	}{
		{name: "method not allowed", method: http.MethodPost, target: "/grants/g1", authHeader: "Bearer t", wantStatus: http.StatusMethodNotAllowed},
		{name: "missing grant id", method: http.MethodGet, target: "/grants/", authHeader: "Bearer t", wantStatus: http.StatusBadRequest},
		{name: "nested path", method: http.MethodGet, target: "/grants/g1/extra", authHeader: "Bearer t", wantStatus: http.StatusBadRequest},
		{name: "missing token", method: http.MethodGet, target: "/grants/g1", wantStatus: http.StatusUnauthorized},
		{name: "non bearer token", method: http.MethodGet, target: "/grants/g1", authHeader: "Basic dXNlcjpwYXNz", wantStatus: http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			handler(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestHandleGrantsUpstreamErrorMapped(t *testing.T) {
	issuer := grantDemoIssuerServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{}`)
	})

	req := httptest.NewRequest(http.MethodGet, "/grants/unknown", nil)
	req.Header.Set("Authorization", "Bearer gm-token")
	w := httptest.NewRecorder()
	serveGrantsWithRP(t, issuer)(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for upstream failure (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "grant management") {
		t.Fatalf("body = %s, want grant management error text", w.Body.String())
	}
}

func TestLoginClaimsParameter(t *testing.T) {
	flow := &recordingLoginFlow{stubFlow: stubFlow{authURL: "https://issuer.test/authorize"}}
	h := newMuxForTest(flow)

	// Valid claims JSON passes through as an option.
	req := httptest.NewRequest(http.MethodGet, `/login?claims={"userinfo":{"verified_claims":{"verification":{"trust_framework":null},"claims":{"given_name":null}}}}`, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body: %s)", w.Code, http.StatusFound, w.Body.String())
	}
	if len(flow.captured) != 2 {
		t.Fatalf("captured options = %d, want 2 (grant + claims)", len(flow.captured))
	}

	// Invalid claims JSON yields a 400 before the redirect.
	req = httptest.NewRequest(http.MethodGet, `/login?claims={"userinfo":`, nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
}
