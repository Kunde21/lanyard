package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/rp"
)

type stubFlow struct {
	authURL      string
	authErr      error
	callbackErr  error
	callbackResp *rp.CallbackResult
}

func (s stubFlow) AuthorizationURL(_ context.Context, _ http.ResponseWriter, _ *http.Request) (string, error) {
	return s.authURL, s.authErr
}

func (s stubFlow) HandleCallback(_ context.Context, _ http.ResponseWriter, req *http.Request) (*rp.CallbackResult, error) {
	if req == nil {
		return nil, rp.ErrInvalidState
	}
	code := strings.TrimSpace(req.URL.Query().Get("code"))
	state := strings.TrimSpace(req.URL.Query().Get("state"))
	if state == "" {
		return nil, rp.ErrInvalidState
	}
	if code == "" {
		return nil, rp.ErrMissingCode
	}

	if s.callbackResp != nil {
		return s.callbackResp, s.callbackErr
	}
	return &rp.CallbackResult{Subject: "sub"}, s.callbackErr
}

func TestRoot(t *testing.T) {
	h := newMuxForTest(stubFlow{authURL: "https://issuer.test/authorize"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/login") {
		t.Fatalf("expected /login link in response body")
	}
}

func TestLoginRedirects(t *testing.T) {
	h := newMuxForTest(stubFlow{authURL: "https://issuer.test/authorize?x=1"})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got == "" {
		t.Fatalf("Location header missing")
	}
}

func TestCallbackMissingParams(t *testing.T) {
	h := newMuxForTest(stubFlow{})
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "secret") {
		t.Fatalf("response must not leak sensitive content")
	}
}

func TestCallbackInvalidState(t *testing.T) {
	h := newMuxForTest(stubFlow{callbackErr: fmt.Errorf("wrapped: %w", rp.ErrInvalidState)})
	req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=s", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
}

func TestCallbackErrorMappingAndNoSecrets(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "token error", err: fmt.Errorf("token failed: %w", rp.ErrTokenExchangeFailed), wantStatus: http.StatusBadRequest},
		{name: "id token error", err: fmt.Errorf("id token failed: %w", rp.ErrIDTokenValidationFailed), wantStatus: http.StatusOK},
		{name: "userinfo error", err: fmt.Errorf("userinfo failed: %w", rp.ErrUserInfoValidationFailed), wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newMuxForTest(stubFlow{callbackErr: tt.err})
			req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=s", nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status mismatch: got %d", w.Code)
			}
			if strings.Contains(strings.ToLower(w.Body.String()), "secret") || strings.Contains(strings.ToLower(w.Body.String()), "token") {
				t.Fatalf("response body should not expose sensitive details")
			}
		})
	}
}

func TestParseScopesEnv(t *testing.T) {
	t.Run("uses fallback when unset", func(t *testing.T) {
		fallback := []string{"openid", "profile"}
		got := parseScopesEnv("RP_SCOPES_TEST", fallback)
		if strings.Join(got, " ") != "openid profile" {
			t.Fatalf("unexpected fallback scopes: %v", got)
		}
	})

	t.Run("parses comma and space separated values and deduplicates", func(t *testing.T) {
		t.Setenv("RP_SCOPES_TEST", "openid, profile email openid")
		got := parseScopesEnv("RP_SCOPES_TEST", []string{"openid"})
		if strings.Join(got, " ") != "openid profile email" {
			t.Fatalf("unexpected parsed scopes: %v", got)
		}
	})
}

func TestWebFingerResourceBuilders(t *testing.T) {
	issuer := "https://suite.localhost/test/a/lanyard-local/"

	acct, err := webFingerAcctResource(issuer)
	if err != nil {
		t.Fatalf("webFingerAcctResource() failed: %v", err)
	}
	if acct != "acct:lanyard-local.oidcc-client-test-discovery-webfinger-acct@suite.localhost" {
		t.Fatalf("acct resource mismatch: %q", acct)
	}

	resourceURL, err := webFingerURLResource(issuer)
	if err != nil {
		t.Fatalf("webFingerURLResource() failed: %v", err)
	}
	if resourceURL != "https://suite.localhost/lanyard-local/oidcc-client-test-discovery-webfinger-url" {
		t.Fatalf("url resource mismatch: %q", resourceURL)
	}
}

func TestResolveRPRequest_RequiresRegisteredRuntimeForExplicitIssuerAlias(t *testing.T) {
	conformanceRuntimes = newRuntimeRegistry()
	req := httptest.NewRequest(http.MethodGet, "/login?issuer=https://suite.localhost/test/a/unknown/", nil)
	_, err := resolveRPRequest(req, "client", "secret", "https://rp.localhost/callback", rp.UserInfoTokenTransportHeader)
	if err == nil || !strings.Contains(err.Error(), "no registered conformance runtime") {
		t.Fatalf("resolveRPRequest() error = %v, want missing runtime error", err)
	}
}

func TestResolveRPRequest_UsesCallbackAliasRuntime(t *testing.T) {
	conformanceRuntimes = newRuntimeRegistry()
	if err := conformanceRuntimes.Register(rpRuntimeConfig{
		Alias:        "alias-a",
		Issuer:       "https://suite.localhost/test/a/alias-a/",
		ClientID:     "client-a",
		ClientSecret: "secret-a",
		RedirectURI:  "https://rp.localhost/callback/alias-a",
		Namespace:    "alias-a",
		Scopes:       []string{"openid"},
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/callback/alias-a?code=abc&state=s", nil)
	resolved, err := resolveRPRequest(req, "fallback-client", "fallback-secret", "https://rp.localhost/callback", rp.UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("resolveRPRequest() failed: %v", err)
	}
	if resolved.issuer != "https://suite.localhost/test/a/alias-a/" {
		t.Fatalf("issuer = %q, want callback runtime issuer", resolved.issuer)
	}
	if resolved.redirectURI != "https://rp.localhost/callback/alias-a" {
		t.Fatalf("redirectURI = %q, want alias callback URI", resolved.redirectURI)
	}
}

func TestRuntimeRequiresPAR(t *testing.T) {
	tests := []struct {
		name string
		cfg  rpRuntimeConfig
		want bool
	}{
		{
			name: "explicit require par",
			cfg:  rpRuntimeConfig{RequirePAR: true, FAPIProfile: "plain_fapi"},
			want: true,
		},
		{
			name: "simple plain fapi does not force par",
			cfg: rpRuntimeConfig{
				FAPIProfile:              "plain_fapi",
				AuthorizationRequestType: "simple",
			},
			want: false,
		},
		{
			name: "authorization request type par",
			cfg:  rpRuntimeConfig{AuthorizationRequestType: "par"},
			want: true,
		},
		{
			name: "request type par",
			cfg:  rpRuntimeConfig{RequestType: "pushed_authorization_request"},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runtimeRequiresPAR(tc.cfg)
			if got != tc.want {
				t.Fatalf("runtimeRequiresPAR() = %t, want %t", got, tc.want)
			}
		})
	}
}
