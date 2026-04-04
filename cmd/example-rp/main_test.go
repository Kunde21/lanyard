package main

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

	"github.com/Kunde21/lanyard/oidc"
	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

type stubFlow struct {
	authURL      string
	authErr      error
	callbackErr  error
	callbackResp *rp.CallbackResult
}

func (s stubFlow) AuthorizationURL(_ context.Context, _ http.ResponseWriter, _ *http.Request, _ ...rp.AuthorizationURLOption) (string, error) {
	return s.authURL, s.authErr
}

func (s stubFlow) HandleCallback(_ context.Context, _ http.ResponseWriter, req *http.Request) (*rp.CallbackResult, error) {
	if req == nil {
		return nil, rp.ErrInvalidState
	}
	code := strings.TrimSpace(req.URL.Query().Get("code"))
	state := strings.TrimSpace(req.URL.Query().Get("state"))
	if code == "" && state == "" {
		if req.Method == http.MethodPost && strings.HasPrefix(strings.TrimSpace(req.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
			if err := req.ParseForm(); err == nil {
				code = strings.TrimSpace(req.FormValue("code"))
				state = strings.TrimSpace(req.FormValue("state"))
			}
		}
	}
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

func TestMaybeFetchConformanceResource_RetriesWithDpopNonce(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	keyProvider := rp.NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)

	requests := 0
	var firstAuth string
	var secondAuth string
	var firstProof string
	var secondProof string
	var gotPath string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotPath = r.URL.Path
		auth := r.Header.Get("Authorization")
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstAuth = auth
			firstProof = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondAuth = auth
		secondProof = proof
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer ts.Close()

	flow, err := rp.New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		rp.WithProviderMetadata(oidc.ProviderMetadata{AuthorizationServerMetadata: oidc.AuthorizationServerMetadata{AuthorizationEndpoint: "https://issuer.test/authorize"}}),
		rp.WithAuthMethod(rp.AuthMethodPrivateKeyJWT),
		rp.WithClientKeyProvider(keyProvider),
		rp.WithSenderConstrain("dpop"),
	)
	if err != nil {
		t.Fatalf("rp.New() failed: %v", err)
	}

	resolved := resolvedRPRequest{
		issuer:          ts.URL + "/test/a/alias-a/",
		keyProvider:     keyProvider,
		senderConstrain: "dpop",
		fapiProfile:     "plain_fapi",
	}

	if err := maybeFetchConformanceResource(context.Background(), flow, resolved, "access-token"); err != nil {
		t.Fatalf("maybeFetchConformanceResource() failed: %v", err)
	}

	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("request count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("DPoP access-token", firstAuth); diff != "" {
		t.Fatalf("first Authorization header mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("DPoP access-token", secondAuth); diff != "" {
		t.Fatalf("second Authorization header mismatch (-want +got):\n%s", diff)
	}
	if firstProof == "" || secondProof == "" {
		t.Fatalf("expected DPoP proofs on both requests")
	}
	if firstProof == secondProof {
		t.Fatalf("expected second proof to differ from first proof (should include new nonce)")
	}
	if diff := cmp.Diff("/test/a/alias-a/open-banking/v1.1/accounts", gotPath); diff != "" {
		t.Fatalf("conformance resource path mismatch (-want +got):\n%s", diff)
	}
}

func TestMaybeFetchConformanceResource_UsesImplicitDpop(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	keyProvider := rp.NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)

	requests := 0
	var firstAuth string
	var secondAuth string
	var firstProof string
	var secondProof string
	var gotPath string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotPath = r.URL.Path
		auth := r.Header.Get("Authorization")
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstAuth = auth
			firstProof = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondAuth = auth
		secondProof = proof
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer ts.Close()

	flow, err := rp.New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		rp.WithProviderMetadata(oidc.ProviderMetadata{AuthorizationServerMetadata: oidc.AuthorizationServerMetadata{AuthorizationEndpoint: "https://issuer.test/authorize"}}),
		rp.WithAuthMethod(rp.AuthMethodPrivateKeyJWT),
		rp.WithClientKeyProvider(keyProvider),
		rp.WithSenderConstrain(""),
	)
	if err != nil {
		t.Fatalf("rp.New() failed: %v", err)
	}

	resolved := resolvedRPRequest{
		issuer:      ts.URL + "/test/a/alias-a/",
		keyProvider: keyProvider,
		fapiProfile: "plain_fapi",
	}

	if err := maybeFetchConformanceResource(context.Background(), flow, resolved, "access-token"); err != nil {
		t.Fatalf("maybeFetchConformanceResource() failed: %v", err)
	}

	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("request count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("DPoP access-token", firstAuth); diff != "" {
		t.Fatalf("first Authorization header mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("DPoP access-token", secondAuth); diff != "" {
		t.Fatalf("second Authorization header mismatch (-want +got):\n%s", diff)
	}
	if firstProof == "" || secondProof == "" {
		t.Fatalf("expected DPoP proofs on both requests")
	}
	if firstProof == secondProof {
		t.Fatalf("expected second proof to differ from first proof (should include new nonce)")
	}
	if diff := cmp.Diff("/test/a/alias-a/open-banking/v1.1/accounts", gotPath); diff != "" {
		t.Fatalf("conformance resource path mismatch (-want +got):\n%s", diff)
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

func TestCallback_FormPostError(t *testing.T) {
	h := newMuxForTest(stubFlow{})
	form := url.Values{}
	form.Set("error", "access_denied")
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCallback_FormPostSuccess(t *testing.T) {
	h := newMuxForTest(stubFlow{callbackResp: &rp.CallbackResult{Subject: "form-sub"}})
	form := url.Values{}
	form.Set("code", "form-code")
	form.Set("state", "form-state")
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "form-sub") {
		t.Fatalf("response should contain subject")
	}
}

func TestCallback_FormPostWithAlias(t *testing.T) {
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

	h := newMuxForTest(stubFlow{callbackResp: &rp.CallbackResult{Subject: "alias-sub"}})
	form := url.Values{}
	form.Set("code", "code")
	form.Set("state", "state")
	req := httptest.NewRequest(http.MethodPost, "/callback/alias-a", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "alias-sub") {
		t.Fatalf("response should contain subject")
	}
}

func TestCallback_GETBehaviorUnchanged(t *testing.T) {
	h := newMuxForTest(stubFlow{callbackResp: &rp.CallbackResult{Subject: "get-sub"}})
	req := httptest.NewRequest(http.MethodGet, "/callback?code=get-code&state=get-state", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "get-sub") {
		t.Fatalf("response should contain subject")
	}
}
