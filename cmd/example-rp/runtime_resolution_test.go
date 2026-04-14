package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

func TestNewRPHTTPClient_LogsRequestAndResponseDumps(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newRPHTTPClient(nil)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ReadAll() failed: %v", err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "rp http request dump") {
		t.Fatal("expected request dump log entry")
	}
	if !strings.Contains(logs, "rp http response dump") {
		t.Fatal("expected response dump log entry")
	}
}

func TestProviderMetadataForResolvedRequest_UsesMTLSAliasesForConformanceOAuthOnly(t *testing.T) {
	resolved := resolvedRPRequest{
		issuer:          "https://suite.localhost/test/a/plain-fapi-10/",
		scopes:          []string{"accounts"},
		senderConstrain: "mtls",
	}

	got, ok := providerMetadataForResolvedRequest(resolved)
	if !ok {
		t.Fatal("providerMetadataForResolvedRequest() = not configured, want configured")
	}

	if diff := cmp.Diff("https://suite.localhost/test/a/plain-fapi-10/authorize", got.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://suite.localhost/test/a/plain-fapi-10/par", got.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("PAR endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://suite.localhost:8444/test-mtls/a/plain-fapi-10/par", got.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("MTLS PAR endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://suite.localhost:8444/test-mtls/a/plain-fapi-10/token", got.MTLSEndpointAliases.TokenEndpoint); diff != "" {
		t.Fatalf("MTLS token endpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestProviderMetadataForResolvedRequest_UsesOverrideForEncryptedClient2(t *testing.T) {
	got, ok := providerMetadataForResolvedRequest(resolvedRPRequest{
		issuer:   "https://suite.localhost/test/a/plain-fapi-10/",
		clientID: "local-dev-client-2",
		scopes:   []string{"openid"},
	})
	if !ok {
		t.Fatal("providerMetadataForResolvedRequest() = not configured, want configured")
	}
	if diff := cmp.Diff([]string{"PS256", "RS256"}, got.IDTokenSigningAlgValuesSupported); diff != "" {
		t.Fatalf("ID token signing algs mismatch (-want +got):\n%s", diff)
	}
}

func TestNewRPHTTPClient_SendsClientCertificateWhenRequested(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	tlsCert, privateKey, err := generateTestTLSCertificate()
	if err != nil {
		t.Fatalf("generateTestTLSCertificate() failed: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("expected client certificate on TLS connection")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()

	client := newRPHTTPClient(rp.NewStaticClientKeyProvider(privateKey, "test-mtls", "RS256", &tlsCert))
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}
	defer resp.Body.Close()

	if diff := cmp.Diff(http.StatusNoContent, resp.StatusCode); diff != "" {
		t.Fatalf("status mismatch (-want +got):\n%s", diff)
	}
}

func TestNewRPHTTPClient_SendsClientCertificateWithUnrelatedAcceptedCAs(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	tlsCert, privateKey, err := generateTestTLSCertificate()
	if err != nil {
		t.Fatalf("generateTestTLSCertificate() failed: %v", err)
	}

	caPool, err := generateUnrelatedCAPool()
	if err != nil {
		t.Fatalf("generateUnrelatedCAPool() failed: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("expected client certificate on TLS connection")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, ClientCAs: caPool}
	server.StartTLS()
	defer server.Close()

	client := newRPHTTPClient(rp.NewStaticClientKeyProvider(privateKey, "test-mtls", "RS256", &tlsCert))
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}
	defer resp.Body.Close()

	if diff := cmp.Diff(http.StatusNoContent, resp.StatusCode); diff != "" {
		t.Fatalf("status mismatch (-want +got):\n%s", diff)
	}
}

func generateTestTLSCertificate() (tls.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, privateKey, nil
}

func generateUnrelatedCAPool() (*x509.CertPool, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ca.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

func TestAuthMethodForRuntime_SelfSignedTLSClientAuth(t *testing.T) {
	cfg := rpRuntimeConfig{ClientAuthType: "self_signed_tls_client_auth"}
	got, ok := authMethodForRuntime(cfg)
	if !ok {
		t.Fatalf("expected auth method to resolve")
	}
	if diff := cmp.Diff(rp.AuthMethodSelfSignedTLSClientAuth, got); diff != "" {
		t.Fatalf("auth method mismatch (-want +got):\n%s", diff)
	}
}

func TestRequestMethodForRuntime_UsesSignedRequestObjectForOIDCCRequestTypes(t *testing.T) {
	tests := []struct {
		name        string
		cfg         rpRuntimeConfig
		wantMethod  string
		wantRequire bool
	}{
		{name: "plain request", cfg: rpRuntimeConfig{RequestType: "plain_http_request"}, wantMethod: "", wantRequire: false},
		{name: "request object", cfg: rpRuntimeConfig{RequestType: "request_object"}, wantMethod: "signed_non_repudiation", wantRequire: false},
		{name: "request uri non-fapi", cfg: rpRuntimeConfig{RequestType: "request_uri"}, wantMethod: "signed_non_repudiation", wantRequire: false},
		{name: "request uri fapi", cfg: rpRuntimeConfig{RequestType: "request_uri", FAPIProfile: "fapi2-sp"}, wantMethod: "signed_non_repudiation", wantRequire: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.wantMethod, requestMethodForRuntime(tt.cfg)); diff != "" {
				t.Fatalf("requestMethodForRuntime() mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantRequire, runtimeRequiresPAR(tt.cfg)); diff != "" {
				t.Fatalf("runtimeRequiresPAR() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestShouldUseRequestURI(t *testing.T) {
	tests := []struct {
		name string
		cfg  rpRuntimeConfig
		want bool
	}{
		{name: "plain_http_request", cfg: rpRuntimeConfig{RequestType: "plain_http_request"}, want: false},
		{name: "request_object", cfg: rpRuntimeConfig{RequestType: "request_object"}, want: false},
		{name: "request_uri no fapi", cfg: rpRuntimeConfig{RequestType: "request_uri"}, want: true},
		{name: "request_uri with fapi profile", cfg: rpRuntimeConfig{RequestType: "request_uri", FAPIProfile: "fapi2-sp"}, want: false},
		{name: "request_uri with require_par", cfg: rpRuntimeConfig{RequestType: "request_uri", RequirePAR: true}, want: false},
		{name: "request_uri with par request_type", cfg: rpRuntimeConfig{RequestType: "pushed_authorization_request"}, want: false},
		{name: "empty request_type", cfg: rpRuntimeConfig{RequestType: ""}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, shouldUseRequestURI(tt.cfg)); diff != "" {
				t.Fatalf("shouldUseRequestURI() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildRPFromResolvedRequest_RequestURIModeUsesSharedStore(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	oldStore := sharedRequestStore
	sharedRequestStore = newRequestObjectStore(5 * time.Minute)
	defer func() {
		sharedRequestStore = oldStore
	}()

	resolved := resolvedRPRequest{
		issuer:        "https://suite.localhost/test/a/test-alias/",
		clientID:      "local-dev-client-2",
		clientSecret:  "secret",
		redirectURI:   "https://rp.localhost/callback/test-alias",
		stateStore:    sharedStateStore,
		scopes:        []string{"openid"},
		requestMethod: "signed_non_repudiation",
		useRequestURI: true,
		keyProvider:   rp.NewStaticClientKeyProvider(privateKey, "kid-1", "PS256", nil),
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil)
	flow, err := buildRPFromResolvedRequest(req, resolved)
	if err != nil {
		t.Fatalf("buildRPFromResolvedRequest() failed: %v", err)
	}

	rec := httptest.NewRecorder()
	authURL, err := flow.AuthorizationURL(rec, req)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(authURL) failed: %v", err)
	}
	requestURI := parsed.Query().Get("request_uri")
	if requestURI == "" {
		t.Fatal("request_uri missing from authorization url")
	}

	requestURIParsed, err := url.Parse(requestURI)
	if err != nil {
		t.Fatalf("url.Parse(request_uri) failed: %v", err)
	}

	handlerReq := httptest.NewRequest(http.MethodGet, requestURIParsed.Path, nil)
	handlerRec := httptest.NewRecorder()
	handleRequestObject(sharedRequestStore).ServeHTTP(handlerRec, handlerReq)

	if diff := cmp.Diff(http.StatusOK, handlerRec.Code); diff != "" {
		t.Fatalf("request handler status mismatch (-want +got):\n%s", diff)
	}
	if got := handlerRec.Header().Get("Content-Type"); got != "application/jwt" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/jwt")
	}
	if strings.TrimSpace(handlerRec.Body.String()) == "" {
		t.Fatal("hosted request object body is empty")
	}
	if !strings.Contains(handlerRec.Body.String(), ".") {
		t.Fatal("hosted request object does not look like a compact JWT")
	}
}

func TestLoadRequestObjectKeyProvider_ReturnsAsymmetricSignerForSignedRequestTypes(t *testing.T) {
	provider, err := loadRequestObjectKeyProvider("client_secret_basic", "", "request_object")
	if err != nil {
		t.Fatalf("loadRequestObjectKeyProvider() failed: %v", err)
	}
	if provider == nil {
		t.Fatal("loadRequestObjectKeyProvider() = nil, want key provider")
	}
	if diff := cmp.Diff("PS256", provider.SigningAlgorithm()); diff != "" {
		t.Fatalf("signing alg mismatch (-want +got):\n%s", diff)
	}
}

func TestParseStartupAction(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  startupAction
	}{
		{"full_flow", "full_flow", startupActionFullFlow},
		{"discovery_only", "discovery_only", startupActionDiscoveryOnly},
		{"discovery_and_jwks", "discovery_and_jwks", startupActionDiscoveryAndJWKS},
		{"empty_defaults_to_full_flow", "", startupActionFullFlow},
		{"unknown_defaults_to_full_flow", "unknown", startupActionFullFlow},
		{"case insensitive", "Discovery_Only", startupActionDiscoveryOnly},
		{"whitespace trimmed", "  full_flow  ", startupActionFullFlow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseStartupAction(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("parseStartupAction() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRPRuntimeConfigStartupAction(t *testing.T) {
	tests := []struct {
		name string
		cfg  rpRuntimeConfig
		want startupAction
	}{
		{"empty defaults to full_flow", rpRuntimeConfig{}, startupActionFullFlow},
		{"full_flow explicit", rpRuntimeConfig{StartupAction: "full_flow"}, startupActionFullFlow},
		{"discovery_only", rpRuntimeConfig{StartupAction: "discovery_only"}, startupActionDiscoveryOnly},
		{"discovery_and_jwks", rpRuntimeConfig{StartupAction: "discovery_and_jwks"}, startupActionDiscoveryAndJWKS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.startupAction()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("startupAction() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestShouldUseMemoryStateStore(t *testing.T) {
	tests := []struct {
		name string
		cfg  rpRuntimeConfig
		want bool
	}{
		{name: "oidc private_key_jwt", cfg: rpRuntimeConfig{ClientAuthType: "private_key_jwt"}, want: false},
		{name: "oidc mtls", cfg: rpRuntimeConfig{ClientAuthType: "mtls"}, want: false},
		{name: "plain fapi", cfg: rpRuntimeConfig{FAPIProfile: "plain_fapi"}, want: true},
		{name: "fapi2", cfg: rpRuntimeConfig{FAPIProfile: "fapi2-sp"}, want: true},
		{name: "fapi1", cfg: rpRuntimeConfig{FAPIProfile: "fapi1"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, shouldUseMemoryStateStore(tt.cfg)); diff != "" {
				t.Fatalf("shouldUseMemoryStateStore() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveRPRequest_DefaultStartupActionIsFullFlow(t *testing.T) {
	reg := newRuntimeRegistry()
	if err := reg.Register(rpRuntimeConfig{
		Alias:       "test-alias",
		ClientID:    "client-id",
		RedirectURI: "https://rp.localhost/callback/test-alias",
		Issuer:      "https://suite.localhost/test/a/test-alias/",
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	oldRegistry := conformanceRuntimes
	conformanceRuntimes = reg
	defer func() { conformanceRuntimes = oldRegistry }()

	r := httptest.NewRequest(http.MethodGet, "/login?issuer=https://suite.localhost/test/a/test-alias/", nil)
	resolved, err := resolveRPRequest(r, "client", "secret", "https://rp.localhost/callback", rp.UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("resolveRPRequest() failed: %v", err)
	}
	if resolved.startupAction != startupActionFullFlow {
		t.Fatalf("startupAction = %q, want %q", resolved.startupAction, startupActionFullFlow)
	}
}

func TestResolveRPRequest_ParsesDiscoveryOnlyStartupAction(t *testing.T) {
	reg := newRuntimeRegistry()
	if err := reg.Register(rpRuntimeConfig{
		Alias:         "test-alias",
		ClientID:      "client-id",
		RedirectURI:   "https://rp.localhost/callback/test-alias",
		Issuer:        "https://suite.localhost/test/a/test-alias/",
		StartupAction: "discovery_only",
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	oldRegistry := conformanceRuntimes
	conformanceRuntimes = reg
	defer func() { conformanceRuntimes = oldRegistry }()

	r := httptest.NewRequest(http.MethodGet, "/login?issuer=https://suite.localhost/test/a/test-alias/", nil)
	resolved, err := resolveRPRequest(r, "client", "secret", "https://rp.localhost/callback", rp.UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("resolveRPRequest() failed: %v", err)
	}
	if resolved.startupAction != startupActionDiscoveryOnly {
		t.Fatalf("startupAction = %q, want %q", resolved.startupAction, startupActionDiscoveryOnly)
	}
}

func TestResolveRPRequest_ParsesDiscoveryAndJWKSStartupAction(t *testing.T) {
	reg := newRuntimeRegistry()
	if err := reg.Register(rpRuntimeConfig{
		Alias:         "test-alias",
		ClientID:      "client-id",
		RedirectURI:   "https://rp.localhost/callback/test-alias",
		Issuer:        "https://suite.localhost/test/a/test-alias/",
		StartupAction: "discovery_and_jwks",
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	oldRegistry := conformanceRuntimes
	conformanceRuntimes = reg
	defer func() { conformanceRuntimes = oldRegistry }()

	r := httptest.NewRequest(http.MethodGet, "/login?issuer=https://suite.localhost/test/a/test-alias/", nil)
	resolved, err := resolveRPRequest(r, "client", "secret", "https://rp.localhost/callback", rp.UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("resolveRPRequest() failed: %v", err)
	}
	if resolved.startupAction != startupActionDiscoveryAndJWKS {
		t.Fatalf("startupAction = %q, want %q", resolved.startupAction, startupActionDiscoveryAndJWKS)
	}
}

func TestShouldAllowUnsecuredIDTokens(t *testing.T) {
	tests := []struct {
		name     string
		resolved resolvedRPRequest
		want     bool
	}{
		{name: "oidc profile allows", resolved: resolvedRPRequest{profile: "oidc"}, want: true},
		{name: "oauth2 profile allows", resolved: resolvedRPRequest{profile: "oauth2"}, want: true},
		{name: "empty profile allows", resolved: resolvedRPRequest{profile: ""}, want: true},
		{name: "fapi1_adv profile rejects", resolved: resolvedRPRequest{profile: "fapi1_adv"}, want: false},
		{name: "fapi1-advanced profile rejects", resolved: resolvedRPRequest{profile: "fapi1-advanced"}, want: false},
		{name: "fapi2-sp profile rejects", resolved: resolvedRPRequest{profile: "fapi2-sp"}, want: false},
		{name: "fapi2-ms profile rejects", resolved: resolvedRPRequest{profile: "fapi2-ms"}, want: false},
		{name: "fapi_profile plain_fapi rejects", resolved: resolvedRPRequest{fapiProfile: "plain_fapi"}, want: false},
		{name: "fapi_profile fapi2-sp rejects", resolved: resolvedRPRequest{fapiProfile: "fapi2-sp"}, want: false},
		{name: "unknown profile allows", resolved: resolvedRPRequest{profile: "unknown"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, shouldAllowUnsecuredIDTokens(tt.resolved)); diff != "" {
				t.Fatalf("shouldAllowUnsecuredIDTokens() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
