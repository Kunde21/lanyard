package rp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	rpstore "github.com/Kunde21/lanyard/rp/store"
	"github.com/Kunde21/lanyard/rp/store/memory"
	"github.com/google/go-cmp/cmp"
)

type correlationOnlyStore struct{}

func (correlationOnlyStore) SaveCorrelation(context.Context, http.ResponseWriter, *http.Request, string, rpstore.CallbackCorrelation) error {
	return nil
}

func (correlationOnlyStore) ConsumeCorrelation(context.Context, http.ResponseWriter, *http.Request, string) (rpstore.CallbackCorrelation, bool, error) {
	return rpstore.CallbackCorrelation{}, false, nil
}

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		clientID    string
		redirectURI string
		wantErr     bool
	}{
		{name: "missing issuer", issuer: "", clientID: "client", redirectURI: "https://rp.test/callback"},
		{name: "invalid issuer", issuer: "http://issuer.test", clientID: "client", redirectURI: "https://rp.test/callback"},
		{name: "missing client id", issuer: "https://issuer.test", clientID: "", redirectURI: "https://rp.test/callback"},
		{name: "missing redirect uri", issuer: "https://issuer.test", clientID: "client", redirectURI: ""},
		{name: "invalid redirect uri", issuer: "https://issuer.test", clientID: "client", redirectURI: "http://rp.test/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), tt.issuer,
				WithClientID(tt.clientID),
				WithClientSecret("secret"),
				WithRedirectURI(tt.redirectURI),
			)
			if err == nil {
				t.Fatalf("New() expected error")
			}
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() error mismatch: got %v", err)
			}
		})
	}
}

func TestNew_DefaultsAndOptions(t *testing.T) {
	customHTTPClient := &http.Client{}
	customLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	customOIDCClient := metadata.NewClient()
	customStateStore := memory.New(5 * time.Minute)

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(customHTTPClient),
		WithLogger(customLogger),
		WithMetadataClient(customOIDCClient),
		WithStateStore(customStateStore),
		WithUserInfoTokenTransport(UserInfoTokenTransportBody),
		WithProviderMetadata(providerForAuthMethods()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff([]string{"openid"}, got.scopes); diff != "" {
		t.Fatalf("scopes mismatch (-want +got):\n%s", diff)
	}
	if got.httpClient != customHTTPClient {
		t.Fatalf("httpClient mismatch")
	}
	if got.logger != customLogger {
		t.Fatalf("logger mismatch")
	}
	if got.metadataClient != customOIDCClient {
		t.Fatalf("oidcClient mismatch")
	}
	if got.stateStore != customStateStore {
		t.Fatalf("stateStore mismatch")
	}
	if diff := cmp.Diff(UserInfoTokenTransportBody, got.userInfoTokenTransport); diff != "" {
		t.Fatalf("userinfo transport mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithCorrelationStoreAcceptsNarrowStore(t *testing.T) {
	customStateStore := correlationOnlyStore{}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithCorrelationStore(customStateStore),
		WithProviderMetadata(providerForAuthMethods()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if got.stateStore != customStateStore {
		t.Fatalf("stateStore mismatch")
	}
}

func TestNew_PerformsDiscoveryByDefault(t *testing.T) {
	requestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
	}))
	defer ts.Close()
	issuer = ts.URL

	_, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff(1, requestCount); diff != "" {
		t.Fatalf("discovery request count mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_SkipsDiscoveryForOAuthOnlyScopes(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected network request to %s", req.URL.String())
		return nil, errors.New("unexpected network request")
	})}

	issuer := "https://issuer.test/path"
	got, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff(issuer+"/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/par", got.provider.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("PAR endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/mtls/token", got.provider.MTLSEndpointAliases.TokenEndpoint); diff != "" {
		t.Fatalf("MTLS token endpoint mismatch (-want +got):\n%s", diff)
	}
	if got.provider.JWKSURI != "" {
		t.Fatalf("JWKSURI = %q, want empty", got.provider.JWKSURI)
	}
	if got.providerSet != true {
		t.Fatal("provider should be set after discovery")
	}
}

func TestNew_WithProviderMetadata_SkipsDiscoveryHTTP(t *testing.T) {
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                "https://issuer.test",
			AuthorizationEndpoint: "https://issuer.test/authorize",
			TokenEndpoint:         "https://issuer.test/token",
			JWKSURI:               "https://issuer.test/jwks",
			ResponseTypesSupported: []string{
				"code",
			},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
}

func TestNew_WithProviderMetadataMissingAuthorizationEndpoint_ReturnsError(t *testing.T) {
	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(metadata.Provider{}),
	)
	if err == nil {
		t.Fatalf("New() expected error")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New() error mismatch: got %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNew_WithProfile_StoresProfileOnRP(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
		WithProfile(OAuth2),
		WithDiscoveryMode(DiscoveryDisabled),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff(profileOAuth2, got.profile); diff != "" {
		t.Fatalf("profile mismatch (-want +got):\n%s", diff)
	}
	if !got.profileExplicit {
		t.Fatal("profileExplicit should be true")
	}
}

func TestNew_WithDiscoveryMode_DiscoveryDisabledStoredOnRP(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
		WithDiscoveryMode(DiscoveryDisabled),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff(discoveryModeDisabled, got.discoveryMode); diff != "" {
		t.Fatalf("discoveryMode mismatch (-want +got):\n%s", diff)
	}
	if !got.discoveryModeExplicit {
		t.Fatal("discoveryModeExplicit should be true")
	}
}

func TestNew_WithProfile_DefaultProfileIsOIDC(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff(profileOIDC, got.profile); diff != "" {
		t.Fatalf("profile mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithDiscoveryMode_DefaultIsAuto(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff(discoveryModeAuto, got.discoveryMode); diff != "" {
		t.Fatalf("discoveryMode mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_ExplicitScopesMarkedExplicit(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if !got.scopesExplicit {
		t.Fatal("scopesExplicit should be true when WithScopes is used")
	}
}

func TestNew_ScopesExplicit_WithScopesMarksExplicit(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("custom"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if !got.scopesExplicit {
		t.Fatal("scopesExplicit should be true when WithScopes is used")
	}
}

func TestNew_WithProviderMetadata_SkipsDiscoveryWhenMetadataIsComplete(t *testing.T) {
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 "https://issuer.test",
			AuthorizationEndpoint:  "https://issuer.test/authorize",
			TokenEndpoint:          "https://issuer.test/token",
			JWKSURI:                "https://issuer.test/jwks",
			ResponseTypesSupported: []string{"code"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
}

func TestNew_WithAuthorizationEndpoint_StoresPartialMetadata(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
}

func TestNew_WithTokenEndpoint_StoresPartialMetadata(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff("https://issuer.test/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithJWKSURI_StoresPartialMetadata(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithJWKSURI("https://issuer.test/jwks"),
		WithScopes("accounts"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff("https://issuer.test/jwks", got.provider.JWKSURI); diff != "" {
		t.Fatalf("jwks uri mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_GranularOptions_MergeWithDiscovery(t *testing.T) {
	requestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")))
	}))
	defer ts.Close()
	issuer = ts.URL

	got, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithAuthorizationEndpoint("https://custom.test/authorize"),
		WithScopes("openid"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff("https://custom.test/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint should come from discovery (-want +got):\n%s", diff)
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 discovery request, got %d", requestCount)
	}
}

func TestNew_WithProviderMetadata_PreservesExplicitFieldsOverDiscovery(t *testing.T) {
	requestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")))
	}))
	defer ts.Close()
	issuer = ts.URL

	partialProvider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			AuthorizationEndpoint: "https://custom.test/authorize",
		},
	}

	got, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(partialProvider),
		WithScopes("openid"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff("https://custom.test/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint should come from discovery (-want +got):\n%s", diff)
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 discovery request, got %d", requestCount)
	}
}

func TestNew_WithDiscoveryDisabledAndMissingAuthorizationEndpoint_ReturnsError(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithScopes("accounts"),
		WithDiscoveryMode(DiscoveryDisabled),
	)
	if err == nil {
		t.Fatalf("New() expected error for missing metadata with discovery disabled")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestNew_WithDiscoveryModeOAuth2_UsesAuthorizationServerDiscovery(t *testing.T) {
	asRequestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			asRequestCount++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"issuer": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q,
				"jwks_uri": %q,
				"response_types_supported": ["code"]
			}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	got, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithScopes("accounts"),
		WithDiscoveryMode(DiscoveryOAuth2),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if asRequestCount != 1 {
		t.Fatalf("expected 1 AS discovery request, got %d", asRequestCount)
	}
	if diff := cmp.Diff(issuer+"/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithDiscoveryModeOAuth2_ReturnsDiscoveryError(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		http.Error(w, "bad metadata", http.StatusBadGateway)
	}))
	defer ts.Close()
	issuer = ts.URL

	_, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithScopes("accounts"),
		WithDiscoveryMode(DiscoveryOAuth2),
	)
	if err == nil {
		t.Fatal("New() expected error")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to discover provider") {
		t.Fatalf("error = %q, want discovery failure detail", err)
	}
	if strings.Contains(err.Error(), "/authorize") {
		t.Fatalf("error = %q, should not fall back to synthetic oauth endpoints", err)
	}
	_ = issuer
}

func TestNew_ExplicitProviderFieldsOverrideDiscoveredValues(t *testing.T) {
	requestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")))
	}))
	defer ts.Close()
	issuer = ts.URL

	got, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithAuthorizationEndpoint("https://custom.test/authorize"),
		WithScopes("openid"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff("https://custom.test/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint should come from discovery (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(issuer+"/jwks", got.provider.JWKSURI); diff != "" {
		t.Fatalf("jwks uri should come from discovery (-want +got):\n%s", diff)
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 discovery request, got %d", requestCount)
	}
}

func TestNew_WithProviderMetadataThenGranularOption_LastExplicitValueWins(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			AuthorizationEndpoint: "https://bulk.test/authorize",
			TokenEndpoint:         "https://bulk.test/token",
			JWKSURI:               "https://bulk.test/jwks",
		}}),
		WithAuthorizationEndpoint("https://granular.test/authorize"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff("https://granular.test/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://bulk.test/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://bulk.test/jwks", got.provider.JWKSURI); diff != "" {
		t.Fatalf("jwks uri mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithGranularOptionThenProviderMetadata_UnrelatedFieldsAccumulate(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithAuthorizationEndpoint("https://granular.test/authorize"),
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			TokenEndpoint: "https://bulk.test/token",
			JWKSURI:       "https://bulk.test/jwks",
		}}),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff("https://granular.test/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://bulk.test/token", got.provider.TokenEndpoint); diff != "" {
		t.Fatalf("token endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://bulk.test/jwks", got.provider.JWKSURI); diff != "" {
		t.Fatalf("jwks uri mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithGranularAndBulkMetadata_LastExplicitValueWinsForSameField(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithAuthorizationEndpoint("https://first.test/authorize"),
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			AuthorizationEndpoint: "https://second.test/authorize",
			TokenEndpoint:         "https://second.test/token",
			JWKSURI:               "https://second.test/jwks",
		}}),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff("https://second.test/authorize", got.provider.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithDiscoveryModeOIDC_UsesOIDCDiscovery(t *testing.T) {
	requestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")))
	}))
	defer ts.Close()
	issuer = ts.URL

	got, err := New(
		context.Background(),
		issuer,
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithScopes("accounts"),
		WithDiscoveryMode(DiscoveryOIDC),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	_ = got

	if requestCount != 1 {
		t.Fatalf("expected 1 OIDC discovery request, got %d", requestCount)
	}
}

func TestWithProfile_OIDC_DefaultsOpenIDScope(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProfile(OIDC),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
		WithJWKSURI("https://issuer.test/jwks"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff([]string{"openid"}, got.scopes); diff != "" {
		t.Fatalf("scopes mismatch (-want +got):\n%s", diff)
	}
}

func TestWithProfile_OAuth2_DoesNotForceOpenIDScope(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProfile(OAuth2),
		WithScopes("accounts"),
		WithDiscoveryMode(DiscoveryDisabled),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	for _, scope := range got.scopes {
		if strings.EqualFold(scope, "openid") {
			t.Fatal("OAuth2 profile should not include openid scope")
		}
	}
}

func TestWithProfile_FAPI1Adv_DefaultsCanBeOverridden(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProfile(FAPI1Adv),
		WithScopes("accounts"),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff([]string{"accounts"}, got.scopes); diff != "" {
		t.Fatalf("explicit scopes should override profile defaults (-want +got):\n%s", diff)
	}
}

func TestWithProfile_FAPI2_SetsSignedRequestMethod(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProfile(FAPI2MessageSigning),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
		WithJWKSURI("https://issuer.test/jwks"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if !got.requestMethod.isSigned() {
		t.Fatal("FAPI2 message signing profile should default to signed request method")
	}
}

func TestWithProfile_FAPI1Adv_SignedRequestMethodCanBeOverridden(t *testing.T) {
	failOnRequest := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected network request")
	})}

	got, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(failOnRequest),
		WithProfile(FAPI1Adv),
		WithRequestMethod(""),
		WithAuthorizationEndpoint("https://issuer.test/authorize"),
		WithTokenEndpoint("https://issuer.test/token"),
		WithJWKSURI("https://issuer.test/jwks"),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if got.requestMethod.isSigned() {
		t.Fatal("explicit request method should override profile default")
	}
}
