package rp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp/store/memory"
	"github.com/google/go-cmp/cmp"
)

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		clientID    string
		redirectURI string
	}{
		{name: "missing issuer", issuer: "", clientID: "client", redirectURI: "https://rp.test/callback"},
		{name: "invalid issuer", issuer: "http://issuer.test", clientID: "client", redirectURI: "https://rp.test/callback"},
		{name: "missing client id", issuer: "https://issuer.test", clientID: "", redirectURI: "https://rp.test/callback"},
		{name: "missing redirect uri", issuer: "https://issuer.test", clientID: "client", redirectURI: ""},
		{name: "invalid redirect uri", issuer: "https://issuer.test", clientID: "client", redirectURI: "http://rp.test/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), tt.issuer, tt.clientID, "secret", tt.redirectURI)
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
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(customHTTPClient),
		WithLogger(customLogger),
		WithOIDCClient(customOIDCClient),
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
		"client",
		"secret",
		"https://rp.test/callback",
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
		"client",
		"secret",
		"https://rp.test/callback",
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
		"client",
		"secret",
		"https://rp.test/callback",
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
		"client",
		"secret",
		"https://rp.test/callback",
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
