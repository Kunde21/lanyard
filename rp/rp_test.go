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

	"github.com/Kunde21/lanyard/oidc"
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
	customOIDCClient := oidc.NewClient()
	customStateStore := NewMemoryStateStore(5 * time.Minute)

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
		WithProviderDiscovery(providerForAuthMethods()),
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
	if got.oidcClient != customOIDCClient {
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

func TestNew_WithProviderDiscovery_SkipsDiscoveryHTTP(t *testing.T) {
	provider := oidc.ProviderMetadata{
		AuthorizationServerMetadata: oidc.AuthorizationServerMetadata{
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
		WithProviderDiscovery(provider),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
}

func TestDiscoverWithJWKSFetchesRemoteKeys(t *testing.T) {
	issuer := ""
	discoveryCalls := 0
	jwksCalls := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discoveryCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			jwksCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
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

	if err := r.DiscoverWithJWKS(context.Background()); err != nil {
		t.Fatalf("DiscoverWithJWKS() failed: %v", err)
	}

	if jwksCalls == 0 {
		t.Fatalf("expected DiscoverWithJWKS() to fetch jwks_uri")
	}
	if discoveryCalls == 0 {
		t.Fatalf("expected discovery endpoint to be called")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
