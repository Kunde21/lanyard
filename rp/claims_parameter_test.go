package rp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func claimsTestRP(t *testing.T, opts ...Option) *RP {
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
	}

	base := []Option{
		WithClientID("client"),
		WithClientSecret("a-very-secret-secret-0123456789abcdef"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		withRandReader(strings.NewReader(strings.Repeat("a", 4096))),
	}
	r, err := New(context.Background(), "https://issuer.test", append(base, opts...)...)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return r
}

func authorizationQuery(t *testing.T, r *RP, opts ...AuthorizationURLOption) url.Values {
	t.Helper()
	authURL, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil), opts...)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}
	return parsed.Query()
}

func TestClaimsParameter_Default(t *testing.T) {
	r := claimsTestRP(t, WithClaims(`{"userinfo":{"given_name":null}}`))

	query := authorizationQuery(t, r)
	if diff := cmp.Diff(`{"userinfo":{"given_name":null}}`, query.Get("claims")); diff != "" {
		t.Fatalf("claims mismatch (-want +got):\n%s", diff)
	}
}

func TestClaimsParameter_PerRequestOverride(t *testing.T) {
	r := claimsTestRP(t, WithClaims(`{"userinfo":{"given_name":null}}`))

	query := authorizationQuery(t, r, SetClaims(`{"id_token":{"email":null}}`))
	if diff := cmp.Diff(`{"id_token":{"email":null}}`, query.Get("claims")); diff != "" {
		t.Fatalf("claims override mismatch (-want +got):\n%s", diff)
	}
}

func TestClaimsParameter_InvalidJSON(t *testing.T) {
	_, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("a-very-secret-secret-0123456789abcdef"),
		WithRedirectURI("https://rp.test/callback"),
		WithClaims(`{"userinfo":`),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New() with invalid claims error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "claims parameter must be a JSON object") {
		t.Fatalf("error = %v, want claims message", err)
	}

	r := claimsTestRP(t)
	_, err = r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil),
		SetClaims(`[1,2,3]`),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("AuthorizationURL() with array claims error = %v, want ErrInvalidConfiguration", err)
	}

	// Empty per-request claims clear the parameter.
	query := authorizationQuery(t, r, SetClaims(""))
	if query.Get("claims") != "" {
		t.Fatalf("claims = %q, want empty", query.Get("claims"))
	}
}

func TestClaimsParameter_SignedRequestObject(t *testing.T) {
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
	}
	r, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("a-very-secret-secret-0123456789abcdef"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithClaims(`{"userinfo":{"given_name":null}}`),
		WithRequestMethod("signed_non_repudiation"),
		withRandReader(strings.NewReader(strings.Repeat("a", 4096))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	authURL, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil))
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}

	requestObject := parsed.Query().Get("request")
	if requestObject == "" {
		t.Fatal("request parameter missing in signed mode")
	}
	payload := strings.Split(requestObject, ".")[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	embedded, ok := claims["claims"].(map[string]any)
	if !ok {
		t.Fatalf("claims member missing from request object: %v", claims["claims"])
	}
	userinfo, ok := embedded["userinfo"].(map[string]any)
	if !ok {
		t.Fatalf("userinfo member missing: %v", embedded)
	}
	if _, present := userinfo["given_name"]; !present {
		t.Fatalf("given_name missing from embedded claims: %v", userinfo)
	}
}
