package rp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func introspectionProvider(endpoint string, methods ...string) metadata.Provider {
	return metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                                    "https://issuer.test",
		IntrospectionEndpoint:                     endpoint,
		IntrospectionEndpointAuthMethodsSupported: append([]string(nil), methods...),
		TokenEndpointAuthMethodsSupported:         append([]string(nil), methods...),
	}}
}

func TestNewIntrospector_RejectsAuthCodeOptions(t *testing.T) {
	_, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider("https://issuer.test/introspect", "client_secret_basic")),
		WithRedirectURI("https://rp.test/callback"),
	)
	if err == nil {
		t.Fatal("expected error for auth-code option")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestNewIntrospector_RequiresClientID(t *testing.T) {
	_, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider("https://issuer.test/introspect", "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestNewIntrospector_RequiresIntrospectionEndpoint(t *testing.T) {
	_, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer: "https://issuer.test",
		}}),
		WithAuthMethod(AuthMethodBasic),
	)
	if err == nil {
		t.Fatal("expected error for missing introspection endpoint")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestNewIntrospector_AcceptsConfiguredProvider(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL+"/introspect", "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}
	if i == nil {
		t.Fatal("expected non-nil Introspector")
	}
}

func TestNewIntrospector_SelectsIntrospectionAuthMethods(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                                    "https://issuer.test",
		IntrospectionEndpoint:                     server.URL + "/introspect",
		TokenEndpointAuthMethodsSupported:         []string{"client_secret_basic"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}
	if i.resolvedAuthMethod != AuthMethodPost {
		t.Fatalf("resolvedAuthMethod = %q, want %q", i.resolvedAuthMethod, AuthMethodPost)
	}
}

func TestNewIntrospector_FallsBackToTokenEndpointAuthMethods(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             server.URL + "/introspect",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}
	if i.resolvedAuthMethod != AuthMethodBasic {
		t.Fatalf("resolvedAuthMethod = %q, want %q", i.resolvedAuthMethod, AuthMethodBasic)
	}
}

func TestIntrospectionResponse_UnmarshalPreservesRaw(t *testing.T) {
	data := []byte(`{"active":true,"scope":"read write","client_id":"client","aud":"https://api.example.com","custom":"value"}`)

	var got IntrospectionResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON() failed: %v", err)
	}

	want := IntrospectionResponse{
		Active:   true,
		Scope:    "read write",
		ClientID: "client",
		Aud:      audienceClaim{"https://api.example.com"},
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(IntrospectionResponse{})); diff != "" {
		t.Fatalf("IntrospectionResponse mismatch (-want +got):\n%s", diff)
	}

	var extra struct {
		Custom string `json:"custom"`
	}
	if err := got.DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("value", extra.Custom); diff != "" {
		t.Fatalf("custom field mismatch (-want +got):\n%s", diff)
	}
}

func TestIntrospectionResponse_UnmarshalAudArray(t *testing.T) {
	data := []byte(`{"active":true,"aud":["https://api.example.com","https://other.example.com"]}`)

	var got IntrospectionResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON() failed: %v", err)
	}

	want := audienceClaim{"https://api.example.com", "https://other.example.com"}
	if diff := cmp.Diff(want, got.Aud); diff != "" {
		t.Fatalf("Aud mismatch (-want +got):\n%s", diff)
	}
}

func TestIntrospectionResponse_RawJWT(t *testing.T) {
	resp := IntrospectionResponse{}
	if got := resp.RawJWT(); got != "" {
		t.Fatalf("RawJWT() = %q, want empty", got)
	}
}

func TestIntrospector_PublicAPISmoke(t *testing.T) {
	var _ = TokenTypeHintAccessToken
	var _ = TokenTypeHintRefreshToken
	var _ = IntrospectionRequest{Token: "token", TokenTypeHint: TokenTypeHintAccessToken}
	var _ = IntrospectionRequest{Token: "token", PreferJWTResponse: true}
	var _ = IntrospectionRequest{Token: "token", ExpectedJWTAudience: "https://rs.example.com"}
	var _ = (*Introspector)(nil)
}
