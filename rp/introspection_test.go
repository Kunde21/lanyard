package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestIntrospector_IntrospectToken_BasicAuth(t *testing.T) {
	var requestBody string
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"scope":"read"}`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL, "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:         "opaque-token",
		TokenTypeHint: TokenTypeHintAccessToken,
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if diff := cmp.Diff(true, got.Active); diff != "" {
		t.Fatalf("Active mismatch (-want +got):\n%s", diff)
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		t.Fatalf("Authorization header = %q, want Basic", authHeader)
	}
	values, err := url.ParseQuery(requestBody)
	if err != nil {
		t.Fatalf("ParseQuery() failed: %v", err)
	}
	want := url.Values{"token": {"opaque-token"}, "token_type_hint": {"access_token"}}
	if diff := cmp.Diff(want, values); diff != "" {
		t.Fatalf("form mismatch (-want +got):\n%s", diff)
	}
}

func TestIntrospector_IntrospectToken_PostAuth(t *testing.T) {
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"scope":"read"}`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL, "client_secret_post")),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatalf("Active = false, want true")
	}

	values, err := url.ParseQuery(requestBody)
	if err != nil {
		t.Fatalf("ParseQuery() failed: %v", err)
	}
	if values.Get("client_id") != "client" {
		t.Fatalf("client_id = %q, want %q", values.Get("client_id"), "client")
	}
	if values.Get("client_secret") != "secret" {
		t.Fatalf("client_secret = %q, want %q", values.Get("client_secret"), "secret")
	}
	if values.Get("token") != "opaque-token" {
		t.Fatalf("token = %q, want %q", values.Get("token"), "opaque-token")
	}
}

func TestIntrospector_IntrospectToken_MissingToken(t *testing.T) {
	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider("https://issuer.test/introspect", "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{Token: ""})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_Non200Status(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL, "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{Token: "token"})
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL, "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{Token: "token"})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_InactiveToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL, "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{Token: "token"})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if got.Active {
		t.Fatal("Active = true, want false")
	}
}

func TestIntrospector_IntrospectToken_PrivateKeyJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"scope":"read"}`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithProviderMetadata(introspectionProvider(server.URL, "private_key_jwt")),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if gotForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("client_assertion_type = %q, want jwt-bearer", gotForm.Get("client_assertion_type"))
	}
	assertion := gotForm.Get("client_assertion")
	if assertion == "" {
		t.Fatal("client_assertion is empty")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("client_assertion has %d parts, want 3", len(parts))
	}
}

func TestIntrospector_IntrospectToken_ClientSecretJWT(t *testing.T) {
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                                    "https://issuer.test",
		IntrospectionEndpoint:                     server.URL,
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_jwt"},
		TokenEndpointAuthMethodsSupported:         []string{"client_secret_jwt"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("a-very-long-client-secret-for-hs256-compat"),
		WithAuthMethod(AuthMethodClientSecretJWT),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if gotForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("client_assertion_type = %q, want jwt-bearer", gotForm.Get("client_assertion_type"))
	}
	if gotForm.Get("client_assertion") == "" {
		t.Fatal("client_assertion is empty")
	}
}

func TestIntrospector_IntrospectToken_NoneAuth(t *testing.T) {
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                                    "https://issuer.test",
		IntrospectionEndpoint:                     server.URL,
		IntrospectionEndpointAuthMethodsSupported: []string{"none"},
		TokenEndpointAuthMethodsSupported:         []string{"none"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithAuthMethod(AuthMethodNone),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if gotForm.Get("client_id") != "client" {
		t.Fatalf("client_id = %q, want %q", gotForm.Get("client_id"), "client")
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatal("client_secret should not be present for none auth")
	}
}

func TestIntrospector_IntrospectToken_SelfSignedTLSClientAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	cert := &tls.Certificate{}

	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             server.URL,
		TokenEndpointAuthMethodsSupported: []string{"self_signed_tls_client_auth"},
		MTLSEndpointAliases: metadata.MTLSEndpointAliases{
			IntrospectionEndpoint: server.URL + "/mtls",
		},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", cert)),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if gotForm.Get("client_id") != "client" {
		t.Fatalf("client_id = %q, want %q", gotForm.Get("client_id"), "client")
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatal("client_secret should not be present for TLS auth")
	}
}

func TestIntrospector_IntrospectToken_FallbackToBasic(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                "https://issuer.test",
		IntrospectionEndpoint: server.URL,
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if callCount != 2 {
		t.Fatalf("callCount = %d, want 2 (post then basic fallback)", callCount)
	}
}

func TestIntrospector_IntrospectToken_DPoP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	var dpopHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dpopHeader = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             server.URL,
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if dpopHeader == "" {
		t.Fatal("DPoP header is empty")
	}
}

func TestIntrospector_IntrospectToken_DPoPNonceRetry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("DPoP-Nonce", "server-nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             server.URL,
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if callCount != 2 {
		t.Fatalf("callCount = %d, want 2 (initial + nonce retry)", callCount)
	}
}

func TestIntrospector_IntrospectToken_RawExtensionPreserved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"scope":"read","custom_field":"custom_value","exp":1234567890}`))
	}))
	defer server.Close()

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL, "client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if diff := cmp.Diff(int64(1234567890), got.Exp); diff != "" {
		t.Fatalf("Exp mismatch (-want +got):\n%s", diff)
	}

	var extra struct {
		CustomField string `json:"custom_field"`
	}
	if err := got.DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("custom_value", extra.CustomField); diff != "" {
		t.Fatalf("custom_field mismatch (-want +got):\n%s", diff)
	}
}
