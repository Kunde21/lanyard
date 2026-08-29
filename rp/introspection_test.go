package rp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func introspectionProvider(endpoint string, methods ...string) metadata.Provider {
	return metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                "https://issuer.test",
		IntrospectionEndpoint: endpoint,
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
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             server.URL + "/introspect",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
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

func TestNewIntrospector_RejectsNilDecryptionKey(t *testing.T) {
	_, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithIntrospectionDecryptionKey(nil),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewIntrospector() error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "decryption key must not be nil") {
		t.Fatalf("NewIntrospector() error = %v, want nil-key message", err)
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

func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestIntrospector_PublicAPISmoke(t *testing.T) {
	_ = TokenTypeHintAccessToken
	_ = TokenTypeHintRefreshToken
	_ = IntrospectionRequest{Token: "token", TokenTypeHint: TokenTypeHintAccessToken}
	_ = IntrospectionRequest{Token: "token", PreferJWTResponse: true}
	_ = IntrospectionRequest{Token: "token", ExpectedJWTAudience: "https://rs.example.com"}
	_ = (*Introspector)(nil)
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

func TestIntrospector_IntrospectToken_ParsesCnfClaim(t *testing.T) {
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jkt, err := JWKThumbprint(dpopKey)
	if err != nil {
		t.Fatalf("JWKThumbprint() failed: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"active": true,
		"sub":    "user-1",
		"cnf":    map[string]any{"jkt": jkt},
	})
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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

	want := &Confirmation{JKT: jkt}
	if diff := cmp.Diff(want, got.Cnf); diff != "" {
		t.Fatalf("Cnf mismatch (-want +got):\n%s", diff)
	}
	if err := got.Cnf.VerifyDPoPBinding(dpopKey); err != nil {
		t.Fatalf("VerifyDPoPBinding() = %v, want nil for matching key", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	if err := got.Cnf.VerifyDPoPBinding(otherKey); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("VerifyDPoPBinding() = %v, want ErrTokenBindingMismatch", err)
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
		Issuer:                "https://issuer.test",
		IntrospectionEndpoint: server.URL,
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
		Issuer:                "https://issuer.test",
		IntrospectionEndpoint: server.URL,
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

func signIntrospectionJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": "token-introspection+jwt",
			"kid": kid,
		},
	})
	if err != nil {
		t.Fatalf("create introspection signer: %v", err)
	}
	payload, _ := json.Marshal(claims)
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign introspection JWT: %v", err)
	}
	out, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize introspection JWT: %v", err)
	}
	return out
}

func newIntrospectionJWKSServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
}

// encryptIntrospectionJWT wraps a signed introspection JWT in a JWE addressed
// to recipient, producing a signed-then-encrypted nested JWT (RFC 9701 section 5).
func encryptIntrospectionJWT(t *testing.T, recipient crypto.PublicKey, keyAlg jose.KeyAlgorithm, signed string) string {
	t.Helper()
	opts := (&jose.EncrypterOptions{}).
		WithType("token-introspection+jwt").
		WithContentType("JWT")
	encrypter, err := jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{Algorithm: keyAlg, Key: recipient}, opts)
	if err != nil {
		t.Fatalf("create introspection encrypter: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte(signed))
	if err != nil {
		t.Fatalf("encrypt introspection JWT: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize encrypted introspection JWT: %v", err)
	}
	return out
}

func TestIntrospector_IntrospectToken_JWTResponse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
			"scope":  "read write",
			"sub":    "user-1",
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != introspectionJWTMediaType {
			t.Errorf("Accept = %q, want %q", r.Header.Get("Accept"), introspectionJWTMediaType)
		}
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if diff := cmp.Diff("read write", got.Scope); diff != "" {
		t.Fatalf("Scope mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("user-1", got.Sub); diff != "" {
		t.Fatalf("Sub mismatch (-want +got):\n%s", diff)
	}
	if got.RawJWT() == "" {
		t.Fatal("RawJWT() is empty, want JWT string")
	}
}

func TestIntrospector_IntrospectToken_JWTResponseParsesCnfClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jkt, err := JWKThumbprint(dpopKey)
	if err != nil {
		t.Fatalf("JWKThumbprint() failed: %v", err)
	}

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
			"sub":    "user-1",
			"cnf":    map[string]any{"jkt": jkt},
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}

	want := &Confirmation{JKT: jkt}
	if diff := cmp.Diff(want, got.Cnf); diff != "" {
		t.Fatalf("Cnf mismatch (-want +got):\n%s", diff)
	}
	if err := got.Cnf.VerifyDPoPBinding(dpopKey); err != nil {
		t.Fatalf("VerifyDPoPBinding() = %v, want nil for matching key", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseCustomAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "https://rs.example.com",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:               "opaque-token",
		PreferJWTResponse:   true,
		ExpectedJWTAudience: "https://rs.example.com",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRejectsNone(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	payload, _ := json.Marshal(claims)
	parts := strings.Split(
		base64Encode([]byte(`{"alg":"none","typ":"token-introspection+jwt"}`)),
		string(rune(0)),
	)
	_ = parts
	header := base64Encode([]byte(`{"alg":"none","typ":"token-introspection+jwt"}`))
	payloadB64 := base64Encode(payload)
	unsigned := header + "." + payloadB64 + "."

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(unsigned))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for none algorithm")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRejectsIssuerMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://evil.test",
		"aud": "client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for iss mismatch")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRejectsAudienceMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "wrong-client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for aud mismatch")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRejectsEncryptedWithoutDecryptionKey(t *testing.T) {
	encryptedJWT := "eyJhbGciOiJSU0EtPUEyNTYsImVuYyI6IkEyNTZHQ00ifQ.UGFydA.UGFydQ.UGFydI.QmFzZTY0UGF5bG9hZA"

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(encryptedJWT))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           "https://issuer.test/jwks",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for encrypted JWT without decryption key")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
	if !strings.Contains(err.Error(), "no decryption key is configured") {
		t.Fatalf("error = %v, want no-decryption-key message", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseEncrypted(t *testing.T) {
	asKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	rsKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, asKey, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
			"sub":    "user-1",
			"scope":  "read write",
		},
	}
	signed := signIntrospectionJWT(t, asKey, "signing-key-1", claims)
	nested := encryptIntrospectionJWT(t, &rsKey.PublicKey, jose.RSA_OAEP_256, signed)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(nested))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
		WithIntrospectionDecryptionKey(rsKey),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	got, err := i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if diff := cmp.Diff("user-1", got.Sub); diff != "" {
		t.Fatalf("Sub mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("read write", got.Scope); diff != "" {
		t.Fatalf("Scope mismatch (-want +got):\n%s", diff)
	}
	if got.RawJWT() != nested {
		t.Fatal("RawJWT() does not match the received nested JWT")
	}
}

func TestIntrospector_IntrospectToken_JWTResponseEncryptedWrongKey(t *testing.T) {
	asKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	configuredKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, asKey, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":                 "https://issuer.test",
		"aud":                 "client",
		"iat":                 now,
		"token_introspection": map[string]any{"active": true},
	}
	signed := signIntrospectionJWT(t, asKey, "signing-key-1", claims)
	// Encrypted to a different recipient than the configured decryption key.
	nested := encryptIntrospectionJWT(t, &otherKey.PublicKey, jose.RSA_OAEP_256, signed)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(nested))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
		WithIntrospectionDecryptionKey(configuredKey),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for wrong decryption key")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
	if !strings.Contains(err.Error(), "failed to decrypt") {
		t.Fatalf("error = %v, want decrypt failure message", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseEncryptedRejectsRSA15(t *testing.T) {
	asKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	rsKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, asKey, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":                 "https://issuer.test",
		"aud":                 "client",
		"iat":                 now,
		"token_introspection": map[string]any{"active": true},
	}
	signed := signIntrospectionJWT(t, asKey, "signing-key-1", claims)
	nested := encryptIntrospectionJWT(t, &rsKey.PublicKey, jose.RSA1_5, signed)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(nested))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
		WithIntrospectionDecryptionKey(rsKey),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for RSA1_5 key encryption")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseEncryptedRejectsMalformedJWE(t *testing.T) {
	asKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	rsKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, asKey, "signing-key-1")
	defer jwksServer.Close()

	garbageJWE := "eyJhbGciOiJSU0EtTUEyNTYiLCJlbmMiOiJBMjU2R0NNIn0.UGFydA.UGFydQ.UGFydI.QmFzZTY0UGF5bG9hZA"
	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(garbageJWE))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
		WithIntrospectionDecryptionKey(rsKey),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for malformed JWE")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
	if !strings.Contains(err.Error(), "failed to parse encrypted introspection JWT") {
		t.Fatalf("error = %v, want parse failure message", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseFutureIat(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	futureIat := time.Now().Add(10 * time.Minute).Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"iat": futureIat,
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for future iat")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
	if !strings.Contains(err.Error(), "iat in the future") {
		t.Fatalf("error = %v, want future iat message", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRequiresIat(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for missing iat")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
	if !strings.Contains(err.Error(), "missing required iat") {
		t.Fatalf("error = %v, want missing iat message", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRejectsInvalidSignature(t *testing.T) {
	publishedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	// The JWKS publishes publishedKey under the advertised kid, but the JWT is
	// signed by a different (untrusted) key claiming the same kid.
	jwksServer := newIntrospectionJWKSServer(t, publishedKey, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://issuer.test",
		"aud": "client",
		"iat": now,
		"token_introspection": map[string]any{
			"active": true,
		},
	}
	signed := signIntrospectionJWT(t, attackerKey, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("error = %v, want signature verification failure message", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseRejectsWrongTyp(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": "wrong-typ",
			"kid": "signing-key-1",
		},
	})
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	now := time.Now().Unix()
	payload, _ := json.Marshal(map[string]any{
		"iss":                 "https://issuer.test",
		"aud":                 "client",
		"iat":                 now,
		"token_introspection": map[string]any{"active": true},
	})
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		IntrospectionEndpoint:             introspectionServer.URL,
		JWKSURI:                           jwksServer.URL,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestIntrospector_IntrospectToken_JWTResponseEnforcesProviderAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	jwksServer := newIntrospectionJWKSServer(t, key, "signing-key-1")
	defer jwksServer.Close()

	now := time.Now().Unix()
	claims := map[string]any{
		"iss":                 "https://issuer.test",
		"aud":                 "client",
		"iat":                 now,
		"token_introspection": map[string]any{"active": true},
	}
	signed := signIntrospectionJWT(t, key, "signing-key-1", claims)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", introspectionJWTMediaType)
		_, _ = w.Write([]byte(signed))
	}))
	defer introspectionServer.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                                 "https://issuer.test",
		IntrospectionEndpoint:                  introspectionServer.URL,
		JWKSURI:                                jwksServer.URL,
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic"},
		IntrospectionSigningAlgValuesSupported: []string{"ES256"},
	}}

	i, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithHTTPClient(jwksServer.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = i.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:             "opaque-token",
		PreferJWTResponse: true,
	})
	if err == nil {
		t.Fatal("expected error for algorithm not in provider list")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestRP_IntrospectToken_SendsCredentials(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		AuthorizationEndpoint:             "https://issuer.test/authorize",
		TokenEndpoint:                     "https://issuer.test/token",
		IntrospectionEndpoint:             server.URL,
		JWKSURI:                           "https://issuer.test/jwks",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	rpClient, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithDiscoveryMode(DiscoveryDisabled),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := rpClient.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic auth", gotAuth)
	}
}

func TestRP_IntrospectToken_HonorsIntrospectionAuthMethods(t *testing.T) {
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
		AuthorizationEndpoint:             "https://issuer.test/authorize",
		TokenEndpoint:                     "https://issuer.test/token",
		IntrospectionEndpoint:             server.URL,
		JWKSURI:                           "https://issuer.test/jwks",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}}

	rpClient, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithDiscoveryMode(DiscoveryDisabled),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := rpClient.IntrospectToken(context.Background(), IntrospectionRequest{
		Token: "opaque-token",
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !got.Active {
		t.Fatal("Active = false, want true")
	}
	if gotForm.Get("client_secret") != "secret" {
		t.Fatalf("client_secret in form = %q, want %q", gotForm.Get("client_secret"), "secret")
	}
}

func TestRP_IntrospectToken_ErrorsOnEmptyToken(t *testing.T) {
	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		AuthorizationEndpoint:             "https://issuer.test/authorize",
		TokenEndpoint:                     "https://issuer.test/token",
		IntrospectionEndpoint:             "https://issuer.test/introspect",
		JWKSURI:                           "https://issuer.test/jwks",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	rpClient, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithDiscoveryMode(DiscoveryDisabled),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = rpClient.IntrospectToken(context.Background(), IntrospectionRequest{Token: ""})
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}

func TestRP_IntrospectToken_ErrorsOnMissingEndpoint(t *testing.T) {
	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.test",
		AuthorizationEndpoint:             "https://issuer.test/authorize",
		TokenEndpoint:                     "https://issuer.test/token",
		JWKSURI:                           "https://issuer.test/jwks",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}

	rpClient, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(provider),
		WithDiscoveryMode(DiscoveryDisabled),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = rpClient.IntrospectToken(context.Background(), IntrospectionRequest{Token: "token"})
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("error = %v, want ErrIntrospectionFailed", err)
	}
}
