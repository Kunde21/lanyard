package rp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestClientCredentials_TokenSourceInterface(t *testing.T) {
	var _ TokenSource = (*ClientCredentials)(nil)
}

func TestNewClientCredentials_Validation(t *testing.T) {
	tests := []struct {
		name         string
		issuer       string
		clientID     string
		clientSecret string
		wantErr      bool
		errContains  string
	}{
		{
			name:        "empty issuer",
			issuer:      "",
			clientID:    "client-id",
			wantErr:     true,
			errContains: "issuer",
		},
		{
			name:        "invalid issuer URL",
			issuer:      "not-a-url",
			clientID:    "client-id",
			wantErr:     true,
			errContains: "issuer",
		},
		{
			name:        "empty client ID",
			issuer:      "https://auth.example.com",
			clientID:    "",
			wantErr:     true,
			errContains: "client_id",
		},
		{
			name:        "http issuer",
			issuer:      "http://auth.example.com",
			clientID:    "client-id",
			wantErr:     true,
			errContains: "https",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(clientCredentialsProvider("https://auth.example.com/token", AuthMethodPost))
			}))
			defer server.Close()

			ctx := context.Background()
			// Use a dummy provider that passes validation
			provider := clientCredentialsProvider(server.URL+"/token", AuthMethodPost)
			provider.Issuer = tc.issuer

			_, err := NewClientCredentials(ctx, tc.issuer, tc.clientID, tc.clientSecret,
				WithClientCredentialsProviderMetadata(provider))

			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error to contain %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestClientCredentials_Token_BasicAuth(t *testing.T) {
	var requestBody string
	var authHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodBasic)

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsAuthMethod(AuthMethodBasic))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	want := &Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}
	if diff := cmp.Diff(want, token, cmpopts.IgnoreUnexported(Token{})); diff != "" {
		t.Errorf("Token() mismatch (-want +got):\n%s", diff)
	}
	if err := token.DecodeRaw(&map[string]any{}); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if token.IDToken != "" {
		t.Errorf("Token().IDToken = %q, want empty", token.IDToken)
	}

	if authHeader == "" {
		t.Error("expected Authorization header, got none")
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		t.Errorf("expected Basic auth, got: %s", authHeader)
	}

	if strings.Contains(requestBody, "client_id") || strings.Contains(requestBody, "client_secret") {
		t.Error("credentials should not be in body for Basic auth")
	}

	if !strings.Contains(requestBody, "grant_type=client_credentials") {
		t.Error("expected grant_type=client_credentials in body")
	}
}

func TestClientCredentials_Token_PostAuth(t *testing.T) {
	var requestBody string
	var authHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodPost)

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsAuthMethod(AuthMethodPost))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	want := &Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}
	if diff := cmp.Diff(want, token, cmpopts.IgnoreUnexported(Token{})); diff != "" {
		t.Errorf("Token() mismatch (-want +got):\n%s", diff)
	}
	if token.IDToken != "" {
		t.Errorf("Token().IDToken = %q, want empty", token.IDToken)
	}

	if authHeader != "" {
		t.Errorf("expected no Authorization header for Post auth, got: %s", authHeader)
	}

	if !strings.Contains(requestBody, "client_id=client-id") {
		t.Errorf("expected client_id in body, got: %s", requestBody)
	}
	if !strings.Contains(requestBody, "client_secret=client-secret") {
		t.Errorf("expected client_secret in body, got: %s", requestBody)
	}
}

func TestClientCredentials_Token_Scopes(t *testing.T) {
	var requestBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodPost)

	t.Run("default scopes from constructor", func(t *testing.T) {
		client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
			WithClientCredentialsProviderMetadata(provider),
			WithClientCredentialsScopes("api:read", "api:write"))
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		_, err = client.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		if !strings.Contains(requestBody, "scope=api%3Aread+api%3Awrite") && !strings.Contains(requestBody, "scope=api%3Aread%20api%3Awrite") {
			t.Errorf("expected scopes in body, got: %s", requestBody)
		}
	})

	t.Run("per-request scopes override", func(t *testing.T) {
		client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
			WithClientCredentialsProviderMetadata(provider),
			WithClientCredentialsScopes("api:read"))
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		ctxWithScopes := WithTokenScopes(ctx, "admin:all", "admin:users")
		_, err = client.Token(ctxWithScopes)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		if !strings.Contains(requestBody, "scope=admin%3Aall+admin%3Ausers") && !strings.Contains(requestBody, "scope=admin%3Aall%20admin%3Ausers") {
			t.Errorf("expected override scopes in body, got: %s", requestBody)
		}
	})

	t.Run("no scopes when none configured", func(t *testing.T) {
		client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
			WithClientCredentialsProviderMetadata(provider))
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		_, err = client.Token(ctx)
		if err != nil {
			t.Fatalf("Token() error: %v", err)
		}

		if strings.Contains(requestBody, "scope=") {
			t.Errorf("expected no scope in body when not configured, got: %s", requestBody)
		}
	})
}

func TestClientCredentials_Token_ErrorResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    string
	}{
		{
			name:       "invalid client",
			statusCode: http.StatusUnauthorized,
			response:   `{"error": "invalid_client", "error_description": "Client authentication failed"}`,
			wantErr:    "401",
		},
		{
			name:       "invalid scope",
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid_scope", "error_description": "Requested scope is invalid"}`,
			wantErr:    "400",
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			response:   `not valid json`,
			wantErr:    "decode",
		},
		{
			name:       "missing access_token",
			statusCode: http.StatusOK,
			response:   `{"token_type": "Bearer"}`,
			wantErr:    "access_token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.response))
			}))
			defer server.Close()

			ctx := context.Background()
			provider := clientCredentialsProvider(server.URL, AuthMethodPost)

			client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
				WithClientCredentialsProviderMetadata(provider))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			_, err = client.Token(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantErr != "" && !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Errorf("expected error to contain %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestClientCredentials_Token_Fallback(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// First request with Post auth (no Authorization header) should fail
		// Second request with Basic auth should succeed
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "invalid_request",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "success-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	// Provider with no supported auth methods listed triggers fallback behavior
	provider := clientCredentialsProvider(server.URL)

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "client-secret",
		WithClientCredentialsProviderMetadata(provider))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	if token.AccessToken != "success-token" {
		t.Errorf("expected success-token, got: %s", token.AccessToken)
	}

	if requestCount != 2 {
		t.Errorf("expected 2 requests (first failing, second succeeding), got: %d", requestCount)
	}

	requestCount = 0
	token, err = client.Token(ctx)
	if err != nil {
		t.Fatalf("second Token() error: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 request after fallback (cached method), got: %d", requestCount)
	}
}

func TestClientCredentials_Token_PrivateKeyJWT(t *testing.T) {
	var requestBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "jwt-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodPrivateKeyJWT)

	// Generate a real RSA key for testing
	keyProvider, err := createTestKeyProvider()
	if err != nil {
		t.Fatalf("failed to create test key provider: %v", err)
	}

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsKeyProvider(keyProvider),
		WithClientCredentialsAuthMethod(AuthMethodPrivateKeyJWT))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	if token.AccessToken != "jwt-token" {
		t.Errorf("expected jwt-token, got: %s", token.AccessToken)
	}

	if !strings.Contains(requestBody, "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer") {
		t.Errorf("expected client_assertion_type in body, got: %s", requestBody)
	}
	if !strings.Contains(requestBody, "client_assertion=") {
		t.Errorf("expected client_assertion in body, got: %s", requestBody)
	}
}

func TestClientCredentials_Discovery(t *testing.T) {
	requestCount := 0
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected discovery path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(providerMetadataJSON(issuer)))
	}))
	defer ts.Close()
	issuer = ts.URL

	ctx := context.Background()

	_, err := NewClientCredentials(ctx, issuer, "client-id", "client-secret",
		WithClientCredentialsHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 discovery request, got: %d", requestCount)
	}
}

func TestWithTokenScopes(t *testing.T) {
	ctx := context.Background()

	t.Run("add scopes to context", func(t *testing.T) {
		scopes := []string{"scope1", "scope2"}
		ctxWithScopes := WithTokenScopes(ctx, scopes...)

		got := tokenScopesFromContext(ctxWithScopes)
		want := []string{"scope1", "scope2"}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("tokenScopesFromContext() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("nil context returns nil", func(t *testing.T) {
		got := tokenScopesFromContext(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty context returns nil", func(t *testing.T) {
		got := tokenScopesFromContext(ctx)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

type mockKeyProvider struct {
	alg string
	kid string
}

func clientCredentialsProvider(tokenEndpoint string, authMethods ...AuthMethod) metadata.Provider {
	supportedAuthMethods := make([]string, len(authMethods))
	for i, method := range authMethods {
		supportedAuthMethods[i] = string(method)
	}

	return metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://auth.example.com",
			TokenEndpoint:                     tokenEndpoint,
			TokenEndpointAuthMethodsSupported: supportedAuthMethods,
		},
	}
}

func (m *mockKeyProvider) PrivateKey() crypto.PrivateKey {
	return nil
}

func (m *mockKeyProvider) KeyID() string {
	return m.kid
}

func (m *mockKeyProvider) SigningAlgorithm() string {
	return m.alg
}

func (m *mockKeyProvider) TLSCertificate() *tls.Certificate {
	return nil
}

func createTestKeyProvider() (ClientKeyProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return NewStaticClientKeyProvider(key, "test-key", "RS256", nil), nil
}

func TestClientCredentials_Token_DPoP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	requests := 0
	var firstDPoP string
	var secondDPoP string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstDPoP = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondDPoP = proof

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "dpop-token",
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodPrivateKeyJWT)

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithClientCredentialsAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientCredentialsSenderConstrain("dpop"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	if token.AccessToken != "dpop-token" {
		t.Errorf("expected dpop-token, got: %s", token.AccessToken)
	}

	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("request count mismatch (-want +got):\n%s", diff)
	}
	if firstDPoP == "" || secondDPoP == "" {
		t.Fatal("expected DPoP header to be set on both requests")
	}
	if firstDPoP == secondDPoP {
		t.Fatal("expected nonce retry to generate a different DPoP proof")
	}
	if diff := cmp.Diff("DPoP", token.TokenType); diff != "" {
		t.Fatalf("token type mismatch (-want +got):\n%s", diff)
	}
}

func TestClientCredentials_Token_DPoP_TLSClientAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	var gotDPoP string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mtls-dpop-token",
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodTLSClientAuth)

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", &tls.Certificate{})),
		WithClientCredentialsAuthMethod(AuthMethodTLSClientAuth),
		WithClientCredentialsSenderConstrain("dpop"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	if token.AccessToken != "mtls-dpop-token" {
		t.Errorf("expected mtls-dpop-token, got: %s", token.AccessToken)
	}
	if gotDPoP == "" {
		t.Fatal("expected DPoP header to be set")
	}
}

func TestClientCredentials_Token_MTLSSenderConstrainDisablesDPoP(t *testing.T) {
	var gotDPoP string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "no-dpop-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodPrivateKeyJWT)
	keyProvider, err := createTestKeyProvider()
	if err != nil {
		t.Fatalf("failed to create test key provider: %v", err)
	}

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsKeyProvider(keyProvider),
		WithClientCredentialsAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientCredentialsSenderConstrain("mtls"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	if token.AccessToken != "no-dpop-token" {
		t.Errorf("expected no-dpop-token, got: %s", token.AccessToken)
	}
	if gotDPoP != "" {
		t.Fatalf("expected no DPoP header when mtls sender constraint is set, got %q", gotDPoP)
	}
}

func TestClientCredentials_Token_StoresNonceFromSuccessfulResponse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	requests := 0
	var secondProofNonce string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			_ = proof
			w.Header().Set("DPoP-Nonce", "cc-fresh-nonce")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "cc-token",
				"token_type":   "DPoP",
				"expires_in":   3600,
			})
			return
		}

		secondProofNonce = extractNonceFromDPoPProof(t, proof)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cc-token-2",
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodPrivateKeyJWT)

	client, err := NewClientCredentials(ctx, "https://auth.example.com", "client-id", "",
		WithClientCredentialsProviderMetadata(provider),
		WithClientCredentialsKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithClientCredentialsAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientCredentialsSenderConstrain("dpop"),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials(): %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token(): %v", err)
	}
	if diff := cmp.Diff("cc-token", token.AccessToken); diff != "" {
		t.Fatalf("token mismatch (-want +got):\n%s", diff)
	}

	token2, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("second Token(): %v", err)
	}
	if diff := cmp.Diff("cc-token-2", token2.AccessToken); diff != "" {
		t.Fatalf("second token mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff("cc-fresh-nonce", secondProofNonce); diff != "" {
		t.Fatalf("second request nonce mismatch (-want +got):\n%s", diff)
	}
}

func extractNonceFromDPoPProof(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid DPoP proof format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode DPoP payload: %v", err)
	}
	var payload struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to parse DPoP payload: %v", err)
	}
	return payload.Nonce
}
