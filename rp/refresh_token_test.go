package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func TestRefreshToken_RequestShape(t *testing.T) {
	var gotBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "new-access",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "rotated-refresh",
		})
	}))
	defer server.Close()

	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     server.URL,
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(server.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}

	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("rotated-refresh", token.RefreshToken); diff != "" {
		t.Fatalf("RefreshToken mismatch (-want +got):\n%s", diff)
	}

	if want := "grant_type=refresh_token&refresh_token=old-refresh-token"; gotBody != want {
		t.Fatalf("request body mismatch:\nwant: %s\n got: %s", want, gotBody)
	}
}

func TestRefreshTokenOnce_PostAuth(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "new-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods("client_secret_post")),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, _, _, err := r.refreshTokenOnce(context.Background(), ts.URL, "rt", AuthMethodPost, "")
	if err != nil {
		t.Fatalf("refreshTokenOnce() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}

	wantFields := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "rt",
		"client_id":     "client",
		"client_secret": "secret",
	}
	for key, want := range wantFields {
		if diff := cmp.Diff(want, gotForm.Get(key)); diff != "" {
			t.Fatalf("form %q mismatch (-want +got):\n%s", key, diff)
		}
	}
}

func TestRefreshTokenOnce_NoneAuth(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "new-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("none")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodNone),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, _, _, err := r.refreshTokenOnce(context.Background(), ts.URL, "rt", AuthMethodNone, "")
	if err != nil {
		t.Fatalf("refreshTokenOnce() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("client", gotForm.Get("client_id")); diff != "" {
		t.Fatalf("client_id mismatch (-want +got):\n%s", diff)
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatalf("client_secret should not be present for none auth")
	}
}

func TestRefreshToken_Success(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "new-access",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "rotated",
		})
	}))
	defer ts.Close()

	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     ts.URL,
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	rp, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := rp.RefreshToken(context.Background(), "old-rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("rotated", token.RefreshToken); diff != "" {
		t.Fatalf("RefreshToken mismatch (-want +got):\n%s", diff)
	}
}

func TestRefreshToken_EmptyToken(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.RefreshToken(context.Background(), "")
	if err == nil {
		t.Fatalf("RefreshToken() expected error for empty token")
	}
	if !errors.Is(err, ErrRefreshTokenFailed) {
		t.Fatalf("expected ErrRefreshTokenFailed, got: %v", err)
	}
}

func TestRefreshToken_ServerError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer ts.Close()

	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     ts.URL,
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.RefreshToken(context.Background(), "old-rt")
	if err == nil {
		t.Fatalf("RefreshToken() expected error for server error")
	}
	if !errors.Is(err, ErrRefreshTokenFailed) {
		t.Fatalf("expected ErrRefreshTokenFailed, got: %v", err)
	}
}

func TestRefreshToken_FallbackPostToBasic(t *testing.T) {
	requests := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "new-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods()
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("expected 2 requests (fallback), got %d", requests)
	}
}

func TestRefreshToken_RetriesWithDpopNonce(t *testing.T) {
	key := testRSAKey(t)
	requests := 0
	var firstProof string
	var secondProof string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstProof = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondProof = proof
		if proof == "" {
			t.Fatalf("expected DPoP header on second request")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{AccessToken: "new-access", TokenType: "DPoP"})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("private_key_jwt")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret(""),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
	if firstProof == secondProof {
		t.Fatalf("expected second proof to differ from first proof (should include new nonce)")
	}
}

func TestRefreshToken_PreservesRawPayload(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated","transaction_id":"txn-42"}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods("client_secret_basic")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "old-rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}

	txn, err := token.Extra("transaction_id")
	if err != nil {
		t.Fatalf("Extra() failed: %v", err)
	}
	if diff := cmp.Diff("txn-42", txn); diff != "" {
		t.Fatalf("transaction_id mismatch (-want +got):\n%s", diff)
	}
	if err := token.DecodeRaw(&map[string]any{}); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
}
