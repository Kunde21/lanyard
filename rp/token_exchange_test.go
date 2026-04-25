package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBuildTokenRequestEnvelope(t *testing.T) {
	tests := []struct {
		name              string
		method            AuthMethod
		form              url.Values
		wantAuthorization string
	}{
		{
			name:   "basic auth header",
			method: AuthMethodBasic,
			form: url.Values{
				"grant_type": {"authorization_code"},
			},
			wantAuthorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret")),
		},
		{
			name:   "post auth keeps form credentials",
			method: AuthMethodPost,
			form: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"client"},
				"client_secret": {"secret"},
			},
		},
		{
			name:   "self signed tls auth keeps caller supplied client id",
			method: AuthMethodSelfSignedTLSClientAuth,
			form: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildTokenRequestEnvelope(context.Background(), "https://issuer.test/token", tc.form, tc.method, "client", "secret")
			if err != nil {
				t.Fatalf("buildTokenRequestEnvelope() failed: %v", err)
			}

			if diff := cmp.Diff(http.MethodPost, req.Method); diff != "" {
				t.Fatalf("method mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff("https://issuer.test/token", req.URL.String()); diff != "" {
				t.Fatalf("url mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff("application/x-www-form-urlencoded", req.Header.Get("Content-Type")); diff != "" {
				t.Fatalf("content type mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantAuthorization, req.Header.Get("Authorization")); diff != "" {
				t.Fatalf("authorization mismatch (-want +got):\n%s", diff)
			}

			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("ReadAll() failed: %v", err)
			}
			gotForm, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("ParseQuery() failed: %v", err)
			}
			if diff := cmp.Diff(tc.form, gotForm); diff != "" {
				t.Fatalf("form mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExchangeTokenRequestShape(t *testing.T) {
	var gotContentType string
	var gotAuthorization string
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAuthorization = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
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
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	if diff := cmp.Diff("application/x-www-form-urlencoded", gotContentType); diff != "" {
		t.Fatalf("content type mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")), gotAuthorization); diff != "" {
		t.Fatalf("authorization header mismatch (-want +got):\n%s", diff)
	}

	wantForm := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"redirect_uri":  "https://rp.test/callback",
		"code_verifier": "verifier",
	}
	for key, want := range wantForm {
		if gotForm.Get(key) != want {
			t.Fatalf("form %q mismatch: want %q got %q", key, want, gotForm.Get(key))
		}
	}

	if got.AccessToken == "" || got.IDToken == "" {
		t.Fatalf("token response missing expected fields")
	}
	if err := got.DecodeRaw(&map[string]any{}); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if _, err := got.Extra("transaction_id"); err == nil {
		t.Fatalf("Extra(transaction_id) expected error when field is absent")
	}
}

func TestExchangeToken_PreservesRawPayload(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"idtoken","authorization_details":[{"type":"account_information"}],"transaction_id":"txn-1"}`)
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	txn, err := token.Extra("transaction_id")
	if err != nil {
		t.Fatalf("Extra() failed: %v", err)
	}
	if diff := cmp.Diff("txn-1", txn); diff != "" {
		t.Fatalf("transaction_id mismatch (-want +got):\n%s", diff)
	}
}

func TestExchangeTokenNon200PreviewBounded(t *testing.T) {
	const giant = 8000
	body := strings.Repeat("x", giant)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, body)
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err == nil {
		t.Fatalf("exchangeToken() expected error")
	}
	if !strings.Contains(err.Error(), ErrTokenExchangeFailed.Error()) {
		t.Fatalf("error mismatch: %v", err)
	}
	if len(err.Error()) > maxErrorBodyBytes+300 {
		t.Fatalf("error preview exceeded max bytes")
	}
}

func TestExchangeTokenRequestShapePostAuth(t *testing.T) {
	var gotContentType string
	var gotAuthorization string
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAuthorization = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
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

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	if diff := cmp.Diff("application/x-www-form-urlencoded", gotContentType); diff != "" {
		t.Fatalf("content type mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("", gotAuthorization); diff != "" {
		t.Fatalf("authorization header mismatch (-want +got):\n%s", diff)
	}

	wantForm := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"redirect_uri":  "https://rp.test/callback",
		"code_verifier": "verifier",
		"client_id":     "client",
		"client_secret": "secret",
	}
	for key, want := range wantForm {
		if gotForm.Get(key) != want {
			t.Fatalf("form %q mismatch: want %q got %q", key, want, gotForm.Get(key))
		}
	}
}

func TestExchangeTokenFallbackFromPostToBasicAndCaches(t *testing.T) {
	type requestCapture struct {
		authorization string
		form          url.Values
	}

	requests := make([]requestCapture, 0, 3)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		requests = append(requests, requestCapture{
			authorization: r.Header.Get("Authorization"),
			form:          form,
		})

		if len(requests) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
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
		WithProviderMetadata(providerForAuthMethods()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff(AuthMethodPost, r.resolvedAuthMethod); diff != "" {
		t.Fatalf("initial resolved auth method mismatch (-want +got):\n%s", diff)
	}
	if !r.allowMethodFallback {
		t.Fatalf("allowMethodFallback should be true when metadata omits supported methods")
	}

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("first exchangeToken() failed: %v", err)
	}

	if diff := cmp.Diff(2, len(requests)); diff != "" {
		t.Fatalf("request count mismatch after fallback attempt (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("", requests[0].authorization); diff != "" {
		t.Fatalf("first authorization header mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("client", requests[0].form.Get("client_id")); diff != "" {
		t.Fatalf("first request client_id mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("secret", requests[0].form.Get("client_secret")); diff != "" {
		t.Fatalf("first request client_secret mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff("Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")), requests[1].authorization); diff != "" {
		t.Fatalf("second authorization header mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("", requests[1].form.Get("client_id")); diff != "" {
		t.Fatalf("second request client_id should be empty (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("", requests[1].form.Get("client_secret")); diff != "" {
		t.Fatalf("second request client_secret should be empty (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(AuthMethodBasic, r.resolvedAuthMethod); diff != "" {
		t.Fatalf("resolved auth method mismatch after fallback (-want +got):\n%s", diff)
	}
	if r.allowMethodFallback {
		t.Fatalf("allowMethodFallback should be false after successful fallback")
	}

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code-2", "verifier")
	if err != nil {
		t.Fatalf("second exchangeToken() failed: %v", err)
	}

	if diff := cmp.Diff(3, len(requests)); diff != "" {
		t.Fatalf("request count mismatch after cached retry (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")), requests[2].authorization); diff != "" {
		t.Fatalf("third authorization header mismatch (-want +got):\n%s", diff)
	}
}

func TestExchangeToken_RetriesWithDpopNonce(t *testing.T) {
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
		_ = json.NewEncoder(w).Encode(Token{AccessToken: "access", TokenType: "DPoP", IDToken: "idtoken"})
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

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}

	if firstProof == secondProof {
		t.Fatalf("expected second proof to differ from first proof (should include new nonce)")
	}
}

func TestExchangeToken_StoresNonceFromSuccessfulResponse(t *testing.T) {
	key := testRSAKey(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "fresh-nonce")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{AccessToken: "token", TokenType: "DPoP", IDToken: "idtoken"})
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

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	cachedNonce, ok := r.DPoPNonceForEndpoint(ts.URL)
	if !ok {
		t.Fatal("expected nonce to be cached from successful response")
	}
	if diff := cmp.Diff("fresh-nonce", cachedNonce); diff != "" {
		t.Fatalf("cached nonce mismatch (-want +got):\n%s", diff)
	}
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func TestExchangeTokenRequestShape_SelfSignedTLSClientAuth(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("self_signed_tls_client_auth")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	wantForm := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"redirect_uri":  "https://rp.test/callback",
		"code_verifier": "verifier",
		"client_id":     "client",
	}
	for key, want := range wantForm {
		if gotForm.Get(key) != want {
			t.Fatalf("form %q mismatch: want %q got %q", key, want, gotForm.Get(key))
		}
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatalf("client_secret should not be present for self_signed_tls_client_auth")
	}
}
