package rp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFetchUserInfo(t *testing.T) {
	var gotAuth string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","name":"Alice"}`)
	}))
	defer ts.Close()

	r, err := New(context.Background(), "https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()), WithProviderMetadata(providerForAuthMethods()))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}
	if gotAuth != "Bearer access-token" {
		t.Fatalf("Authorization header mismatch: %q", gotAuth)
	}
	if got["name"] != "Alice" {
		t.Fatalf("userinfo payload mismatch")
	}
}

func TestFetchUserInfoBodyTransport(t *testing.T) {
	var gotMethod string
	var gotAuth string
	var gotToken string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		gotToken = values.Get("access_token")

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","name":"Alice"}`)
	}))
	defer ts.Close()

	r, err := New(context.Background(), "https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()), WithProviderMetadata(providerForAuthMethods()))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportBody)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("userinfo request method mismatch: got %q", gotMethod)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization header should be empty in body mode, got %q", gotAuth)
	}
	if gotToken != "access-token" {
		t.Fatalf("access_token body parameter mismatch: %q", gotToken)
	}
}

func TestFetchUserInfoDistributedClaimsFromEndpoint(t *testing.T) {
	var distributedAuth string
	issuerURL := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"sub":"sub-123","_claim_names":{"email":"src1"},"_claim_sources":{"src1":{"endpoint":"`+issuerURL+`/claims","access_token":"source-token"}}}`)
		case "/claims":
			distributedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"sub":"sub-123","email":"alice@example.com"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuerURL = ts.URL

	r, err := New(context.Background(), "https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()), WithProviderMetadata(providerForAuthMethods()))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := r.fetchUserInfo(context.Background(), ts.URL+"/userinfo", "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}
	if distributedAuth != "Bearer source-token" {
		t.Fatalf("distributed claims auth mismatch: %q", distributedAuth)
	}
	if got["email"] != "alice@example.com" {
		t.Fatalf("distributed claim was not merged")
	}
}

func TestFetchUserInfoDistributedClaimsJWT(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"sub-123","email":"alice@example.com"}`))
	jwt := "header." + payload + ".signature"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","_claim_names":{"email":"src1"},"_claim_sources":{"src1":{"JWT":"`+jwt+`"}}}`)
	}))
	defer ts.Close()

	r, err := New(context.Background(), "https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()), WithProviderMetadata(providerForAuthMethods()))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}
	if got["email"] != "alice@example.com" {
		t.Fatalf("distributed claim from JWT was not merged")
	}
}

func TestFetchUserInfoErrors(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		expectFail bool
	}{
		{name: "non-200", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "bad", http.StatusBadRequest) }, expectFail: true},
		{name: "invalid json", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "{") }, expectFail: true},
		{name: "sub mismatch", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, `{"sub":"other"}`) }, expectFail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(tt.handler)
			defer ts.Close()

			r, err := New(context.Background(), "https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()), WithProviderMetadata(providerForAuthMethods()))
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			_, err = r.fetchUserInfo(context.Background(), ts.URL, "token", "sub-123", UserInfoTokenTransportHeader)
			if tt.expectFail && err == nil {
				t.Fatalf("fetchUserInfo() expected error")
			}
			if err != nil && !strings.Contains(err.Error(), ErrUserInfoValidationFailed.Error()) {
				t.Fatalf("error mismatch: %v", err)
			}
		})
	}
}

func TestFetchUserInfo_PrivateKeyJWTBearerWithoutSenderConstraint(t *testing.T) {
	key := testRSAKey(t)
	var gotAuth string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","name":"Alice"}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods("private_key_jwt")
	provider.UserinfoEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}

	if diff := cmp.Diff("Bearer access-token", gotAuth); diff != "" {
		t.Fatalf("Authorization header mismatch (-want +got):\n%s", diff)
	}
}

func TestFetchUserInfo_DPoPAuthorization(t *testing.T) {
	key := testRSAKey(t)
	var gotAuth string
	var gotDPoP string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDPoP = r.Header.Get("DPoP")

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","name":"Alice"}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods("private_key_jwt")
	provider.UserinfoEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}

	if !strings.HasPrefix(gotAuth, "DPoP ") {
		t.Fatalf("expected Authorization header to start with 'DPoP ', got %q", gotAuth)
	}

	if gotDPoP == "" {
		t.Fatalf("expected DPoP header to be set")
	}
}

func TestFetchUserInfo_RetriesWithDpopNonce(t *testing.T) {
	key := testRSAKey(t)
	requests := 0
	var firstAuth string
	var secondAuth string
	var firstProof string
	var secondProof string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		auth := r.Header.Get("Authorization")
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstAuth = auth
			firstProof = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondAuth = auth
		secondProof = proof
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","name":"Alice"}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods("private_key_jwt")
	provider.UserinfoEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}

	if diff := cmp.Diff(2, requests); diff != "" {
		t.Fatalf("request count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("DPoP access-token", firstAuth); diff != "" {
		t.Fatalf("first Authorization header mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("DPoP access-token", secondAuth); diff != "" {
		t.Fatalf("second Authorization header mismatch (-want +got):\n%s", diff)
	}
	if firstProof == "" || secondProof == "" {
		t.Fatalf("expected DPoP proofs on both requests")
	}
	if firstProof == secondProof {
		t.Fatalf("expected second proof to differ from first proof (should include new nonce)")
	}
}

func TestFetchUserInfo_StoresNonceFromSuccessfulResponse(t *testing.T) {
	key := testRSAKey(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "ui-fresh-nonce")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123"}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods("private_key_jwt")
	provider.UserinfoEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}

	cachedNonce, ok := r.DPoPNonceForEndpoint(ts.URL)
	if !ok {
		t.Fatal("expected cached nonce after userinfo")
	}
	if diff := cmp.Diff("ui-fresh-nonce", cachedNonce); diff != "" {
		t.Fatalf("cached nonce mismatch (-want +got):\n%s", diff)
	}
}
