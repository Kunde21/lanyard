package rp

import (
	"context"
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
		"client",
		"secret",
		"https://rp.test/callback",
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
		"client",
		"secret",
		"https://rp.test/callback",
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
		"client",
		"secret",
		"https://rp.test/callback",
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
		"client",
		"secret",
		"https://rp.test/callback",
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
