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
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
		})
	}))
	defer ts.Close()

	r, err := New("https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()))
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

	r, err := New("https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()))
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
