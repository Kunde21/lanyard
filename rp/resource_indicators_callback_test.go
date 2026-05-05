package rp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp/store/memory"
	"github.com/google/go-cmp/cmp"
)

func TestHandleCallback_SendsAuthorizationResourcesToTokenEndpoint(t *testing.T) {
	var gotForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{AccessToken: "access", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer ts.Close()

	store := memory.New(10 * time.Second)
	provider := metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
		Issuer:                            "https://issuer.example.com",
		AuthorizationEndpoint:             "https://issuer.example.com/authorize",
		TokenEndpoint:                     ts.URL,
		JWKSURI:                           "https://issuer.example.com/jwks",
		ResponseTypesSupported:            []string{"code"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	}}
	r, err := New(
		context.Background(),
		"https://issuer.example.com",
		WithProfile(OAuth2),
		WithScopes("read"),
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.example.com/callback"),
		WithProviderMetadata(provider),
		WithStateStore(store),
		WithHTTPClient(ts.Client()),
		WithResources("https://api.example.com/", "https://payments.example.com/"),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	authURL, err := r.AuthorizationURL(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://rp.example.com/login", nil))
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	parsed, _ := url.Parse(authURL)
	state := parsed.Query().Get("state")

	callbackReq := httptest.NewRequest(http.MethodGet, "https://rp.example.com/callback?code=code-123&state="+url.QueryEscape(state), nil)
	if _, err := r.HandleCallback(httptest.NewRecorder(), callbackReq); err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}

	want := []string{"https://api.example.com/", "https://payments.example.com/"}
	if diff := cmp.Diff(want, gotForm["resource"]); diff != "" {
		t.Fatalf("token request resources mismatch (-want +got):\n%s", diff)
	}
}
