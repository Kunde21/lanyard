package rp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

func ExampleNew() {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
  "issuer": %q,
  "authorization_endpoint": %q,
  "token_endpoint": %q,
  "jwks_uri": %q,
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks")
	}))
	defer server.Close()
	issuer = server.URL

	// Construct a browser-flow RP. New discovers provider metadata and
	// creates a default in-memory state store.
	rpClient, err := rp.New(
		context.Background(),
		issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithHTTPClient(server.Client()),
		rp.WithMetadataClient(metadata.NewClient(metadata.WithHTTPClient(server.Client()))),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate an authorization URL to redirect the browser.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.Background())
	authURL, err := rpClient.AuthorizationURL(rec, req)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(authURL != "")
	// Output: true
}

func ExampleWithResources_clientCredentials() {
	// Use WithResources to request an audience-restricted access token for an API.
	_, _ = rp.NewClientCredentials(
		context.Background(),
		"https://issuer.example.com",
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithResources("https://api.example.com/"),
	)
	// Output:
}
