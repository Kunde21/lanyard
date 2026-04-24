package rp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
	"github.com/Kunde21/lanyard/rp/store/cookie"
)

func Example_readmeBrowserRPFlow() {
	ctx := context.Background()
	provider, httpClient := readmeProviderMetadata()

	stateStore, err := cookie.New(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("abcdef0123456789abcdef0123456789"),
		cookie.WithTTL(10*time.Minute),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	rpClient, err := rp.New(
		ctx,
		provider.Issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithStateStore(stateStore),
		rp.WithScopes("openid", "profile", "email"),
		rp.WithProviderMetadata(provider),
		rp.WithHTTPClient(httpClient),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	login := func(w http.ResponseWriter, r *http.Request) {
		authURL, err := rpClient.AuthorizationURL(w, r)
		if err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}

	callback := func(w http.ResponseWriter, r *http.Request) {
		result, err := rpClient.HandleCallback(w, r)
		if err != nil {
			http.Error(w, "callback failed", http.StatusBadRequest)
			return
		}

		_, _ = result.Subject, result.UserInfo
	}

	_, _ = login, callback
	fmt.Println("handlers configured")
	// Output: handlers configured
}

func Example_readmeBrowserRPWithPreloadedProvider() {
	ctx := context.Background()
	provider, _ := readmeProviderMetadata()

	rpClient, err := rp.New(
		ctx,
		provider.Issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithProviderMetadata(provider),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	_ = rpClient
	fmt.Println("rp configured")
	// Output: rp configured
}

func Example_readmeDiscoverProvider() {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, readmeProviderMetadataJSON(issuer))
	}))
	defer server.Close()
	issuer = server.URL

	provider, err := rp.DiscoverProvider(
		context.Background(),
		issuer,
		rp.WithDiscoveryHTTPClient(server.Client()),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(provider.Issuer == issuer)
	// Output: true
}

func Example_readmeClientCredentialsConstruction() {
	ctx := context.Background()
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:        "https://auth.example.com",
			TokenEndpoint: "https://auth.example.com/token",
		},
	}

	client, err := rp.NewClientCredentials(
		ctx,
		provider.Issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithProviderMetadata(provider),
		rp.WithScopes("api:read", "api:write"),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	adminCtx := rp.WithTokenScopes(ctx, "admin:all")
	_, _ = client, adminCtx
	fmt.Println("client credentials configured")
	// Output: client credentials configured
}

func readmeProviderMetadata() (metadata.Provider, *http.Client) {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, readmeProviderMetadataJSON(issuer))
	}))
	issuer = server.URL

	return metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/jwks.json",
		},
		UserinfoEndpoint: issuer + "/userinfo",
	}, server.Client()
}

func readmeProviderMetadataJSON(issuer string) string {
	return fmt.Sprintf(`{
		"issuer": %q,
		"authorization_endpoint": %q,
		"token_endpoint": %q,
		"userinfo_endpoint": %q,
		"jwks_uri": %q,
		"response_types_supported": ["code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256"]
	}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/userinfo", issuer+"/jwks.json")
}
