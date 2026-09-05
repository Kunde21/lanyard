package rp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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

// ExampleWithClaims_identityAssurance builds an OpenID Connect for Identity
// Assurance request: verified given and family names under any trust
// framework, with the verification performed no more than two years ago.
func ExampleWithClaims_identityAssurance() {
	maxAge := int64(2 * 365 * 24 * 60 * 60)

	claims := rp.NewClaimsRequest()
	err := claims.AddVerifiedClaimsToUserInfo(rp.VerifiedClaimsFilter{
		Verification: &rp.VerificationFilter{
			TrustFramework: &rp.Constrainable{}, // any framework
			Time:           &rp.Constrainable{MaxAge: &maxAge},
		},
		Claims: map[string]*rp.ClaimConstraint{
			"given_name":  {Essential: boolPtr(true)},
			"family_name": {Essential: boolPtr(true)},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	raw, err := claims.JSON()
	if err != nil {
		fmt.Println(err)
		return
	}

	rpClient, err := rp.New(
		context.Background(),
		"https://issuer.example.com",
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                 "https://issuer.example.com",
				AuthorizationEndpoint:  "https://issuer.example.com/authorize",
				TokenEndpoint:          "https://issuer.example.com/token",
				JWKSURI:                "https://issuer.example.com/jwks",
				ResponseTypesSupported: []string{"code"},
			},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}),
		rp.WithClaims(raw),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = rpClient
	fmt.Println("claims request configured")
	// Output: claims request configured
}

func boolPtr(v bool) *bool { return &v }

// ExampleParseVerifiedClaims extracts identity assurance data from a
// UserInfo payload and checks the verification freshness.
func ExampleParseVerifiedClaims() {
	payload := map[string]any{
		"sub": "248289761",
		"verified_claims": map[string]any{
			"verification": map[string]any{
				"trust_framework": "de_aml",
				"time":            "2026-01-15T10:30:00Z",
			},
			"claims": map[string]any{
				"given_name":  "Max",
				"family_name": "Meier",
			},
		},
	}

	verified, err := rp.ParseVerifiedClaims(payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(verified[0].Verification.TrustFramework, verified[0].Claims["given_name"])

	fresh := verified[0].Verification.FreshFor(
		365*24*time.Hour,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	)
	fmt.Println("verified within the last year:", fresh)
	// Output:
	// de_aml Max
	// verified within the last year: true
}

// ExampleNewIntrospector queries token state at an authorization server
// supporting RFC 7662 introspection.
func ExampleNewIntrospector() {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer": %q, "introspection_endpoint": %q,
				"authorization_endpoint": %q,
				"token_endpoint": %q, "jwks_uri": %q,
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"],
				"token_endpoint_auth_methods_supported": ["client_secret_basic"]}`,
				issuer, issuer+"/introspect", issuer+"/authorize", issuer+"/token", issuer+"/jwks")
		case "/introspect":
			fmt.Fprint(w, `{"active": true, "scope": "read write", "client_id": "client-id"}`)
		}
	}))
	defer server.Close()
	issuer = server.URL

	introspector, err := rp.NewIntrospector(
		context.Background(),
		issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithHTTPClient(server.Client()),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	resp, err := introspector.IntrospectToken(context.Background(), rp.IntrospectionRequest{
		Token: "the-opaque-access-token",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("active:", resp.Active, "scopes:", resp.Scope)
	// Output:
	// active: true scopes: read write
}

// ExampleNewRegistrar registers a client dynamically (RFC 7591) and splices
// the issued credentials into a browser-flow RP.
func ExampleNewRegistrar() {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer": %q, "registration_endpoint": %q,
				"authorization_endpoint": %q, "token_endpoint": %q, "jwks_uri": %q,
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"],
				"token_endpoint_auth_methods_supported": ["client_secret_basic"]}`,
				issuer, issuer+"/register", issuer+"/authorize", issuer+"/token", issuer+"/jwks")
		case "/register":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"client_id": "s6BhdRkqt3", "client_secret": "cf8DCbyUSm0boaf3"}`)
		}
	}))
	defer server.Close()
	issuer = server.URL

	registrar, err := rp.NewRegistrar(
		context.Background(),
		issuer,
		rp.WithHTTPClient(server.Client()),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	registration, err := registrar.Register(context.Background(), rp.ClientMetadata{
		RedirectURIs:            []string{"https://rp.example.com/callback"},
		TokenEndpointAuthMethod: rp.AuthMethodBasic,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "My Example Client",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("registered as", registration.ClientID, "manageable:", registration.Manageable())

	// Splice the issued credentials into a browser-flow RP.
	rpClient, err := rp.New(
		context.Background(),
		issuer,
		append(registration.Options(),
			rp.WithRedirectURI("https://rp.example.com/callback"),
			rp.WithHTTPClient(server.Client()),
		)...,
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = rpClient
	// Output:
	// registered as s6BhdRkqt3 manageable: false
}

// ExampleNewRefreshTokenSource tracks refresh token rotation (RFC 9700):
// concurrent or repeated refreshes always use the token the server most
// recently issued.
func ExampleNewRefreshTokenSource() {
	issued := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issued++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "at-%d", "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": "refresh-%d"}`, issued, issued)
	}))
	defer server.Close()

	rpClient, err := rp.New(
		context.Background(),
		"https://issuer.example.com",
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithHTTPClient(server.Client()),
		rp.WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                 "https://issuer.example.com",
				AuthorizationEndpoint:  "https://issuer.example.com/authorize",
				TokenEndpoint:          server.URL + "/token",
				JWKSURI:                "https://issuer.example.com/jwks",
				ResponseTypesSupported: []string{"code"},
			},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	source, err := rp.NewRefreshTokenSource(rpClient, "refresh-0")
	if err != nil {
		fmt.Println(err)
		return
	}

	if _, err := source.Refresh(context.Background()); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("current refresh token:", source.CurrentRefreshToken())
	// Output:
	// current refresh token: refresh-1
}

// ExampleRP_QueryGrant reads a grant's status through the Grant Management
// API with a caller-supplied access token.
func ExampleRP_QueryGrant() {
	issuer := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer": %q, "authorization_endpoint": %q,
				"token_endpoint": %q, "jwks_uri": %q,
				"grant_management_endpoint": %q,
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"],
				"token_endpoint_auth_methods_supported": ["client_secret_basic"]}`,
				issuer, issuer+"/authorize", issuer+"/token", issuer+"/jwks", issuer+"/grants")
		default:
			fmt.Fprint(w, `{"scopes": [{"scope": "read", "resource": ["https://api.example.com/"]}],
				"updated_by": "client"}`)
		}
	}))
	defer server.Close()
	issuer = server.URL

	rpClient, err := rp.New(
		context.Background(),
		issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithHTTPClient(server.Client()),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	// The access token is obtained out of band with the
	// grant_management_query scope.
	status, err := rpClient.QueryGrant(context.Background(), "gm-access-token", "TSdqirmAxDa0")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("updated by:", status.UpdatedBy, "scopes:", len(status.Scopes))
	// Output:
	// updated by: client scopes: 1
}

// ExampleOAuthError shows branching on the typed token endpoint error: an
// invalid_grant refresh failure carries ErrRefreshTokenRejected.
func ExampleOAuthError() {
	err := fmt.Errorf("refresh failed: %w", fmt.Errorf("%w: %w",
		rp.ErrRefreshTokenRejected,
		&rp.OAuthError{Code: "invalid_grant", Status: 400}))

	var oauthErr *rp.OAuthError
	switch {
	case errors.Is(err, rp.ErrRefreshTokenRejected):
		fmt.Println("discard the refresh token and restart the flow")
	case errors.As(err, &oauthErr):
		fmt.Println("oauth error:", oauthErr.Code)
	default:
		fmt.Println("other failure")
	}
	// Output:
	// discard the refresh token and restart the flow
}

// ExampleWithTracerProvider wires an OpenTelemetry tracer provider so the
// library's spans flow to the application's telemetry backend.
func ExampleWithTracerProvider() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}`)
	}))
	defer server.Close()

	// Any trace.TracerProvider works; a real application would use the SDK
	// provider configured with its exporter.
	provider := sdktrace.NewTracerProvider()
	defer provider.Shutdown(context.Background())

	credentials, err := rp.NewClientCredentials(
		context.Background(),
		"https://issuer.example.com",
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithTracerProvider(provider),
		rp.WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                 "https://issuer.example.com",
				AuthorizationEndpoint:  "https://issuer.example.com/authorize",
				TokenEndpoint:          server.URL + "/token",
				JWKSURI:                "https://issuer.example.com/jwks",
				ResponseTypesSupported: []string{"code"},
			},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}),
		rp.WithHTTPClient(server.Client()),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	token, err := credentials.Token(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("token issued:", token.AccessToken != "")
	// Output:
	// token issued: true
}
