# Lanyard

Lanyard is a Go OpenID Connect (OIDC) and OAuth 2.0 relying party library.

## API Documentation

The source-of-truth API documentation is the Go package documentation:

*   `github.com/Kunde21/lanyard/rp` for relying-party flows and token APIs
*   `github.com/Kunde21/lanyard/metadata` for discovery and authorization server metadata
*   `github.com/Kunde21/lanyard/jwks` for remote JWKS retrieval
*   `github.com/Kunde21/lanyard/cache` for the default in-memory cache

README examples are introductory. Prefer `go doc` or pkg.go.dev for exact signatures, defaults, and option behavior.

## Capabilities

Lanyard implements a fully featured OIDC relying party (RP) with support for the Authorization Code flow with PKCE.

### Core Features

*   **Discovery**:
    *   Automatic OIDC provider discovery via `.well-known/openid-configuration`.
    *   OAuth 2.0 Authorization Server metadata discovery (RFC 8414).
    *   WebFinger discovery for issuer resolution.
    *   JWKS URI retrieval and caching.

*   **Authentication Flow**:
    *   Authorization Code flow with PKCE (RFC 7636).
    *   State management with supported stores:
        *   `rp/store/memory`
        *   `rp/store/cookie`
    *   Dynamic client authentication methods:
        *   `client_secret_basic`
        *   `client_secret_post`
        *   `client_secret_jwt`
        *   `private_key_jwt` (asymmetric signatures)
        *   `tls_client_auth` (mTLS)
        *   `self_signed_tls_client_auth`
    *   Pushed Authorization Requests (PAR) support.
    *   JWT Secured Authorization Requests (JAR).
    *   RP-hosted `request_uri` request object support for OIDC configuration variants.
    *   JWT Secured Authorization Response Mode (JARM).
    *   Rich Authorization Requests (RAR).
    *   Resource Indicators (RFC 8707): audience-restricted tokens via repeated `resource` parameters.

*   **Client Credentials Grant** (RFC 6749 §4.4):
    *   OAuth 2.0 Client Credentials flow for service-to-service authentication.
    *   Per-request scope customization via context.
    *   TokenSource interface (note: not golang.org/x/oauth2.TokenSource; ClientCredentials.Token performs a token request per call - wrap it with your own expiry-aware cache).

*   **Token & User Info**:
    *   ID Token validation (signature, claims, audience, expiration).
    *   User Info endpoint retrieval.
    *   Token exchange support (RFC 8693).
     *   Token introspection (RFC 7662) with signed and encrypted JWT response verification (RFC 9701).
     *   Grant management: create, merge, replace, query, and revoke grants (FAPI 2.0 Grant Management).
     *   Dynamic client registration and registration management (RFC 7591, RFC 7592).
     *   Identity assurance: verified_claims request builders, response parsing, and freshness checks (OpenID Connect for Identity Assurance 1.0).
     *   OpenTelemetry tracing with redaction-safe spans across all flows.
    *   DPoP (Demonstrating Proof-of-Possession) support.
    *   mTLS sender-constrained access token support.
    *   RFC 7800 `cnf` claim parsing and binding verification for sender-constrained tokens.

*   **Security & Validation**:
    *   HTTPS enforcement for issuer and redirect URIs.
    *   Clock skew tolerance configuration.
    *   Request/response validation helpers.

### Conformance Status

Lanyard is verified against the OpenID Foundation conformance suite (`104/104` plans, `1180/1180` tests passed) covering:

*   OpenID Connect Core Basic Certification
*   OpenID Connect Config Certification
*   OpenID Connect Form Post Basic Certification
*   FAPI 1.0 Advanced Final
*   FAPI 2.0 Security Profile Final
*   FAPI 2.0 Message Signing Final

See `conformance` package for local suite setup, harness usage, and run commands.

## Installation

```bash
go get github.com/Kunde21/lanyard
```

## Usage

### Browser RP Flow

```go
import (
	"context"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/rp"
	"github.com/Kunde21/lanyard/rp/store/cookie"
)

func setupRP(ctx context.Context) (*rp.RP, error) {
	// Fixture keys for illustration only: generate real 32-byte signing
	// and 16/24/32-byte encryption keys and load them from configuration.
	stateStore, err := cookie.New(
		[]byte("0123456789abcdef0123456789abcdef"), // signing key (fixture)
		[]byte("abcdef0123456789abcdef0123456789"), // encryption key (fixture)
		cookie.WithTTL(10*time.Minute),
	)
	if err != nil {
		return nil, err
	}

	return rp.New(
		ctx,
		"https://issuer.example.com",
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithStateStore(stateStore),
		rp.WithScopes("openid", "profile", "email"),
	)
	// If you already have provider info, add rp.WithProviderMetadata(provider)
	// and the constructor will skip discovery.
}

func handleLogin(rpClient *rp.RP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := rpClient.AuthorizationURL(w, r)
		if err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func handleCallback(rpClient *rp.RP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := rpClient.HandleCallback(w, r)
		if err != nil {
			http.Error(w, "callback failed", http.StatusBadRequest)
			return
		}

		_, _ = result.Subject, result.UserInfo
	}
}
```

### Production session storage and refresh

For example, a multi-instance web application can keep each user's token set in
an encrypted database row, keyed by an opaque application-session ID. The browser
receives only that ID in a `Secure; HttpOnly` session cookie, never the token set.
Application-session protection is separate from Lanyard's login correlation store.

Use this lifecycle:

1. After a successful callback, persist `CallbackResult.Token` and its issuer with
   the acquisition time and an absolute access-token expiry. `ExpiresIn` is a
   relative lifetime in seconds; compute expiry conservatively from the time just
   before starting the token exchange, with an application safety margin. Do not
   recompute expiry from the current time when loading a persisted token. If the
   lifetime is absent or unknown, do not assume the token is valid indefinitely.
2. Before refreshing, acquire exclusive coordination for the session across all
   application instances (for example, a database row lock in a transaction),
   then reload its latest persisted token. Reuse an unexpired access token rather
   than refreshing on every API call.
3. Construct `rp.NewRefreshTokenSource` from the stored refresh token and call
   `Refresh` under that same coordination. Persist the returned full token set,
   acquisition time and absolute expiry, and commit **before** another worker can
   load or refresh that session. The source preserves the prior refresh token
   when the provider validly omits a replacement.
4. If `errors.Is(err, rp.ErrRefreshTokenRejected)`, invalidate the application
   session and restart authorization. If the refresh response or database commit
   is uncertain, quarantine the session and recover or reauthorize rather than
   blindly retrying its old refresh token: the provider may already have rotated
   it. A database transaction cannot atomically commit the provider's rotation.

Keep coordination through the entire load/refresh/save sequence, not just the
HTTP call. Each `RefreshTokenSource` mutex protects only that instance; separately
constructed sources and separate processes do not share it. A distributed lease
must remain valid for the whole operation and prevent stale workers from writing.
Use bounded HTTP/database deadlines and protect stored tokens with encryption and
restricted access. JSON persistence retains the original provider payload;
clearing exported token fields does not securely erase secrets retained in it.
Never log token values. The runnable `ExampleNewRefreshTokenSource` demonstrates
in-process rotation, not a durable database implementation.

### Browser RP with Preloaded Provider

```go
import (
	"context"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

func newRP(ctx context.Context) (*rp.RP, error) {
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                "https://issuer.example.com",
			AuthorizationEndpoint: "https://issuer.example.com/authorize",
			TokenEndpoint:         "https://issuer.example.com/token",
			JWKSURI:               "https://issuer.example.com/jwks.json",
		},
		UserinfoEndpoint: "https://issuer.example.com/userinfo",
	}

	return rp.New(
		ctx,
		provider.Issuer,
		rp.WithClientID("client-id"),
		rp.WithClientSecret("client-secret"),
		rp.WithRedirectURI("https://rp.example.com/callback"),
		rp.WithProviderMetadata(provider),
	)
}
```

### Validate Provider Configuration

```go
import (
	"context"

	"github.com/Kunde21/lanyard/rp"
)

func validateIssuer(ctx context.Context, issuer string) error {
	provider, err := rp.DiscoverProvider(ctx, issuer)
	if err != nil {
		return err
	}

	_ = provider.AuthorizationEndpoint
	_ = provider.TokenEndpoint
	_ = provider.JWKSURI
	return nil
}
```

### Client Credentials Grant

```go
import (
	"context"
	"fmt"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

func main() {
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
		panic(err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Printf("token issued, type %s, expires in %ds\n", token.TokenType, token.ExpiresIn)
	// Never log token values.

	adminCtx := rp.WithTokenScopes(ctx, "admin:all")
	adminToken, err := client.Token(adminCtx)
	if err != nil {
		panic(err)
	}

	_ = adminToken
}
```

### Resource Indicators

Use [WithResources] to request audience-restricted access tokens with OAuth 2.0
Resource Indicators (RFC 8707). Resources are sent as repeated `resource`
parameters in authorization requests and token requests.

```go
client, err := rp.NewClientCredentials(
	ctx,
	provider.Issuer,
	rp.WithClientID("client-id"),
	rp.WithClientSecret("client-secret"),
	rp.WithProviderMetadata(provider),
	rp.WithResources("https://api.example.com/"),
)

// Override resources per-request via context.
paymentsCtx := rp.WithTokenResources(ctx, "https://payments.example.com/")
paymentsToken, err := client.Token(paymentsCtx)
```

## Project Structure

*   `cmd/example-rp/` - Example Relying Party implementation.
*   `conformance/` - Conformance test harness and setup.
*   `metadata/` - OIDC and OAuth AS discovery, metadata, and validation logic.
*   `rp/` - Relying Party implementation (Authorization Code flow, tokens, user info).
*   `rp/store/memory/` - In-memory RP state store.
*   `rp/store/cookie/` - Cookie-backed RP state store using `gorilla/sessions`.
*   `jwks/` - Remote JSON Web Key Set (JWKS) handling.
*   `cache/` - Caching utilities.

## Development

See `AGENTS.md` for development guidelines, build commands, and code style.

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./metadata
```

### Code Style

The project uses `gofumpt` for formatting and `go vet` for static analysis.
