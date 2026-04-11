# Lanyard

Lanyard is a Go OpenID Connect (OIDC) and OAuth 2.0 relying party library.

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

*   **Client Credentials Grant** (RFC 6749 §4.4):
    *   OAuth 2.0 Client Credentials flow for service-to-service authentication.
    *   Per-request scope customization via context.
    *   TokenSource interface for caching and reuse.

*   **Token & User Info**:
    *   ID Token validation (signature, claims, audience, expiration).
    *   User Info endpoint retrieval.
    *   Token exchange support (RFC 8693).
    *   DPoP (Demonstrating Proof-of-Possession) support.
    *   mTLS sender-constrained access token support.

*   **Security & Validation**:
    *   HTTPS enforcement for issuer and redirect URIs.
    *   Clock skew tolerance configuration.
    *   Request/response validation helpers.

### Conformance Status

Lanyard is verified against the OpenID Foundation conformance suite with the included local harness.

*   **Full suite preset**: `all-rp-full`
*   **Latest verified result**: `104/104` plans passed, `1180/1180` tests passed
*   **Included coverage**:
    *   OpenID Connect Core Basic Certification
    *   OpenID Connect Config Certification (`42/42` plans)
    *   OpenID Connect Form Post Basic Certification
    *   FAPI 1.0 Advanced Final (`12/12` plans)
    *   FAPI 2.0 Security Profile Final (`16/16` plans)
    *   FAPI 2.0 Message Signing Final (`32/32` plans)
*   **Setup**: See `conformance/README.md` for local suite setup and harness usage.

Useful commands:

```bash
# Full verified RP suite
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full

# OIDC config matrix only
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=oidcc-config-full

# FAPI 1.0 Advanced Final
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi1-adv-full

# FAPI 2.0 Security Profile Final
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -test.timeout=45m \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -matrix=fapi2-sp-final-plain-fapi-all16 \
  -parallel \
  -max-parallel-runs=8

# FAPI 2.0 Message Signing Final
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -test.timeout=60m \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-all32 \
  -parallel \
  -max-parallel-runs=8
```

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
	stateStore, err := cookie.New(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("abcdef0123456789abcdef0123456789"),
		cookie.WithTTL(10*time.Minute),
	)
	if err != nil {
		return nil, err
	}

	return rp.New(
		ctx,
		"https://issuer.example.com",
		"client-id",
		"client-secret",
		"https://rp.example.com/callback",
		rp.WithStateStore(stateStore),
		rp.WithScopes("openid", "profile", "email"),
	)
	// If you already have provider info, add rp.WithProviderMetadata(provider)
	// and the constructor will skip discovery.
}

func handleLogin(rpClient *rp.RP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := rpClient.AuthorizationURL(r.Context(), w, r)
		if err != nil {
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func handleCallback(rpClient *rp.RP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := rpClient.HandleCallback(r.Context(), w, r)
		if err != nil {
			http.Error(w, "callback failed", http.StatusBadRequest)
			return
		}

		_, _ = result.Subject, result.UserInfo
	}
}
```

### Browser RP with Preloaded Provider

```go
import (
	"context"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

func newRP(ctx context.Context) (*rp.RP, error) {
	provider := metadata.Provider{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		TokenEndpoint:         "https://issuer.example.com/token",
		UserinfoEndpoint:      "https://issuer.example.com/userinfo",
		JWKSURI:               "https://issuer.example.com/jwks.json",
	}

	return rp.New(
		ctx,
		provider.Issuer,
		"client-id",
		"client-secret",
		"https://rp.example.com/callback",
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
		Issuer:        "https://auth.example.com",
		TokenEndpoint: "https://auth.example.com/token",
	}

	client, err := rp.NewClientCredentials(
		ctx,
		provider.Issuer,
		"client-id",
		"client-secret",
		rp.WithClientCredentialsProviderMetadata(provider),
		rp.WithClientCredentialsScopes("api:read", "api:write"),
	)
	if err != nil {
		panic(err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Printf("access token: %s\n", token.AccessToken)
	fmt.Printf("token type: %s\n", token.TokenType)
	fmt.Printf("expires in: %d\n", token.ExpiresIn)

	adminCtx := rp.WithTokenScopes(ctx, "admin:all")
	adminToken, err := client.Token(adminCtx)
	if err != nil {
		panic(err)
	}

	_ = adminToken
}
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
