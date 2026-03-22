# Lanyard

Lanyard is a Go OpenID Connect (OIDC) relying party library.

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
        *   `private_key_jwt` (asymmetric signatures)
    *   Pushed Authorization Requests (PAR) support.

*   **Client Credentials Grant** (RFC 6749 §4.4):
    *   OAuth 2.0 Client Credentials flow for service-to-service authentication.
    *   Per-request scope customization via context.
    *   TokenSource interface for caching and reuse.

*   **Token & User Info**:
    *   ID Token validation (signature, claims, audience, expiration).
    *   User Info endpoint retrieval.
    *   Token exchange support (RFC 8693).
    *   DPoP (Demonstrating Proof-of-Possession) support.

*   **Security & Validation**:
    *   HTTPS enforcement for issuer and redirect URIs.
    *   Clock skew tolerance configuration.
    *   Request/response validation helpers.

### OpenID Conformance Status

Lanyard is designed to pass OpenID Connect conformance tests.

*   **Profile**: OpenID Connect Core: Basic Certification Profile Relying Party Tests
*   **Status**: The library includes a conformance harness to automate testing against the official OpenID Foundation conformance suite.
*   **Setup**: See `conformance/README.md` for instructions on running the conformance tests locally using Docker.

To run the conformance tests (Linux required):

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp
```

## Installation

```bash
go get github.com/Kunde21/lanyard
```

## Usage

### Basic Discovery

```go
import (
    "context"
    "fmt"
    "github.com/Kunde21/lanyard/oidc"
)

func main() {
    ctx := context.Background()
    client := oidc.NewClient()

    // Discover provider metadata
    provider, err := client.DiscoverProvider(ctx, "https://accounts.google.com")
    if err != nil {
        panic(err)
    }

    fmt.Printf("Issuer: %s\n", provider.Issuer)
    fmt.Printf("Authorization Endpoint: %s\n", provider.AuthEndpoint)
    fmt.Printf("Token Endpoint: %s\n", provider.TokenEndpoint)
}
```

### Creating an RP Client

```go
import (
    "context"
    "time"

    "github.com/Kunde21/lanyard/rp"
    "github.com/Kunde21/lanyard/rp/store/memory"
)

func main() {
    ctx := context.Background()
    issuer := "https://accounts.google.com"
    clientID := "your-client-id"
    clientSecret := "your-client-secret"
    redirectURI := "https://your-app.com/callback"

    rpClient, err := rp.New(
        ctx,
        issuer,
        clientID,
        clientSecret,
        redirectURI,
        rp.WithStateStore(memory.New(10*time.Minute)),
    )
    if err != nil {
        panic(err)
    }

    _ = rpClient
}
```

### Browser Flow with Cookie Store

```go
import (
    "context"
    "net/http"

    "github.com/Kunde21/lanyard/rp"
    "github.com/Kunde21/lanyard/rp/store/cookie"
)

func setupRP(ctx context.Context) (*rp.RP, error) {
    stateStore, err := cookie.New(
        []byte("0123456789abcdef0123456789abcdef"),
        []byte("abcdef0123456789abcdef0123456789"),
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
    )
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

        _ = result.Subject
        _ = result.UserInfo
    }
}
```

### Client Credentials Grant

For service-to-service authentication using the OAuth 2.0 Client Credentials flow:

```go
import (
    "context"
    "github.com/Kunde21/lanyard/rp"
)

func main() {
    ctx := context.Background()

    // Create client with default scopes
    client, err := rp.NewClientCredentials(ctx,
        "https://auth.example.com",
        "client-id",
        "client-secret",
        rp.WithClientCredentialsScopes("api:read", "api:write"),
    )
    if err != nil {
        panic(err)
    }

    // Get token
    token, err := client.Token(ctx)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Access Token: %s\n", token.AccessToken)
    fmt.Printf("Expires In: %d\n", token.ExpiresIn)

    // Per-request scope override via context
    ctx = rp.WithTokenScopes(ctx, "admin:all")
    adminToken, err := client.Token(ctx)
}
```

## Project Structure

*   `cmd/example-rp/` - Example Relying Party implementation.
*   `conformance/` - Conformance test harness and setup.
*   `oidc/` - Core OIDC discovery, metadata, and validation logic.
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
go test ./pkg/oidc
```

### Code Style

The project uses `gofumpt` for formatting and `go vet` for static analysis.
