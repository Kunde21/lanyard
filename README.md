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
    *   State management (in-memory implementation provided).
    *   Dynamic client authentication methods:
        *   `client_secret_basic`
        *   `client_secret_post`
        *   `private_key_jwt` (asymmetric signatures)
    *   Pushed Authorization Requests (PAR) support.

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
    "github.com/Kunde21/lanyard/rp"
)

func main() {
    ctx := context.Background()
    issuer := "https://accounts.google.com"
    clientID := "your-client-id"
    clientSecret := "your-client-secret"
    redirectURI := "https://your-app.com/callback"

    rpClient, err := rp.New(ctx, issuer, clientID, clientSecret, redirectURI)
    if err != nil {
        panic(err)
    }

    // Use rpClient to generate authorization URLs and handle callbacks
    authURL, err := rpClient.AuthorizationURL(ctx, "openid profile email", "state-value")
    if err != nil {
        panic(err)
    }
    // Redirect user to authURL
}
```

### Handling Callbacks

```go
func handleCallback(ctx context.Context, code, state string) (*rp.CallbackResult, error) {
    result, err := rpClient.HandleCallback(ctx, code, state)
    if err != nil {
        return nil, err
    }

    // result.Subject contains the user's ID (sub claim)
    // result.UserInfo contains claims from the UserInfo endpoint
    return result, nil
}
```

## Project Structure

*   `cmd/example-rp/` - Example Relying Party implementation.
*   `conformance/` - Conformance test harness and setup.
*   `oidc/` - Core OIDC discovery, metadata, and validation logic.
*   `rp/` - Relying Party implementation (Authorization Code flow, tokens, user info).
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
