# Client Credentials Grant Implementation Plan

## Overview

Add OAuth 2.0 Client Credentials grant (RFC 6749 §4.4) support with a `TokenSource` interface and `Token` type.

## Goals

- Provide a clean API for obtaining tokens via client credentials flow
- Support all existing token endpoint authentication methods
- Enable per-request scope customization via context values
- Maintain consistency with existing library patterns

## Files to Create/Modify

### 1. Create `rp/token_source.go`

Define the public interface and token type:

```go
package rp

type Token struct {
    AccessToken string
    TokenType   string
    ExpiresIn   int64
}

type TokenSource interface {
    Token(ctx context.Context) (*Token, error)
}

type ctxKey struct{}

func WithScopes(ctx context.Context, scopes ...string) context.Context
func scopesFromContext(ctx context.Context) []string
```

**Design notes:**
- `Token` is a concrete type (not pointer in struct definition)
- `TokenSource.Token` returns `*Token` for nil-check convenience
- Context helpers are lowercase `scopesFromContext` (unexported) since only client_credentials uses them internally

### 2. Create `rp/client_credentials.go`

Core implementation:

```go
package rp

type ClientCredentials struct {
    issuer       string
    clientID     string
    clientSecret string
    scopes       []string

    httpClient *http.Client
    logger     *slog.Logger
    oidcClient *oidc.Client

    provider    oidc.ProviderMetadata
    providerSet bool

    clientKeyProvider ClientKeyProvider

    resolvedAuthMethod  AuthMethod
    allowMethodFallback bool
    methodMu            sync.RWMutex

    now        func() time.Time
    randReader io.Reader
}

func NewClientCredentials(ctx context.Context, issuer, clientID, clientSecret string, opts ...ClientCredentialsOption) (*ClientCredentials, error)

func (c *ClientCredentials) Token(ctx context.Context) (*Token, error)
```

**Implementation details:**
- Constructor validates issuer URL and clientID (clientSecret required for Basic/Post auth methods)
- Discovery performed if provider not pre-configured
- Auth method resolution reuses patterns from `auth_method.go`
- `Token()` method:
  1. Check context for scope override via `scopesFromContext`
  2. Fall back to default scopes if not set
  3. Build form request with `grant_type=client_credentials`
  4. Apply client authentication per resolved method
  5. POST to token endpoint
  6. Parse response into `Token`

**Token request format:**
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=space-separated-scopes (optional, only if scopes provided)
```

### 3. Create `rp/client_credentials_options.go`

Configuration options:

```go
package rp

type ClientCredentialsOption func(*ClientCredentials)

func WithClientCredentialsHTTPClient(client *http.Client) ClientCredentialsOption
func WithClientCredentialsLogger(logger *slog.Logger) ClientCredentialsOption
func WithClientCredentialsOIDCClient(client *oidc.Client) ClientCredentialsOption
func WithClientCredentialsScopes(scopes ...string) ClientCredentialsOption
func WithClientCredentialsAuthMethod(method AuthMethod) ClientCredentialsOption
func WithClientCredentialsProviderDiscovery(provider oidc.ProviderMetadata) ClientCredentialsOption
func WithClientCredentialsKeyProvider(provider ClientKeyProvider) ClientCredentialsOption
```

**Internal options (for testing):**
```go
func withClientCredentialsNow(now func() time.Time) ClientCredentialsOption
func withClientCredentialsRandReader(reader io.Reader) ClientCredentialsOption
```

### 4. Modify `rp/errors.go`

Add new sentinel error:

```go
var (
    // ... existing errors ...
    
    // ErrClientCredentialsFailed indicates client credentials token request failed.
    ErrClientCredentialsFailed = errors.New("client credentials token request failed")
)
```

### 5. Keep `rp/token.go` unchanged

`TokenResponse` remains for internal authorization code flow use. The new `Token` type serves the public API for client credentials.

**Rationale:** 
- Avoids breaking changes to internal code
- `TokenResponse` includes `IDToken` which is relevant for auth code flow but not client credentials
- Can unify types in future refactor if desired

### 6. Create `rp/client_credentials_test.go`

Test coverage:

1. **Request shape validation**
   - `grant_type=client_credentials` present
   - Scope format (space-separated, URL-encoded)
   - Content-Type header

2. **Authentication methods**
   - `client_secret_basic` - Authorization header
   - `client_secret_post` - Form body credentials
   - `private_key_jwt` - Client assertion
   - `tls_client_auth` - mTLS (cert via ClientKeyProvider)

3. **Error handling**
   - Non-200 responses with bounded error preview
   - Malformed JSON response
   - Missing access_token in response

4. **Fallback behavior**
   - Post → Basic fallback when provider omits supported methods
   - Fallback caching (subsequent requests use resolved method)

5. **Scope handling**
   - Default scopes from constructor
   - Per-request override via `WithScopes(ctx, ...)`
   - No scope parameter when none configured

6. **TokenSource interface**
   - Verify `*ClientCredentials` implements `TokenSource`

7. **Discovery integration**
   - Constructor performs discovery when provider not pre-configured
   - Auth method resolution from provider metadata

### 7. Update `README.md`

Add usage example:

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
    
    // Exceptional: override scopes per-request via context
    ctx = rp.WithScopes(ctx, "admin:all")
    adminToken, err := client.Token(ctx)
}
```

## Implementation Order

1. Add `ErrClientCredentialsFailed` to `rp/errors.go`
2. Create `rp/token_source.go` with `Token`, `TokenSource`, and context helpers
3. Create `rp/client_credentials_options.go` with options
4. Create `rp/client_credentials.go` with core implementation
5. Create `rp/client_credentials_test.go` with tests
6. Update `README.md` with usage documentation

## Estimated Scope

- `token_source.go`: ~25 lines
- `client_credentials_options.go`: ~60 lines
- `client_credentials.go`: ~180 lines
- `client_credentials_test.go`: ~250 lines
- Total: ~515 lines

## Dependencies

- Reuses existing types: `AuthMethod`, `ClientKeyProvider`, `oidc.ProviderMetadata`, `oidc.Client`
- Reuses existing patterns: option pattern, `doJSON` helper, auth method resolution
- No new external dependencies
