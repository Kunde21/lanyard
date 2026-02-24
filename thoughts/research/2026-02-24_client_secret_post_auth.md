---
date: 2026-02-24T05:44:04+07:00
git_commit: 898c01d024651d751084179a41ae11613cca3c82
branch: master
repository: lanyard
topic: "Add client_secret_post OAuth2 Client Authentication"
tags: [research, oauth2, authentication, token-endpoint, client-auth, rp]
last_updated: 2026-02-24T05:44:04+07:00
---

## Ticket Synopsis

Research the codebase to understand how to implement `client_secret_post` OAuth2 client authentication method alongside the existing `client_secret_basic` method. The feature requires:

1. Typed AuthMethod constants (Basic and Post)
2. Configuration option `WithAuthMethod(AuthMethod)`
3. Auto-negotiation from provider metadata (`token_endpoint_auth_methods_supported`)
4. Fallback behavior when metadata unavailable
5. Validation at construction time
6. Backward compatibility with existing code

## Summary

The codebase is well-structured to support this feature. The RP struct uses the functional options pattern, validation is centralized in the `validate()` method, and OIDC discovery infrastructure is already in place. The token exchange currently hardcodes `client_secret_basic` at `rp/token_exchange.go:26` via `req.SetBasicAuth()`.

Key implementation points:
- **AuthMethod type**: Follow the `cacheEntryKind` pattern in `oidc/cache.go:13-18`
- **WithAuthMethod option**: Follow existing option pattern in `rp/options.go`
- **AuthMethodError**: Follow `ValidationError` pattern in `oidc/errors.go:16-56`
- **Auto-negotiation**: Access metadata via `r.oidcClient.DiscoverProvider()` in `New()`
- **Conditional auth**: Switch on `r.resolvedAuthMethod` in `exchangeToken()`
- **Tests**: Extend `rp/token_exchange_test.go` patterns

## Detailed Findings

### Component Analysis

#### 1. RP Struct (`rp/rp.go:20-36`)

Current fields:
```go
type RP struct {
    issuer       string
    clientID     string
    clientSecret string
    redirectURI  string
    scopes       []string

    httpClient *http.Client
    logger     *slog.Logger
    oidcClient *oidc.Client

    stateStore StateStore

    now        func() time.Time
    randReader io.Reader
    clockSkew  time.Duration
}
```

**Required additions**:
- `authMethod AuthMethod` - User-specified auth method
- `resolvedAuthMethod AuthMethod` - Final method after negotiation

**Location**: Add after `scopes` field (around line 25) to group configuration fields.

#### 2. New() Constructor (`rp/rp.go:39-73`)

Current flow:
1. Create struct with defaults (lines 40-51)
2. Apply options (lines 53-55)
3. Validate (lines 57-58)
4. Initialize dependencies (lines 61-72)

**Integration point**: Add auth method resolution after validation, before dependency initialization (around line 59):
```go
if err := r.resolveAuthMethod(); err != nil {
    return nil, err
}
```

#### 3. exchangeToken Function (`rp/token_exchange.go:14-45`)

Current hardcoded Basic auth at line 26:
```go
req.SetBasicAuth(r.clientID, r.clientSecret)
```

**Required changes**:
- Lines 15-19: Add `client_id` and `client_secret` to form for POST auth
- Lines 25-26: Make auth conditional based on `r.resolvedAuthMethod`

Modified structure:
```go
// Add credentials to form for POST auth
if r.resolvedAuthMethod == AuthMethodPost {
    form.Set("client_id", r.clientID)
    form.Set("client_secret", r.clientSecret)
}

// ... create request ...

// Conditional auth header
if r.resolvedAuthMethod == AuthMethodBasic {
    req.SetBasicAuth(r.clientID, r.clientSecret)
}
```

#### 4. Option Pattern (`rp/options.go`)

Current option type (line 13):
```go
type Option func(*RP)
```

**New option implementation** (add after line 59):
```go
// WithAuthMethod sets the token endpoint authentication method.
// Supported methods: AuthMethodBasic (default), AuthMethodPost.
func WithAuthMethod(method AuthMethod) Option {
    return func(r *RP) {
        if method == AuthMethodBasic || method == AuthMethodPost {
            r.authMethod = method
        }
    }
}
```

#### 5. OIDC Discovery and Metadata (`oidc/`)

Key discovery functions:
- `oidc/discovery.go:15` - `DiscoverProvider(ctx, issuer)`
- `oidc/discovery.go:40` - `DiscoverAuthorizationServer(ctx, issuer)`

Metadata field already available:
- `oidc/metadata_oauth_as.go:17` - `TokenEndpointAuthMethodsSupported []string`

**Auto-negotiation logic** in `resolveAuthMethod()`:
1. If user specified method: validate against `TokenEndpointAuthMethodsSupported`
2. If auto-detect: discover metadata, prefer POST over Basic
3. If metadata unavailable: default to Basic

#### 6. Error Types

Existing patterns:
- `rp/errors.go:5-18` - Sentinel errors
- `oidc/errors.go:16-56` - `ValidationError` with fields

**New AuthMethodError** (add to `rp/errors.go`):
```go
// ErrAuthMethodNotSupported indicates the requested auth method is not supported.
ErrAuthMethodNotSupported = errors.New("auth method not supported")

// AuthMethodError indicates an authentication method is not supported.
type AuthMethodError struct {
    Method    AuthMethod
    Supported []string
    Err       error
}

func (e *AuthMethodError) Error() string { /* ... */ }
func (e *AuthMethodError) Unwrap() error { return e.Err }
func (e *AuthMethodError) Is(target error) bool { /* ... */ }
```

### Pattern Analysis

#### Typed Constants Pattern

From `oidc/cache.go:13-18`:
```go
type cacheEntryKind string

const (
    cacheEntryKindProvider cacheEntryKind = "provider"
    cacheEntryKindAS       cacheEntryKind = "authorization_server"
)
```

**Applied to AuthMethod**:
```go
type AuthMethod string

const (
    AuthMethodBasic AuthMethod = "client_secret_basic"
    AuthMethodPost  AuthMethod = "client_secret_post"
)
```

#### Option Validation Pattern

From `rp/options.go:53-59`:
```go
func WithClockSkew(skew time.Duration) Option {
    return func(r *RP) {
        if skew >= 0 {
            r.clockSkew = skew
        }
    }
}
```

Pattern: Validate within option, silently ignore invalid values.

#### Custom Error Pattern

From `oidc/errors.go:16-56`:
- Struct with context fields
- `Error()` with conditional formatting
- `Unwrap()` for error chaining
- `Is()` for sentinel error matching

### Test Patterns

Current test structure in `rp/token_exchange_test.go:18-71`:

1. **Closure capture** for request inspection:
```go
var gotAuthorization string
ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    gotAuthorization = r.Header.Get("Authorization")
    // ...
}))
```

2. **Form data verification**:
```go
body, _ := io.ReadAll(r.Body)
gotForm, _ := url.ParseQuery(string(body))
```

3. **go-cmp assertions**:
```go
if diff := cmp.Diff(want, got); diff != "" {
    t.Fatalf("mismatch (-want +got):\n%s", diff)
}
```

**New test requirements**:
- Verify POST auth adds credentials to form body
- Verify POST auth has no Authorization header
- Verify auto-negotiation from metadata
- Verify error on unsupported method
- Verify error on missing secret for POST

## Code References

- `rp/rp.go:20-36` - RP struct definition
- `rp/rp.go:39-73` - New() constructor
- `rp/rp.go:75-93` - validate() method
- `rp/token_exchange.go:14-45` - exchangeToken() function
- `rp/token_exchange.go:26` - Hardcoded SetBasicAuth
- `rp/options.go:13` - Option type
- `rp/options.go:16-67` - Existing option implementations
- `rp/errors.go:5-18` - Error definitions
- `oidc/errors.go:16-56` - ValidationError pattern
- `oidc/cache.go:13-18` - Typed constant pattern
- `oidc/metadata_oauth_as.go:17` - TokenEndpointAuthMethodsSupported field
- `oidc/discovery.go:15` - DiscoverProvider function
- `oidc/discovery.go:40` - DiscoverAuthorizationServer function
- `rp/token_exchange_test.go:18-71` - Test patterns

## Architecture Insights

### Design Decisions

1. **Fail-fast at construction**: Auth method validation happens in `New()`, not at token exchange time. This provides immediate feedback to developers.

2. **Two-phase auth method storage**: 
   - `authMethod` - user-specified (may be empty for auto-detect)
   - `resolvedAuthMethod` - final method after negotiation/caching

3. **Option pattern with silent validation**: Invalid option values are silently ignored, following existing patterns in `WithClockSkew`, etc.

4. **Priority order for auto-negotiation**: POST preferred over Basic per requirements.

5. **No persistent caching**: In-memory only, per RP instance lifetime.

### Cross-Component Connections

- **RP ↔ OIDC Client**: RP initializes OIDC client with shared HTTP client and logger
- **RP ↔ Metadata**: Auth method negotiation depends on `oidc.Client.DiscoverProvider()`
- **Token Exchange ↔ RP**: Uses `r.resolvedAuthMethod` to determine auth strategy
- **Options ↔ RP**: Functional options modify RP struct before validation

### Testing Architecture

- Uses `httptest.NewTLSServer` for HTTPS validation
- Closure variables capture request state
- `github.com/google/go-cmp/cmp` for assertions (NOT testify)
- Table-driven tests for multiple scenarios

## Historical Context

### From thoughts/tickets/feature_client_secret_post_auth.md

The ticket specifies:
- Design should be extensible for future methods (client_secret_jwt, private_key_jwt)
- Auto-negotiation from provider metadata with priority: POST over Basic
- Fallback behavior: Try POST first, then Basic, cache successful method
- Validation: Return error if client_secret_post selected but no secret provided
- Full backward compatibility required

### From thoughts/research/2026-02-22_oidc_discovery_implementation.md

Discovery infrastructure already supports:
- OAuth AS metadata parsing
- `TokenEndpointAuthMethodsSupported` field available
- Caching with TTL/ETag
- Stale-while-revalidate patterns

## Related Research

- `thoughts/tickets/feature_client_secret_post_auth.md` - Feature ticket (source of truth)
- `thoughts/research/2026-02-22_oidc_discovery_implementation.md` - OIDC discovery patterns
- `thoughts/research/2026-02-22_basic_rp_conformance_profile.md` - Token endpoint auth context

## Open Questions

1. **Fallback timing**: Should fallback logic trigger at first exchange or be built into construction-time resolution?

2. **Extensibility**: Should the initial implementation include placeholder constants for JWT methods (client_secret_jwt, private_key_jwt) or add them later?

3. **Public clients**: The ticket excludes `none` auth method (public clients), but should the design accommodate it for future expansion?

4. **Discovery error handling**: If discovery fails during auto-negotiation, should it fail fast or silently fall back to Basic?

## Implementation Checklist

Based on this research, the implementation should:

- [ ] Add `AuthMethod` type and constants to `rp/rp.go`
- [ ] Add `authMethod` and `resolvedAuthMethod` fields to RP struct
- [ ] Add `WithAuthMethod()` option to `rp/options.go`
- [ ] Add `AuthMethodError` type to `rp/errors.go`
- [ ] Add `resolveAuthMethod()` method to RP
- [ ] Modify `exchangeToken()` for conditional auth
- [ ] Update `New()` to call `resolveAuthMethod()`
- [ ] Add tests for POST auth request shape
- [ ] Add tests for auto-negotiation from metadata
- [ ] Add tests for error cases (unsupported method, missing secret)
- [ ] Verify backward compatibility (existing tests pass)
