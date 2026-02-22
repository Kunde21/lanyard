---
date: 2026-02-22T06:07:34+07:00
git_commit: N/A (new repository)
branch: master
repository: lanyard
topic: "Implement OpenID Connect Discovery with FAPI Extensions"
tags: [research, oidc, discovery, fapi, jwks, metadata, go]
last_updated: 2026-02-22
---

# Research: OpenID Connect Discovery Implementation

## Ticket Synopsis

**Feature**: Implement a Go client library for OpenID Connect Discovery that fetches and validates provider metadata from the `.well-known/openid-configuration` endpoint. The implementation must support FAPI extensions (PAR, JARM, Grant Management, OIDC for Identity Assurance).

**Key Requirements**:
- Separate types for OAuth AS (RFC 8414) and OIDC Provider metadata
- JWKS fetching with key rotation and thread-safe caching
- Pluggable cache interface (Get/Set/Delete only)
- Rich error types with structured fields
- slog.Logger integration
- Thread-safe concurrent access

**Current State**: New project with empty go.mod

## Summary

This research synthesizes patterns from industry-standard Go OIDC libraries (coreos/go-oidc, zitadel/oidc) and best practices for implementing a production-ready OIDC Discovery client. Key findings:

1. **API Design**: Use functional options pattern for configuration, unexported Provider fields with accessor methods
2. **Metadata Types**: Define comprehensive structs with JSON tags, support lenient parsing by ignoring unknown fields
3. **JWKS Handling**: Implement RemoteKeySet with cache expiry, singleflight for thundering herd prevention
4. **Caching**: Minimal Get/Set/Delete interface with sync.RWMutex-backed implementation
5. **Error Handling**: Structured error types with fmt.Formatter support, sentinel errors for API boundaries
6. **Thread Safety**: Use sync.RWMutex for cache, singleflight for request deduplication

## Detailed Findings

### 1. Discovery Client Structure and API Design

#### 1.1 Provider Type Design (coreos/go-oidc Pattern)

The canonical approach uses a `Provider` struct with unexported fields and controlled accessor methods:

```go
type Provider struct {
    issuer string
    authURL string
    tokenURL string
    deviceAuthURL string
    userInfoURL string
    jwksURL string
    algorithms []string
    rawClaims []byte
    
    mu sync.Mutex
    client *http.Client
    remoteKeySet *RemoteKeySet
}
```

**Benefits**:
- Forces controlled access through methods
- Prevents invalid state modification
- Allows lazy initialization

#### 1.2 Functional Options Pattern

For flexible configuration without breaking API changes:

```go
type Client struct {
    httpClient *http.Client
    logger *slog.Logger
    cache Cache
    // ... other fields
}

type Option func(*Client)

func WithHTTPClient(client *http.Client) Option {
    return func(c *Client) { c.httpClient = client }
}

func WithLogger(logger *slog.Logger) Option {
    return func(c *Client) { c.logger = logger }
}

func WithCache(cache Cache) Option {
    return func(c *Client) { c.cache = cache }
}

func New(opts ...Option) *Client {
    c := &Client{
        httpClient: http.DefaultClient,
        logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
    }
    for _, opt := range opts {
        opt(c)
    }
    return c
}
```

### 2. Metadata Types and Parsing

#### 2.1 Separate Types for OAuth AS and OIDC Provider

**OAuth Authorization Server Metadata (RFC 8414)**:

```go
type AuthorizationServerMetadata struct {
    Issuer                            string   `json:"issuer"`
    AuthorizationEndpoint             string   `json:"authorization_endpoint"`
    TokenEndpoint                     string   `json:"token_endpoint"`
    JWKSURI                           string   `json:"jwks_uri"`
    RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
    ScopesSupported                   []string `json:"scopes_supported,omitempty"`
    ResponseTypesSupported            []string `json:"response_types_supported"`
    ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
    GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
    TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
    // ... other fields
}
```

**OpenID Provider Metadata (OIDC Discovery)**:

```go
type ProviderMetadata struct {
    AuthorizationServerMetadata  // Embed common fields
    
    // OIDC-specific fields
    UserinfoEndpoint                    string   `json:"userinfo_endpoint,omitempty"`
    CheckSessionIframe                  string   `json:"check_session_iframe,omitempty"`
    EndSessionEndpoint                  string   `json:"end_session_endpoint,omitempty"`
    SubjectTypesSupported               []string `json:"subject_types_supported"`
    IDTokenSigningAlgValuesSupported    []string `json:"id_token_signing_alg_values_supported"`
    IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`
    // ... other OIDC fields
}
```

#### 2.2 Lenient Parsing with Raw Claims Access

Support for accessing fields not explicitly defined:

```go
type Provider struct {
    // ... other fields
    rawClaims []byte
}

func (p *Provider) Claims(v interface{}) error {
    if p.rawClaims == nil {
        return errors.New("claims not set")
    }
    return json.Unmarshal(p.rawClaims, v)
}

// Usage:
var claims struct {
    ScopesSupported []string `json:"scopes_supported"`
    CustomField     string   `json:"custom_field"`
}
if err := provider.Claims(&claims); err != nil {
    // handle error
}
```

### 3. JWKS Handling and Key Rotation

#### 3.1 RemoteKeySet Structure

```go
type RemoteKeySet struct {
    jwksURL string
    ctx     context.Context
    now     func() time.Time
    
    mu         sync.Mutex
    inflight   *inflight
    cachedKeys []jose.JSONWebKey
    expiry     time.Time
}

type inflight struct {
    doneCh chan struct{}
    keys   []jose.JSONWebKey
    err    error
}
```

#### 3.2 Key Rotation with Cache Expiry

```go
const keysExpiryDelta = 30 * time.Second

func (r *RemoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
    jws, err := jose.ParseSigned(jwt)
    if err != nil {
        return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
    }
    
    // Extract key ID from JWT header
    keyID := ""
    for _, sig := range jws.Signatures {
        keyID = sig.Header.KeyID
        break
    }
    
    // Try cached keys first
    keys, expiry := r.keysFromCache()
    for _, key := range keys {
        if keyID == "" || key.KeyID == keyID {
            if payload, err := jws.Verify(&key); err == nil {
                return payload, nil
            }
        }
    }
    
    // If keys haven't expired, don't refresh
    if !r.now().Add(keysExpiryDelta).After(expiry) {
        return nil, errors.New("failed to verify signature")
    }
    
    // Fetch fresh keys
    keys, err = r.keysFromRemote(ctx)
    if err != nil {
        return nil, fmt.Errorf("fetching keys: %w", err)
    }
    
    // Try verification with fresh keys
    for _, key := range keys {
        if keyID == "" || key.KeyID == keyID {
            if payload, err := jws.Verify(&key); err == nil {
                return payload, nil
            }
        }
    }
    
    return nil, errors.New("failed to verify signature")
}
```

#### 3.3 Thundering Herd Prevention with Inflight Pattern

```go
func (r *RemoteKeySet) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
    r.mu.Lock()
    
    // If there's already an in-flight request, wait for it
    if r.inflight != nil {
        inflight := r.inflight
        r.mu.Unlock()
        <-inflight.doneCh
        return inflight.keys, inflight.err
    }
    
    // Create new in-flight request marker
    inflight := &inflight{doneCh: make(chan struct{})}
    r.inflight = inflight
    r.mu.Unlock()
    
    // Perform the actual key fetch
    keys, expiry, err := r.updateKeys(ctx)
    
    // Update cache
    r.mu.Lock()
    r.cachedKeys = keys
    r.expiry = expiry
    r.inflight = nil
    r.mu.Unlock()
    
    // Signal waiting goroutines
    close(inflight.doneCh)
    inflight.keys = keys
    inflight.err = err
    
    return keys, err
}
```

### 4. Cache Interface Design

#### 4.1 Minimal Pluggable Interface

```go
// Cache defines a minimal interface for caching discovery documents.
// Implementations must be thread-safe.
type Cache interface {
    // Get retrieves a value by key.
    // Returns (value, true) if found, (nil, false) otherwise.
    Get(key string) (interface{}, bool)
    
    // Set stores a value with the given key.
    Set(key string, value interface{})
    
    // Delete removes a value by key.
    Delete(key string)
}
```

#### 4.2 Default Implementation with sync.RWMutex

```go
type MemoryCache struct {
    mu   sync.RWMutex
    data map[string]cacheEntry
}

type cacheEntry struct {
    value  interface{}
    expiry time.Time
}

func NewMemoryCache() *MemoryCache {
    return &MemoryCache{
        data: make(map[string]cacheEntry),
    }
}

func (c *MemoryCache) Get(key string) (interface{}, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    entry, ok := c.data[key]
    if !ok {
        return nil, false
    }
    
    // Check expiry
    if !entry.expiry.IsZero() && time.Now().After(entry.expiry) {
        return nil, false
    }
    
    return entry.value, true
}

func (c *MemoryCache) Set(key string, value interface{}) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    // Default TTL: 24 hours
    c.data[key] = cacheEntry{
        value:  value,
        expiry: time.Now().Add(24 * time.Hour),
    }
}

func (c *MemoryCache) Delete(key string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.data, key)
}
```

### 5. Error Type Design

#### 5.1 Structured Validation Errors

```go
type ValidationError struct {
    Field    string // Field name that failed validation
    Expected string // Expected value/format
    Actual   string // Actual value found
    Err      error  // Wrapped error
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed for field %q: expected %q, got %q", 
        e.Field, e.Expected, e.Actual)
}

func (e *ValidationError) Unwrap() error {
    return e.Err
}

// Support errors.Is
func (e *ValidationError) Is(target error) bool {
    if _, ok := target.(*ValidationError); ok {
        return true
    }
    return errors.Is(e.Err, target)
}

// Implement fmt.Formatter for detailed output
func (e *ValidationError) Format(s fmt.State, verb rune) {
    switch verb {
    case 'v':
        if s.Flag('+') {
            fmt.Fprintf(s, "ValidationError{field=%q, expected=%q, actual=%q, err=%+v}",
                e.Field, e.Expected, e.Actual, e.Err)
        } else {
            fmt.Fprint(s, e.Error())
        }
    default:
        fmt.Fprint(s, e.Error())
    }
}
```

#### 5.2 Discovery-Specific Errors

```go
// Sentinel errors for common conditions
var (
    ErrInvalidIssuer   = errors.New("invalid issuer")
    ErrDiscoveryFailed = errors.New("discovery failed")
    ErrJWKSFetchFailed = errors.New("jwks fetch failed")
)

type DiscoveryError struct {
    IssuerURL string
    Err       error
}

func (e *DiscoveryError) Error() string {
    return fmt.Sprintf("OIDC discovery failed for issuer %q: %v", e.IssuerURL, e.Err)
}

func (e *DiscoveryError) Unwrap() error {
    return e.Err
}
```

### 6. slog.Logger Integration

#### 6.1 Constructor Integration

```go
type Client struct {
    logger *slog.Logger
    // ... other fields
}

func New(opts ...Option) *Client {
    c := &Client{
        logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), // Default: no-op
    }
    for _, opt := range opts {
        opt(c)
    }
    return c}

func WithLogger(logger *slog.Logger) Option {
    return func(c *Client) {
        c.logger = logger
    }
}
```

#### 6.2 Context-Aware Logging

```go
func (c *Client) fetchDiscovery(ctx context.Context, issuer string) (*ProviderMetadata, error) {
    c.logger.DebugContext(ctx, "fetching discovery document",
        slog.String("issuer", issuer),
    )
    
    // ... fetch logic
    
    c.logger.InfoContext(ctx, "discovery document fetched",
        slog.String("issuer", issuer),
        slog.String("authorization_endpoint", meta.AuthorizationEndpoint),
    )
    
    return meta, nil
}
```

### 7. Well-Known URL Construction

```go
func wellKnownURL(issuer, suffix string) (string, error) {
    // Remove trailing slash from issuer
    issuer = strings.TrimSuffix(issuer, "/")
    
    // Parse issuer URL
    u, err := url.Parse(issuer)
    if err != nil {
        return "", fmt.Errorf("invalid issuer URL: %w", err)
    }
    
    // Construct well-known path
    u.Path = path.Join("/.well-known", suffix, u.Path)
    
    return u.String(), nil
}

// Usage:
oidcURL, _ := wellKnownURL("https://accounts.google.com", "openid-configuration")
// Result: https://accounts.google.com/.well-known/openid-configuration

oauthURL, _ := wellKnownURL("https://example.com/tenant1", "oauth-authorization-server")
// Result: https://example.com/.well-known/oauth-authorization-server/tenant1
```

### 8. Issuer Validation

```go
func validateIssuer(discoveredIssuer, expectedIssuer string) error {
    if discoveredIssuer != expectedIssuer {
        return &ValidationError{
            Field:    "issuer",
            Expected: expectedIssuer,
            Actual:   discoveredIssuer,
            Err:      ErrInvalidIssuer,
        }
    }
    return nil
}
```

## Code References

### From coreos/go-oidc (https://github.com/coreos/go-oidc)

- `oidc/oidc.go:45-85` - Provider struct with unexported fields
- `oidc/oidc.go:150-200` - NewProvider with discovery URL construction
- `oidc/jwks.go:20-60` - RemoteKeySet struct definition
- `oidc/jwks.go:100-150` - Key rotation with cache expiry
- `oidc/jwks.go:180-220` - Inflight pattern for thundering herd prevention

### From zitadel/oidc (https://github.com/zitadel/oidc)

- `pkg/client/rp/relying_party.go` - Option pattern for client configuration
- `pkg/oidc/discovery.go` - Discovery metadata types

### Specification References

- OpenID Connect Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
- RFC 8414: https://www.rfc-editor.org/rfc/rfc8414
- RFC 9126 (PAR): https://www.rfc-editor.org/rfc/rfc9126
- FAPI 2.0 Security Profile: https://openid.net/specs/fapi-security-profile-2_0-final.html

## Architecture Insights

### Key Design Decisions

1. **Separate Metadata Types**: OAuth AS and OIDC Provider metadata should be separate types, with OIDC embedding OAuth fields. This reflects the specification hierarchy.

2. **Unexported Provider Fields**: Following coreos/go-oidc's pattern, keep Provider fields unexported to enforce controlled access and maintain invariants.

3. **Minimal Cache Interface**: The cache interface should be minimal (Get/Set/Delete) without TTL parameters. TTL is an implementation detail of the concrete cache.

4. **Lenient Parsing**: Use `json.RawMessage` or keep raw bytes to allow access to unknown fields without rejecting the entire document.

5. **Error Context**: Rich error types should include field names, expected vs actual values, and issuer context for debugging.

6. **Thread Safety**: Use `sync.RWMutex` for cache implementations and the inflight pattern for preventing duplicate remote requests.

### FAPI Extension Support

**PAR Fields** (RFC 9126):
- `pushed_authorization_request_endpoint` - URL for PAR endpoint
- `require_pushed_authorization_requests` - Boolean requiring PAR

**JARM Fields**:
- `authorization_signing_alg_values_supported`
- `authorization_encryption_alg_values_supported`

**Grant Management** (FAPI 2.0):
- `grant_management_endpoint`
- `grant_management_actions_supported`

**OIDC for Identity Assurance**:
- `trust_frameworks_supported`
- `evidence_supported`
- `verified_claims_supported`

## Package Structure Recommendation

```
pkg/
├── oidc/
│   ├── client.go          # Main Client type and constructor
│   ├── discovery.go       # Discovery fetching and validation
│   ├── metadata.go        # OAuth AS and OIDC Provider metadata types
│   ├── errors.go          # Error types and sentinel errors
│   └── options.go         # Functional options
├── jwks/
│   ├── keyset.go          # RemoteKeySet implementation
│   ├── cache.go           # Key cache interface and implementation
│   └── fetch.go           # JWKS fetching logic
└── cache/
    └── cache.go           # Generic cache interface
```

## Open Questions

1. **Signed Metadata**: Should we support validation of `signed_metadata` JWT field from RFC 8414? This is not widely implemented.

2. **Background Refresh**: Should the cache support automatic background refresh, or only on-demand refresh with stale-while-revalidate?

3. **HTTP Client Context**: Should we follow coreos/go-oidc's pattern of context-based HTTP client injection, or accept http.Client in constructor?

4. **FAPI Compliance Testing**: What specific providers should we test against for FAPI compliance (besides reference implementations)?

5. **JWKS Key Selection**: Should we implement algorithm-based key selection, or only kid-based selection?

## Related Research

- [Go Cache Interface Patterns](../../research/cache_interface_patterns.md) - Pluggable cache design patterns
- [Go Error Handling](../../research/go_error_patterns.md) - Rich error type patterns
- [Thread Safety in Go](../../research/go_concurrency_patterns.md) - Concurrent access patterns

---

*Research conducted on 2026-02-22 for FEATURE-001: Implement OpenID Connect Discovery with FAPI Extensions*
