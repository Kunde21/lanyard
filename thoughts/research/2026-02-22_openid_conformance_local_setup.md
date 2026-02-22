---
date: 2026-02-22T20:56:39+07:00
git_commit: ee7f3ee252139d602a996b77b58743c8420d2538
branch: master
repository: lanyard
topic: "Run OpenID Conformance Suite Locally (Docker Compose + mkcert)"
tags: [research, conformance, oidc, oauth2, docker, caddy, mkcert, local-dev]
last_updated: 2026-02-22
---

## Ticket Synopsis

This research supports FEATURE-002: establishing a local developer environment to run the OpenID Foundation conformance suite against the lanyard OIDC relying party library. The setup uses Docker Compose for orchestration, Caddy as a TLS-terminating reverse proxy, and mkcert for local certificate generation. The goal is to enable rapid iteration on OAuth/OIDC client behavior with a repeatable local testing environment.

## Summary

The lanyard codebase currently implements **discovery-only** OIDC/OAuth2 client functionality. It can fetch and cache provider metadata, validate it, and retrieve JWKS keys. However, it **lacks all protocol flow implementations** required for conformance testing:

- ❌ PKCE (RFC 7636)
- ❌ Pushed Authorization Requests client (RFC 9126)
- ❌ Dynamic Client Registration (RFC 7591)
- ❌ Authorization endpoint interactions
- ❌ Token endpoint exchange
- ❌ ID Token validation
- ❌ UserInfo endpoint

The conformance suite setup is a **green field** implementation - no Docker, Caddy, mkcert, or infrastructure patterns exist in the codebase. The example app (`examples/basic_discovery/main.go`) only demonstrates discovery and cannot serve as a conformance test RP without significant additions.

**Critical blocker identified**: The upstream OpenID Conformance Suite does not publish pre-built Docker images. It requires building from source (Maven + Java), conflicting with the "published images only" constraint in the ticket.

## Detailed Findings

### Current OIDC Implementation Capabilities

#### Discovery Implementation (✅ Complete)

**Files**: `oidc/client.go`, `oidc/discovery.go`, `oidc/metadata_provider.go`, `oidc/metadata_oauth_as.go`

The library implements complete discovery for both OIDC and OAuth 2.0:

```go
// From oidc/client.go:31-47
func NewClient(opts ...Option) *Client {
    logger := slog.New(slog.NewTextHandler(io.Discard, nil))
    c := &Client{
        httpClient:                   http.DefaultClient,
        logger:                       logger,
        discoveryCache:               cache.NewStore[*CacheEntry](),
        jwksCache:                    cache.NewStore[*jwks.CacheEntry](),
        defaultDiscoveryTTL:          defaultDiscoveryTTL,
        issuerTrailingSlashTolerance: false,
    }
    for _, opt := range opts {
        opt(c)
    }
    return c
}
```

**Discovery methods**:
- `DiscoverProvider(ctx, issuer)` - OIDC Discovery ([oidc/discovery.go:15-37])
- `DiscoverAuthorizationServer(ctx, issuer)` - OAuth 2.0 AS Discovery ([oidc/discovery.go:40-62])

**Metadata support**:
- Full OAuth 2.0 AS metadata ([oidc/metadata_oauth_as.go:7-31])
- Full OIDC Provider metadata ([oidc/metadata_provider.go:6-47])
- FAPI/PAR extensions parsed but not used ([oidc/metadata_provider.go:35-44])

#### JWKS Remote KeySet (✅ Complete)

**File**: `jwks/remote_keyset.go:26-187`

Implements remote JWKS fetching with:
- Caching with TTL and stale-while-revalidate
- ETag support for conditional requests
- Singleflight deduplication
- Rate limiting for unknown key ID refresh

Usage:
```go
// From oidc/jwks.go:11-31
func (c *Client) RemoteKeySet(ctx context.Context, issuer string) (*jwks.RemoteKeySet, error)
```

#### Caching Infrastructure (✅ Complete)

**Files**: `cache/store.go`, `oidc/cache.go`, `jwks/cache.go`

Thread-safe generic cache store with:
- `sync.RWMutex` for concurrent access
- Cache entry tracking (etag, freshUntil, fetchedAt)
- Stale-while-revalidate pattern

### Missing Components for Conformance

#### PKCE (❌ Not Implemented)

No PKCE support exists anywhere in the codebase:
- No code verifier generation
- No code challenge computation (S256/plain)
- No `code_challenge` parameter construction
- No `code_verifier` in token requests

**Impact**: Cannot pass OAuth 2.1 conformance tests (PKCE is mandatory).

#### PAR Client (❌ Not Implemented)

Only metadata fields exist ([oidc/metadata_provider.go:35-36]):
```go
PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
RequirePushedAuthorizationRequests *bool  `json:"require_pushed_authorization_requests,omitempty"`
```

Missing:
- `PushAuthorizationRequest()` method
- Request object construction/signing
- `request_uri` handling
- Fallback to regular authorization

#### Dynamic Client Registration (❌ Not Implemented)

Only metadata field exists ([oidc/metadata_oauth_as.go:12]):
```go
RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
```

Missing:
- `RegisterClient()` method
- Client metadata construction
- Registration response parsing
- Client credentials extraction

#### Authorization Flow (❌ Not Implemented)

No code for:
- `AuthorizationRequest` struct/builder
- Authorization URL construction
- Parameter encoding (`client_id`, `response_type`, `scope`, `redirect_uri`, `state`, `nonce`)
- Response handling (authorization code extraction, error handling)

#### Token Exchange (❌ Not Implemented)

No code for:
- `TokenRequest` for authorization code exchange
- Client authentication (basic auth, POST body)
- Token response parsing (`access_token`, `id_token`, `refresh_token`)
- Refresh token flow

#### ID Token Validation (❌ Not Implemented)

Despite having `RemoteKeySet` for key retrieval:
- No JWT parsing/validation logic
- No signature verification
- No claim validation (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, etc.)
- No `at_hash`/`c_hash` verification

### Example App Assessment

**File**: `examples/basic_discovery/main.go:1-27`

Current example:
```go
func main() {
    issuer := "https://accounts.google.com"
    client := oidc.NewClient()
    metadata, err := client.DiscoverProvider(context.Background(), issuer)
    // Prints: issuer, jwks_uri, response_types_supported
}
```

**Verdict**: Cannot serve as conformance test RP base. Requires:
- HTTP server for callback handling
- PKCE implementation
- Authorization URL building
- Token exchange
- ID token validation
- Session management

Essentially a complete rewrite adding all protocol flow implementations.

## Code References

### Core OIDC Implementation
- `oidc/client.go:17-47` - Client struct and constructor
- `oidc/discovery.go:15-62` - Discovery methods
- `oidc/metadata_provider.go:6-47` - OIDC provider metadata structure
- `oidc/metadata_oauth_as.go:7-31` - OAuth AS metadata structure
- `oidc/options.go:12-64` - Client configuration options
- `oidc/validate.go:102-167` - Metadata validation

### JWKS Implementation
- `jwks/remote_keyset.go:26-187` - Remote keyset with caching
- `jwks/cache.go` - JWKS cache implementation

### Caching Infrastructure
- `cache/store.go:7-42` - Generic cache store
- `oidc/cache.go:6-49` - OIDC cache structures

### Examples and Tests
- `examples/basic_discovery/main.go:1-27` - Current example app
- `oidc/live_compliance_test.go:17-47` - Live provider testing pattern
- `oidc/example_test.go:12-40` - Test server setup pattern

### Dependencies
- `go.mod:1-10` - Module definition and dependencies
  - `github.com/go-jose/go-jose/v4` - JOSE/JWT types (not used for validation)
  - `github.com/pquerna/cachecontrol` - HTTP Cache-Control parsing
  - `golang.org/x/sync` - singleflight deduplication

## Architecture Insights

### Library Design Philosophy

The lanyard library follows a **layered architecture** with clear separation:

1. **Discovery Layer**: Fetch and validate metadata (✅ Implemented)
2. **JWKS Layer**: Key retrieval and caching (✅ Implemented)
3. **Protocol Layer**: Authorization flows, token exchange (❌ Not Implemented)
4. **Validation Layer**: Token validation, claim verification (❌ Not Implemented)

This design allows the library to serve as a **foundation for higher-level OIDC/OAuth2 libraries** but makes it insufficient as a standalone RP implementation.

### Functional Options Pattern

The library uses Go's functional options pattern for configuration ([oidc/options.go:12-64]):

```go
type Option func(*Client)

func WithHTTPClient(client *http.Client) Option
func WithLogger(logger *slog.Logger) Option
func WithDiscoveryCache(store CacheStore) Option
```

**Benefits**: Extensible configuration without breaking API changes
**Usage**: `oidc.NewClient(oidc.WithHTTPClient(customClient))`

### Caching Strategy

Implements **stale-while-revalidate** pattern ([oidc/discovery.go:15-37]):
1. Check cache for fresh entry
2. If stale, return cached data immediately
3. Trigger async refresh in background
4. Subsequent calls get fresh data

This minimizes latency while ensuring data freshness.

### Test Patterns

**Live Testing Pattern** ([oidc/live_compliance_test.go:17-47]):
- Environment variable control (`LANYARD_LIVE_TESTS=1`)
- JSON test data loading
- Sub-tests for multiple providers
- Timeout configuration

**Mock Server Pattern** ([oidc/example_test.go:12-40]):
- `httptest.NewTLSServer()` for HTTPS testing
- Custom HTTP client with test server certs
- Mock discovery response serving

## Conformance Suite Requirements

### Required Components to Build

#### 1. Directory Structure
```
conformance/
├── README.md                    # User documentation
├── docker-compose.yml           # Main compose file
├── scripts/
│   └── setup.sh                 # mkcert certificate generation
└── Caddyfile                    # Reverse proxy configuration

cmd/
└── example-rp/                  # Example RP application
    └── main.go
```

#### 2. Docker Compose Stack

**Services needed**:
| Service | Purpose | Challenge |
|---------|---------|-----------|
| `server` | Conformance suite Java app | Requires building from source |
| `mongodb` | Test state storage | Use `mongo:6.0.13` image |
| `caddy` | TLS termination + routing | Standard `caddy:2` image |

**Critical environment variables**:
- `BASE_URL=https://suite.test` (must match proxy)
- `fintechlabs.devmode=true`
- `MONGODB_HOST=mongodb`

#### 3. Caddy Configuration

```
suite.test {
    reverse_proxy server:8080
    tls /etc/caddy/certs/suite.test.pem /etc/caddy/certs/suite.test-key.pem
}

rp.test {
    reverse_proxy host.docker.internal:8080
    tls /etc/caddy/certs/rp.test.pem /etc/caddy/certs/rp.test-key.pem
}
```

#### 4. mkcert Setup Script

**Requirements** ([thoughts/tickets/feature_openid_conformance_local.md:36-38]):
- Install mkcert if not present
- Generate certs for `suite.test` and `rp.test`
- Print (not edit) `/etc/hosts` entries
- Gitignore generated certificates

```bash
#!/bin/bash
# conformance/scripts/setup.sh

mkcert -install
mkcert suite.test rp.test

echo "Add to /etc/hosts:"
echo "127.0.0.1 suite.test"
echo "127.0.0.1 rp.test"
```

#### 5. Example RP Requirements

The example RP must implement:

**Core OAuth 2.1**:
- Authorization Code Flow with PKCE (S256)
- State and nonce handling
- Token endpoint authentication

**Advanced features**:
- PAR client with fallback
- Dynamic Client Registration
- Discovery from `https://suite.test/.well-known/openid-configuration`

**Integration**:
- HTTP server on host (outside Docker)
- Callback handler at `/callback`
- Session management for state/nonce

### Critical Blocker: Container Images

The upstream OpenID Conformance Suite (`gitlab.com/openid/conformance-suite`) **does not publish pre-built Docker images**. The Dockerfile requires:

```dockerfile
COPY target/fapi-test-suite.jar /app/
```

This requires a Maven build step:
```bash
mvn clean package -DskipTests
docker build -t conformance-suite .
```

**Conflict with ticket requirement**: "Use published container images (no upstream source checkout)"

**Potential solutions**:
1. Build image locally and push to private registry
2. Use alternative pre-built images (e.g., `waltid/openid-conformance-suite` if compatible)
3. Revise constraint to allow local build

## Historical Context

### Related Tickets and Plans

- `thoughts/tickets/feature_oidc_discovery.md` - OIDC Discovery with FAPI Extensions (completed)
- `thoughts/plans/oidc_discovery_client.md` - 5-phase implementation plan for discovery client
- `thoughts/research/2026-02-22_oidc_discovery_implementation.md` - Research on OIDC discovery patterns

The conformance suite setup builds on the discovery implementation but requires extending it with full protocol flow support.

## Related Research

- `thoughts/research/2026-02-22_oidc_discovery_implementation.md` - OIDC Discovery Implementation Research

## Open Questions

1. **Container Image Source**: How to handle the lack of published conformance suite images? Options:
   - Build from source locally
   - Find compatible pre-built alternative
   - Create and maintain private registry image

2. **OAuth 2.1 Scope**: Which specific test plans should be targeted? The ticket mentions "OAuth 2.0/2.1" but doesn't specify exact conformance profiles.

3. **RP Hosting**: How should the example RP running on the host be accessible to the conformance suite in Docker? Options:
   - `host.docker.internal` (Docker Desktop only)
   - Host network mode
   - Separate container for RP

4. **PAR Implementation**: Should the example RP implement PAR client or standard authorization flow only? Ticket suggests PAR with fallback.

5. **DCR Support**: Should dynamic client registration be implemented? Ticket lists it as optional.

6. **Implementation Priority**: Should the library gain protocol flow capabilities before building the conformance setup, or build the setup to drive library development?

## Implementation Recommendations

### Immediate Actions

1. **Resolve container image blocker** - Determine approach for conformance suite image
2. **Define MVP scope** - Decide which OAuth 2.1 test profiles to target initially
3. **Create directory structure** - Set up `conformance/` and `cmd/example-rp/` directories
4. **Implement basic setup script** - mkcert certificate generation and hosts file output

### Short-term (Library Development)

Before the conformance suite can be useful, the library needs:

1. **PKCE implementation** - Code verifier/challenge generation ([RFC 7636](https://tools.ietf.org/html/rfc7636))
2. **Basic authorization flow** - URL construction and callback handling
3. **Token exchange** - Authorization code → tokens
4. **Minimal ID token validation** - Signature verification using JWKS

### Medium-term (Conformance Integration)

1. **PAR client implementation** - RFC 9126 pushed authorization requests
2. **DCR support** - RFC 7591 dynamic client registration
3. **Complete example RP** - Full-featured conformance test application
4. **Documentation** - `conformance/README.md` with setup and usage instructions

## Conclusion

The lanyard library provides a solid foundation for OIDC discovery but lacks the protocol flow implementations required for conformance testing. Setting up the OpenID Conformance Suite locally is feasible but requires:

1. Resolving the container image availability issue
2. Implementing missing OIDC/OAuth2 protocol flows in the library
3. Building a comprehensive example RP application
4. Creating Docker Compose infrastructure with Caddy and mkcert

The research identifies specific gaps and provides a roadmap for both the conformance setup and necessary library enhancements.
