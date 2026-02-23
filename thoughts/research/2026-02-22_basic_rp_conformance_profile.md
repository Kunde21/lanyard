---
date: 2026-02-22T23:25:43+07:00
git_commit: d5bb462922e5d071c6c550848fcb23d852767212
branch: master
repository: lanyard
topic: "Implement Basic RP Test Profile and Verify Against Conformance Suite"
tags: [research, oidc, conformance, rp, basic-profile, authorization-code, id-token, userinfo]
last_updated: 2026-02-22
---

## Ticket Synopsis

This research addresses **FEATURE-003: Implement Basic RP Test Profile and Verify Against Conformance Suite**. The goal is to evolve the current placeholder example RP (`cmd/example-rp/main.go`) into a fully functional OpenID Connect Relying Party that can pass the "OpenID Connect Core: Basic Certification Profile Relying Party Tests" in the local conformance environment.

**Key Challenge**: The current implementation only has discovery and JWKS capabilities. The Basic RP profile requires complete authorization code flow, ID token validation, and UserInfo endpoint support.

**Success Criteria**: Local execution against the targeted basic RP profile passes with captured evidence, and runbook docs enable another engineer to reproduce the same result.

## Summary

The codebase has a **solid foundation** for building a conformant RP:
- ✅ **Discovery Layer**: Complete OIDC/OAuth AS discovery with caching (`oidc/discovery.go`)
- ✅ **JWKS Layer**: Remote key fetching with rotation support (`jwks/remote_keyset.go`)
- ✅ **HTTP Patterns**: Context-aware requests, ETag support, error handling
- ✅ **Validation Framework**: Metadata validation with structured errors (`oidc/validate.go`)

**Missing for Conformance**:
- ❌ Authorization code flow (auth URL construction, callback handling)
- ❌ Token exchange (POST to token endpoint, client auth)
- ❌ ID token validation (JWT parsing, signature verification, claim validation)
- ❌ UserInfo client (authenticated requests, response parsing)
- ❌ Session management (state/nonce storage, CSRF protection)

**Implementation Path**: Extend the existing `oidc.Client` with RP-specific methods or create an `rp` package that wraps the Client. The example RP needs: (1) `/login` endpoint for flow initiation, (2) enhanced `/callback` handler for code exchange and validation, (3) session storage for security parameters.

## Detailed Findings

### Current Implementation State

#### What Exists: Discovery & JWKS Infrastructure

**Client Structure** (`oidc/client.go:17-28`):
```go
type Client struct {
    httpClient     *http.Client
    logger         *slog.Logger
    discoveryCache CacheStore
    jwksCache      jwks.CacheStore
    issuerTrailingSlashTolerance bool
    defaultDiscoveryTTL          time.Duration
    discoveryGroup singleflight.Group
}
```

**Key Capabilities**:
- Provider/AS discovery with stale-while-revalidate caching (`oidc/discovery.go:15-62`)
- Remote JWKS with key rotation support (`jwks/remote_keyset.go:26-187`)
- Configurable HTTP clients, loggers, and caches via functional options (`oidc/options.go:12-64`)
- Metadata validation with detailed errors (`oidc/validate.go:102-167`)

**Usage Pattern** (from `oidc/example_test.go`):
```go
client := oidc.NewClient(oidc.WithHTTPClient(httpClient))
metadata, err := client.DiscoverProvider(ctx, issuer)
remoteKeySet, err := client.RemoteKeySet(ctx, issuer)
```

#### What Exists: Example RP Placeholder

**Current State** (`cmd/example-rp/main.go:1-31`):
- HTTP server on `:8080`
- `/` endpoint: static health check
- `/callback` endpoint: placeholder that only prints HTTP method

**No Protocol Logic**: The callback handler does not parse authorization codes, exchange tokens, or validate ID tokens.

### Required Implementation for Basic RP Profile

#### 1. Authorization Code Flow

**Authorization Request Construction**:
- Generate cryptographically random `state` (CSRF protection)
- Generate `nonce` (replay attack protection)  
- Generate PKCE `code_verifier` and `code_challenge` (RFC 7636)
- Build authorization URL with parameters:
  ```
  response_type=code
  client_id={client_id}
  redirect_uri=https://rp.test/callback
  scope=openid
  state={state}
  nonce={nonce}
  code_challenge={code_challenge}
  code_challenge_method=S256
  ```

**Implementation Location**: New `/login` handler in `cmd/example-rp/main.go` (~lines 40-80)

**Reference Metadata** (`oidc/metadata_provider.go:6-47`):
- `AuthorizationEndpoint` - URL to redirect user
- `TokenEndpoint` - URL for code exchange
- `UserinfoEndpoint` - URL for user claims

#### 2. Token Exchange

**Token Request** (POST to `metadata.TokenEndpoint`):
```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic {base64(client_id:client_secret)}

grant_type=authorization_code
&code={authorization_code}
&redirect_uri=https://rp.test/callback
&code_verifier={pkce_verifier}
```

**Token Response Parsing**:
- `access_token` - For UserInfo endpoint
- `id_token` - JWT to validate
- `token_type` - "Bearer"
- `expires_in` - Token lifetime

**Client Authentication**: Support `client_secret_basic` (HTTP Basic Auth) and `client_secret_post` (form parameters) per `oidc/metadata_oauth_as.go:17`.

#### 3. ID Token Validation

**Required Validations** per OIDC Core Section 3.1.3.7:

| Claim | Validation Rule |
|-------|----------------|
| `iss` | Must match discovered issuer |
| `sub` | Must be present (string) |
| `aud` | Must contain `client_id` |
| `exp` | Must be in future (with clock skew) |
| `iat` | Must be in past (with clock skew) |
| `nonce` | Must match request nonce |
| `azp` | If multiple audiences, must be `client_id` |

**Signature Verification**:
1. Parse JWT header to extract `kid` (key ID)
2. Fetch signing key: `remoteKeySet.Key(ctx, kid)` (`jwks/remote_keyset.go:91-127`)
3. Verify using `go-jose/go-jose/v4` library (already in `go.mod`)
4. Support `RS256` algorithm (required by Basic profile)

**Clock Skew Tolerance**: Typically ±5 minutes for `iat` and `exp` validation.

#### 4. UserInfo Endpoint

**Request**:
```
GET /userinfo HTTP/1.1
Authorization: Bearer {access_token}
```

**Response Handling**:
- Support JSON format (required)
- Support signed JWT (optional for Basic)
- Validate `sub` claim matches ID Token

**Endpoint Discovery**: `metadata.UserinfoEndpoint` (`oidc/metadata_provider.go:9`)

#### 5. Session Management

**Required State Storage**:
```go
type Session struct {
    State        string    // CSRF protection
    Nonce        string    // Replay protection
    CodeVerifier string    // PKCE
    CreatedAt    time.Time // Expiry
}
```

**Storage**: In-memory map with mutex (sufficient for conformance):
```go
var sessions = map[string]*Session{}
var sessionsMu sync.RWMutex
```

**Security Parameters** (32+ random bytes each, base64url encoded):
- `state`: CSRF token
- `nonce`: Replay prevention
- `code_verifier`: PKCE verifier

### Conformance Test Requirements

#### Target Profile

**Name**: `OpenID Connect Core: Basic Certification Profile Relying Party Tests`

**Configuration** (`conformance/README.md:81-89`):
- Client type: confidential or public
- Redirect URIs: `https://rp.test/callback`
- Response type: `code`
- Grant type: `authorization_code`
- Token endpoint auth: `client_secret_basic`

#### Positive Test Scenarios

1. **Discovery Test**: RP correctly discovers OP metadata
2. **Authorization Code Flow**: Complete flow from auth request to tokens
3. **ID Token Validation**: Signature and claim verification
4. **UserInfo Access**: Fetch and validate user claims

#### Negative Test Scenarios

**ID Token Failures**:
- Invalid signature (tampered token)
- Wrong issuer (`iss` mismatch)
- Wrong audience (`aud` doesn't contain `client_id`)
- Expired token (`exp` in past)
- Invalid nonce (if sent in request)

**Token Endpoint Failures**:
- Invalid/reused authorization code
- Invalid client credentials
- Mismatched `redirect_uri`

**Security Failures**:
- Missing/invalid `state` parameter (CSRF)
- Missing `nonce` when required

### Architecture Insights

#### Layered Architecture

```
┌─────────────────────────────────────────┐
│  Protocol Layer (NEEDED)                │
│  - Authorization flows                  │
│  - Token exchange                       │
│  - ID token validation                  │
│  - UserInfo                             │
├─────────────────────────────────────────┤
│  JWKS Layer (EXISTS)                    │
│  - RemoteKeySet                         │
│  - Key caching                          │
│  - Rotation handling                    │
├─────────────────────────────────────────┤
│  Discovery Layer (EXISTS)               │
│  - Provider metadata                    │
│  - AS metadata                          │
│  - Validation                           │
└─────────────────────────────────────────┘
```

#### Extension Pattern

**Recommended**: Wrap the existing Client rather than modifying it:

```go
// rp/rp.go
type RP struct {
    *oidc.Client
    clientID     string
    clientSecret string
    redirectURI  string
}

func (r *RP) AuthorizationURL(state, nonce string) (string, error) {
    metadata, err := r.DiscoverProvider(ctx, r.issuer)
    // Build and return authorization URL
}

func (r *RP) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
    // POST to token endpoint
}
```

#### Pattern Consistency

The codebase follows these patterns consistently:
- **Functional Options**: `NewClient(opts ...Option)` for configuration
- **Context Awareness**: All network operations accept `context.Context`
- **Error Wrapping**: `fmt.Errorf("...: %w", err)` with structured error types
- **Caching**: Stale-while-revalidate with background refresh
- **Validation**: Structured `ValidationError` with field-level details
- **Singleflight**: Deduplication of concurrent requests

## Code References

### Core Library Files

- `oidc/client.go:17-28` - Client struct definition
- `oidc/discovery.go:15-37` - Provider discovery with caching
- `oidc/discovery.go:40-62` - OAuth AS discovery
- `oidc/metadata_provider.go:6-47` - ProviderMetadata struct
- `oidc/metadata_oauth_as.go:7-31` - AuthorizationServerMetadata struct
- `oidc/validate.go:102-144` - Provider metadata validation
- `oidc/options.go:12-64` - Functional options pattern
- `oidc/errors.go:8-76` - Error types and handling

### JWKS Files

- `jwks/remote_keyset.go:26-62` - NewRemoteKeySet constructor
- `jwks/remote_keyset.go:64-89` - Keys() method with caching
- `jwks/remote_keyset.go:91-127` - Key() method by kid
- `jwks/remote_keyset.go:139-185` - Refresh with singleflight
- `jwks/http_fetch.go:26-67` - HTTP fetching with ETag
- `jwks/options.go:9-64` - Configuration options
- `jwks/errors.go:8-57` - Error types

### Example RP

- `cmd/example-rp/main.go:1-31` - Current placeholder implementation
- `cmd/example-rp/main.go:27-31` - Callback handler (to replace)

### Conformance Setup

- `conformance/README.md:1-105` - Runbook for local conformance
- `conformance/docker-compose.yml` - Local stack configuration
- `conformance/Caddyfile` - TLS termination and routing
- `conformance/scripts/setup.sh` - mkcert certificate generation
- `conformance/scripts/build_suite.sh` - Suite image building

### Example Usage

- `examples/basic_discovery/main.go` - Discovery example
- `oidc/example_test.go` - Client usage examples
- `jwks/remote_keyset_integration_test.go` - Key rotation tests

## Historical Context (from thoughts/)

### Architecture Decisions

**From `thoughts/research/2026-02-22_oidc_discovery_implementation.md`**:
- Provider type design with unexported fields and controlled access
- Metadata type design with comprehensive structs and JSON tags
- Lenient parsing with raw claims access via `json.RawMessage`
- RemoteKeySet structure with cache expiry and singleflight
- Minimal pluggable cache interface design

**From `thoughts/plans/oidc_discovery_client.md`**:
- 5-phase implementation approach (completed)
- Dependencies: `go-jose/go-jose/v4`, `cachecontrol`, `singleflight`
- Caching model with minimal cache interfaces
- Validation model for required fields and security

### Conformance Setup Context

**From `thoughts/research/2026-02-22_openid_conformance_local_setup.md`**:
- The conformance suite must be built locally (no pre-built images)
- Local infrastructure uses Caddy for TLS termination
- Domains: `suite.test` (suite UI) and `rp.test` (example RP)
- The current RP is expected to fail until protocol features are implemented

**From `thoughts/plans/openid_conformance_local.md`**:
- Phase-based implementation completed through Phase 4
- Phase 4 includes documentation for first (failing) basic RP plan run
- Initial run is expected to fail due to missing RP protocol features

### Related Tickets

- `thoughts/tickets/feature_openid_conformance_local.md` - Local conformance setup (✅ implemented)
- `thoughts/tickets/feature_oidc_discovery.md` - OIDC discovery with FAPI extensions (✅ implemented)
- `thoughts/tickets/feature_basic_rp_test_profile.md` - This ticket (🔄 in progress)

## Implementation Recommendations

### Phase 1: Foundation

1. **Add Session Management**:
   - Create `cmd/example-rp/session.go` with in-memory session store
   - Generate secure random values for state, nonce, code_verifier

2. **Add Authorization Initiation**:
   - Create `/login` handler in `cmd/example-rp/main.go`
   - Build authorization URL using discovered metadata
   - Store session with state as key

### Phase 2: Token Exchange

1. **Enhance Callback Handler**:
   - Replace placeholder `handleCallback` (lines 27-31)
   - Parse `code` and `state` from query parameters
   - Validate state against session store
   - POST to token endpoint with code + code_verifier

2. **Create Token Types**:
   - Add `pkg/oidc/token.go` with TokenRequest/TokenResponse structs
   - Implement client authentication (client_secret_basic/post)

### Phase 3: ID Token Validation

1. **Add JWT Validation**:
   - Extend `oidc/validate.go` or create `pkg/oidc/idtoken.go`
   - Use `go-jose/go-jose/v4` for JWT parsing
   - Implement all required claim validations
   - Fetch signing keys via `RemoteKeySet.Key()`

### Phase 4: UserInfo

1. **Add UserInfo Client**:
   - Create `pkg/oidc/userinfo.go`
   - Implement GET request with Bearer token
   - Parse JSON response and validate `sub` claim

### Phase 5: Testing & Documentation

1. **Test Against Conformance Suite**:
   - Run `OpenID Connect Core: Basic Certification Profile Relying Party Tests`
   - Capture conformance report with test IDs/statuses
   - Verify negative test scenarios pass

2. **Update Documentation**:
   - Update `conformance/README.md` with passing workflow
   - Document configuration requirements
   - Provide troubleshooting guide

## Open Questions

1. **PKCE Requirement**: Does the Basic RP profile require PKCE, or is it optional? OAuth 2.1 requires it, but OIDC Basic may not.

2. **PKCE Support**: Should we implement PKCE now or defer to a later ticket? The ticket mentions "no PKCE/hybrid in this ticket" but OAuth 2.1 conformance may require it.

3. **Package Structure**: Should RP functionality be added to the existing `oidc` package or a new `rp` package?

4. **ID Token Validation Location**: Should ID token validation be a method on `Client` or a standalone function?

5. **Session Persistence**: Is in-memory storage sufficient, or should we support external session stores (Redis, database)?

6. **Refresh Tokens**: Out of scope per ticket, but should we at least parse and store them?

## Related Research

- `thoughts/research/2026-02-22_openid_conformance_local_setup.md` - Local conformance environment setup
- `thoughts/research/2026-02-22_oidc_discovery_implementation.md` - OIDC discovery implementation patterns
- `thoughts/plans/openid_conformance_local.md` - Conformance setup implementation plan
- `thoughts/plans/oidc_discovery_client.md` - OIDC discovery client implementation plan
