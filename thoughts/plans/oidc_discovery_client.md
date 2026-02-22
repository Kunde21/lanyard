# FEATURE-001 OIDC Discovery (FAPI) Implementation Plan

## Overview

Implement a production-ready Go relying-party library for OpenID Connect Discovery and OAuth 2.0 Authorization Server Metadata (RFC 8414), including JWKS fetching with rotation and thread-safe caching. This repo is greenfield (no Go source files yet), so the plan creates the initial package structure and public API.

## Current State Analysis

- No implementation exists yet (no `*.go` files, no tests). Only module metadata exists at `go.mod:1`.
- Project conventions to follow are defined in `AGENTS.md:1` (notably: gofumpt, go-cmp, slog, error wrapping).
- Requirements are defined in `thoughts/tickets/feature_oidc_discovery.md:11`.
- Initial research patterns are captured in `thoughts/research/2026-02-22_oidc_discovery_implementation.md:40`.

Key constraints from the ticket:
- This is client-side discovery only; no OAuth/OIDC flows (see out-of-scope in `thoughts/tickets/feature_oidc_discovery.md:79`).
- Parsing must be lenient to unknown JSON fields (see `thoughts/tickets/feature_oidc_discovery.md:37`).
- Cache interface must be minimal Get/Set/Delete (see `thoughts/tickets/feature_oidc_discovery.md:52`).
- Background/async refresh is required; we will implement stale-while-revalidate (SWR) by default.

## Desired End State

After completing this plan:
- Library users can call a single `oidc.Client` to fetch and validate:
  - OIDC Provider metadata from `/.well-known/openid-configuration`
  - OAuth Authorization Server metadata from `/.well-known/oauth-authorization-server` (RFC 8414)
- Users can fetch/cached-refresh JWKS from `jwks_uri` with key rotation and `kid` lookup.
- All public APIs are safe for concurrent use.
- Tests cover parsing, validation, caching/refresh, JWKS rotation, and error types.

### Verification

#### Automated Verification
- [x] Unit + integration tests pass: `go test ./...`
- [x] Code formatted: `gofumpt ./...`
- [x] No vet issues: `go vet ./...`
- [x] Module builds: `go build ./...`

#### Manual Verification
- [ ] Can fetch discovery from at least two public providers (e.g., Google + Okta) with strict issuer validation
- [x] JWKS rotation behavior works (unknown `kid` triggers refresh and subsequently resolves)
- [x] FAPI extension fields appear in parsed metadata structs
- [x] Logs (when enabled) are structured and do not include secrets

## What We're NOT Doing

- OAuth/OIDC protocol flows (auth code, token exchange) (`thoughts/tickets/feature_oidc_discovery.md:81`)
- Token verification (JWT/JWS verification helpers) (`thoughts/tickets/feature_oidc_discovery.md:82`)
- PAR/JARM protocol handling (metadata only) (`thoughts/tickets/feature_oidc_discovery.md:83`)
- URL building helpers (`thoughts/tickets/feature_oidc_discovery.md:85`)
- Built-in retries/timeouts beyond what the provided `http.Client` does (`thoughts/tickets/feature_oidc_discovery.md:87`)

## Implementation Approach

### Package Layout (no `pkg/`, no `internal/`)

- `oidc/`
  - Discovery client, metadata types, validation, options, error types
- `jwks/`
  - Remote JWKS fetching + caching/rotation + `kid` lookup
- `cache/`
  - Generic in-memory cache implementation used by `oidc` and `jwks`

### Dependencies

- `github.com/go-jose/go-jose/v4` for JWKS parsing/representation
- `golang.org/x/sync/singleflight` for request de-duplication (thundering herd prevention)
- `github.com/pquerna/cachecontrol` to compute freshness lifetime from HTTP caching headers

### Caching Model

- Define minimal cache interfaces in the consumer packages (`oidc` and `jwks`) using concrete (opaque) cache entry types.
- Provide a generic in-memory cache implementation in `cache/` that implements those interfaces when instantiated with the appropriate type parameter.
  - Example: `cache.NewStore[*oidc.CacheEntry]()` satisfies `oidc.CacheStore`.
  - Example: `cache.NewStore[*jwks.CacheEntry]()` satisfies `jwks.CacheStore`.
- SWR default: if cached metadata/JWKS is stale, return it immediately and refresh asynchronously.
- Respect HTTP caching headers when present; fall back to defaults when absent:
  - Discovery default freshness: 1 hour
  - JWKS default freshness: 1 hour
- Use `ETag` and conditional requests (`If-None-Match`) when available.

### Validation Model

- Required fields for OIDC provider metadata (per ticket):
  - `issuer`, `authorization_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`
- Validate:
  - `issuer` scheme https, no query/fragment
  - endpoints are valid URLs and https (jwks_uri required https)
  - issuer matches exactly by default
- Interop option: allow a single trailing slash mismatch for issuer equality (opt-in).

### Well-known URL Construction

- OIDC discovery: append `/.well-known/openid-configuration` to the issuer (OIDC Discovery 1.0 §4.1).
  - If issuer has a path component, remove terminating `/` then append.
- RFC 8414: insert `/.well-known/oauth-authorization-server` between host and issuer path (RFC 8414 §3).

## Phase 1: Scaffolding + Public API + Core Types

### Overview

Create the foundational packages and public API surface (Client/options/errors/logging) without implementing network behavior fully yet.

### Changes Required

#### 1. `cache` package
**File**: `cache/store.go`
**Changes**: Define a generic in-memory cache type `cache.Store[V]`.

```go
package cache

// Store is a generic in-memory cache.
// Store is safe for concurrent use.
type Store[V any] struct {
	// ... sync.RWMutex + map storage
}

func NewStore[V any]() *Store[V]

func (s *Store[V]) Get(key string) (value V, ok bool)
func (s *Store[V]) Set(key string, value V)
func (s *Store[V]) Delete(key string)
```

#### 2. `oidc` package: client + options
**File**: `oidc/client.go`
**Changes**: Define `Client` holding:
- `httpClient *http.Client`
- `logger *slog.Logger`
- `discoveryCache oidc.CacheStore`
- `jwksCache jwks.CacheStore`
- `singleflight.Group` for discovery fetch de-dupe

Defaults:
- if `discoveryCache` unset: `cache.NewStore[*oidc.CacheEntry]()`
- if `jwksCache` unset: `cache.NewStore[*jwks.CacheEntry]()`

**File**: `oidc/cache.go`
**Changes**: Define the cache interface and opaque entry type used by `oidc`.

```go
package oidc

// CacheStore is the minimal cache interface used by the oidc package.
// Implementations must be safe for concurrent use.
type CacheStore interface {
	Get(key string) (value *CacheEntry, ok bool)
	Set(key string, value *CacheEntry)
	Delete(key string)
}

// CacheEntry is an opaque cached discovery entry.
// Its fields are intentionally unexported.
type CacheEntry struct {
	// unexported
}
```

**File**: `oidc/options.go`
**Changes**: Functional options:
- `WithHTTPClient(*http.Client)`
- `WithLogger(*slog.Logger)`
- `WithDiscoveryCache(oidc.CacheStore)`
- `WithJWKSCache(jwks.CacheStore)`
- `WithIssuerTrailingSlashTolerance(bool)`
- `WithDefaultDiscoveryTTL(time.Duration)`

#### 3. `oidc` package: errors
**File**: `oidc/errors.go`
**Changes**: Define rich errors with structured fields:
- `ValidationError` (issuer, field, expected/actual, wrapped err)
- `HTTPStatusError` (url, status, limited body preview)
- Sentinel errors (e.g., `ErrInvalidIssuer`, `ErrDiscoveryFailed`)

#### 4. `jwks` package: errors + options skeleton
**File**: `jwks/errors.go`
**Changes**: `KeyNotFoundError`, `FetchError`, sentinel errors.

**File**: `jwks/cache.go`
**Changes**: Define the cache interface and opaque entry type used by `jwks`.

```go
package jwks

// CacheStore is the minimal cache interface used by the jwks package.
// Implementations must be safe for concurrent use.
type CacheStore interface {
	Get(key string) (value *CacheEntry, ok bool)
	Set(key string, value *CacheEntry)
	Delete(key string)
}

// CacheEntry is an opaque cached JWKS entry.
// Its fields are intentionally unexported.
type CacheEntry struct {
	// unexported
}
```

**File**: `jwks/options.go`
**Changes**: Options for:
- `WithHTTPClient(*http.Client)`
- `WithLogger(*slog.Logger)`
- `WithCache(jwks.CacheStore)`
- default TTL
- expiry delta (e.g., 30s)
- minimum refresh interval to mitigate unknown-kid refresh storms

### Success Criteria

#### Automated Verification
- [x] `go test ./...` passes (initially mostly compile tests)
- [x] `gofumpt ./...` produces no diffs

#### Manual Verification
- [x] `go doc ./...` shows doc comments for exported identifiers

---

## Phase 2: Metadata Types (OIDC + RFC 8414 + FAPI)

### Overview

Implement typed Go structures for metadata documents with lenient JSON parsing and raw-claims retention.

### Changes Required

#### 1. OAuth AS metadata (RFC 8414)
**File**: `oidc/metadata_oauth_as.go`
**Changes**: Define `AuthorizationServerMetadata` with:
- required fields (`issuer`, `response_types_supported`)
- common optional fields (token endpoint, jwks_uri, etc.)
- `Raw json.RawMessage` to retain full JSON document

#### 2. OIDC provider metadata (OIDC Discovery)
**File**: `oidc/metadata_provider.go`
**Changes**: Define `ProviderMetadata` embedding `AuthorizationServerMetadata` and adding OIDC-required fields:
- `SubjectTypesSupported []string`
- `IDTokenSigningAlgValuesSupported []string`

#### 3. FAPI extension fields
**File**: `oidc/metadata_fapi.go`
**Changes**: Add fields listed in the ticket (`thoughts/tickets/feature_oidc_discovery.md:213`), e.g.:
- PAR: `PushedAuthorizationRequestEndpoint`, `RequirePushedAuthorizationRequests`
- JARM: `AuthorizationSigningAlgValuesSupported`, `AuthorizationEncryptionAlgValuesSupported`
- Grant management: `GrantManagementEndpoint`, `GrantManagementActionsSupported`
- Identity assurance: `TrustFrameworksSupported`, `EvidenceSupported`, `VerifiedClaimsSupported`

Implementation detail: keep these in the same `ProviderMetadata` struct (preferred for ergonomics), but keep `Raw` for unknowns.

#### 4. Lenient parsing + raw claims API
**File**: `oidc/claims.go`
**Changes**:
- `func (m ProviderMetadata) Claims(dst any) error`
- `func (m AuthorizationServerMetadata) Claims(dst any) error`

### Success Criteria

#### Automated Verification
- [x] Unit tests for JSON parsing + raw claims round-trips: `go test ./...`

#### Manual Verification
- [x] Adding unknown fields to fixture JSON does not break parsing and remains accessible via `Claims`.

---

## Phase 3: Discovery Fetch + Validation + SWR Caching

### Overview

Implement fetching/parsing/validation for both discovery endpoints, with caching and SWR refresh.

### Changes Required

#### 1. Well-known URL builders
**File**: `oidc/well_known.go`
**Changes**:
- `func OIDCWellKnownURL(issuer string) (string, error)` (append model)
- `func OAuthASWellKnownURL(issuer string) (string, error)` (insert model)

Include unit tests for:
- issuer with/without path
- trailing slash handling
- invalid issuers (non-https, query, fragment)

#### 2. HTTP fetcher
**File**: `oidc/http_fetch.go`
**Changes**:
- `GET` JSON with `Accept: application/json`
- cap response body read for error messages
- parse cache headers (`Cache-Control`, `Expires`, `ETag`) using `cachecontrol`

#### 3. Discovery methods
**File**: `oidc/discovery.go`
**Changes**:
- `func (c *Client) DiscoverProvider(ctx context.Context, issuer string) (ProviderMetadata, error)`
- `func (c *Client) DiscoverAuthorizationServer(ctx context.Context, issuer string) (AuthorizationServerMetadata, error)`

Caching behavior:
- Cache key format (stable + collision-resistant):
  - `oidc:provider-metadata:v1:{issuer}`
  - `oidc:authz-server-metadata:v1:{issuer}`
- Cache value is `*oidc.CacheEntry` containing:
  - parsed metadata
  - `etag string`
  - `freshUntil time.Time`
  - (optionally) `fetchedAt time.Time` for debugging
- SWR:
  - If entry exists and is fresh: return it
  - If entry exists and is stale: return it and start a goroutine refresh (deduped via singleflight)
  - If entry missing: fetch synchronously

#### 4. Validation
**File**: `oidc/validate.go`
**Changes**:
- strict issuer equality by default
- opt-in trailing slash tolerance
- required field checks and https URL checks for endpoints

#### 5. Integration tests
**File**: `oidc/discovery_integration_test.go`
**Changes**: Use `httptest.Server` to simulate:
- normal 200 JSON
- cache headers with max-age
- ETag + 304 Not Modified refresh
- stale entry returned while background refresh occurs

### Success Criteria

#### Automated Verification
- [x] Unit tests for URL building + validation: `go test ./...`
- [x] Integration tests for SWR caching + ETag: `go test ./...`

#### Manual Verification
- [x] Enable logger and confirm no sensitive data is logged (no raw tokens).

---

## Phase 4: JWKS Fetching + Caching + Rotation + kid Lookup

### Overview

Implement JWKS fetching via URL, caching based on HTTP headers, refresh-on-unknown-kid, and thread-safe key lookup.

### Changes Required

#### 1. Remote key set
**File**: `jwks/remote_keyset.go`
**Changes**:
- `type RemoteKeySet struct` holding jwks URL, http client, logger, `jwks.CacheStore`, singleflight group
- `func NewRemoteKeySet(jwksURL string, opts ...Option) (*RemoteKeySet, error)`
- `func (r *RemoteKeySet) Keys(ctx context.Context) ([]jose.JSONWebKey, error)`
- `func (r *RemoteKeySet) Key(ctx context.Context, kid string) (jose.JSONWebKey, error)`

Caching behavior:
- Cache key format:
  - `jwks:keyset:v1:{jwksURL}`
- Cache value is `*jwks.CacheEntry` containing keys, etag, freshUntil.

Rotation behavior:
- If requested `kid` not found in cached keys, trigger refresh (singleflight) subject to a minimum refresh interval.
- If refresh fails and cached keys exist, return `KeyNotFoundError` (not a fetch error) but log refresh failure at debug/warn level.

#### 2. JWKS fetcher
**File**: `jwks/http_fetch.go`
**Changes**:
- GET jwks URI
- conditional request with ETag when available
- parse JWKS JSON into `jose.JSONWebKeySet`
- compute `freshUntil` via cache headers (default TTL fallback)

#### 3. Integration with `oidc.Client`
**File**: `oidc/jwks.go`
**Changes**:
- `func (c *Client) RemoteKeySet(ctx context.Context, issuer string) (*jwks.RemoteKeySet, error)`
  - uses discovered `jwks_uri` from provider metadata
  - configures the returned key set with `c.httpClient`, `c.logger`, and `c.jwksCache`

#### 4. Tests
**Files**:
- `jwks/remote_keyset_test.go`
- `jwks/remote_keyset_integration_test.go`

Test scenarios:
- cache headers honored
- 304 Not Modified updates freshness
- unknown-kid triggers refresh and then resolves after server rotates keys
- concurrent callers do not stampede (singleflight)

### Success Criteria

#### Automated Verification
- [x] `go test ./...` covers JWKS caching and rotation behavior

#### Manual Verification
- [x] With logging enabled, observe refresh triggered on unknown `kid` without excessive repeated refresh.

---

## Phase 5: Examples + Compliance Harness

### Overview

Provide examples and a deterministic compliance test harness primarily using fixtures and mock servers; optionally allow live-provider tests.

### Changes Required

#### 1. Examples
**Files**:
- `oidc/example_test.go` (Go doc examples)
- Optionally `examples/basic_discovery/main.go`

Examples to include (from ticket):
- Basic discovery fetch
- Accessing FAPI metadata fields
- JWKS key lookup by `kid` (no JWT verification)

#### 2. Compliance fixtures
**Files**:
- `oidc/testdata/provider_metadata_minimal.json`
- `oidc/testdata/provider_metadata_fapi.json`
- `jwks/testdata/jwks_rotation_set1.json`
- `jwks/testdata/jwks_rotation_set2.json`

#### 3. Optional live tests
**File**: `oidc/live_compliance_test.go`
**Changes**:
- Guard behind an env var (e.g., `LANYARD_LIVE_TESTS=1`) or build tag
- Provider list file (JSON) checked into repo (non-secret), e.g. `oidc/testdata/providers.json`

### Success Criteria

#### Automated Verification
- [x] `go test ./...` passes without network access
- [x] Live tests run only when enabled via env/build tag

#### Manual Verification
- [x] Examples compile and run successfully.

---

## Testing Strategy

### Unit Tests
- URL construction:
  - OIDC append model
  - RFC 8414 insert model
- Validation:
  - strict issuer match
  - tolerant trailing slash option
  - required fields present
- Parsing:
  - unknown fields ignored but accessible via `Claims`
- Error types:
  - compare errors via `errors.Is` and validate formatting (including `%+v` where relevant)

### Integration Tests (Mock HTTP)
- `httptest.Server` simulating discovery + jwks endpoints with:
  - cache headers and ETag
  - key rotation
  - concurrency (N goroutines calling at once)

### Manual Testing Steps
1. Create a tiny script (or example) calling `oidc.Client.DiscoverProvider` for `https://accounts.google.com`.
2. Inspect parsed metadata (issuer, jwks_uri, response types).
3. Call `RemoteKeySet.Key(ctx, kid)` using a `kid` present in the returned JWKS.
4. Enable slog logger and ensure logs are structured and non-sensitive.

## Performance Considerations

- Use `singleflight.Group` for fetch de-duplication to prevent stampedes under load.
- SWR avoids tail latency spikes by serving cached values while refreshing.
- Limit response body reads in error paths to bound memory use.

## Migration Notes

N/A (greenfield library).

## References

- Original ticket: `thoughts/tickets/feature_oidc_discovery.md`
- Research: `thoughts/research/2026-02-22_oidc_discovery_implementation.md`
- OIDC Discovery 1.0: `https://openid.net/specs/openid-connect-discovery-1_0.html`
- RFC 8414: `https://www.rfc-editor.org/rfc/rfc8414`
