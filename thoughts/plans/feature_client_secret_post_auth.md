# FEATURE-001: client_secret_post Token Endpoint Client Authentication Implementation Plan

## Overview

Add OAuth2/OIDC token endpoint client authentication support for `client_secret_post` alongside the existing `client_secret_basic`, including constructor-time negotiation from discovery metadata, explicit override via options, and fallback behavior when metadata does not declare supported methods.

This plan is explicitly test-driven: each implementation phase starts by adding new tests that fail (compile-time or runtime), then implementing the minimum code to make them pass.

## Current State Analysis

- Token exchange always uses HTTP Basic auth (`client_secret_basic`) via `req.SetBasicAuth(...)` in `rp/token_exchange.go:26`.
- RP construction is local-only and does not accept `context.Context`, so it cannot perform discovery at construction time (`rp/rp.go:38-73`).
- Provider discovery exists and already parses `token_endpoint_auth_methods_supported` into `oidc.ProviderMetadata.AuthorizationServerMetadata.TokenEndpointAuthMethodsSupported` (`oidc/metadata_oauth_as.go:17`, embedded via `oidc/metadata_provider.go:7-8`).
- RP currently discovers provider metadata during auth start and callback (`rp/authrequest.go:14`, `rp/callback.go:29`).

## Desired End State

- `rp.New` accepts `context.Context` and performs provider discovery during construction (unless provider discovery is injected).
- RP supports two auth methods for the token endpoint:
  - `client_secret_basic` (existing)
  - `client_secret_post` (new)
- RP supports:
  - `WithAuthMethod(AuthMethod)` explicit override
  - auto-negotiation from provider discovery metadata with priority: POST over Basic
  - typed error when a chosen method is not supported by provider metadata
  - fallback behavior when metadata does not declare supported methods: try POST first, then Basic on failure; cache the successful method for the RP instance lifetime
- Conformance:
  - Basic RP certification plan still passes (regression)
  - A conformance run verifies token endpoint `client_secret_post` by forcing the suite variant `client_auth_type=client_secret_post`

### Key Discoveries

- RP constructor currently has no `ctx` (`rp/rp.go:38-73`), so construction-time discovery requires a signature change.
- Discovery validation in `oidc` does not require `token_endpoint` to be present (`oidc/validate.go:134-136`), but our token exchange path requires it; the RP already depends on it during callback.
- Conformance suite variant for token endpoint auth is `client_auth_type` with value `client_secret_post` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/variant/OIDCCClientAuthType.java:5-20`).
- The Basic RP certification plan forces `client_secret_basic` regardless of variant selection (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/openid/client/OIDCCClientBasicTestPlan.java:27-32`, `.../OIDCCClientTestClientSecretBasic.java:43-47`).

## What We're NOT Doing

- Implementing `none` (public client) token endpoint auth.
- Implementing `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, etc. (design remains extensible).
- Extending auth method selection to revocation/introspection endpoints.
- Persisting the resolved auth method across RP instances.

## Implementation Approach

- Keep the public surface small and typed: add `AuthMethod` constants and a single `WithAuthMethod` option.
- Resolve/validate auth method at construction time when provider metadata declares supported methods.
- When provider metadata does not declare supported methods, allow runtime fallback on the first token exchange, then cache the winner.
- Ensure concurrency-safety for caching (avoid data races if RP methods are used concurrently).
- Make conformance verification explicit and automated via `conformance/harness` (plus manual fallback steps).

## Phase 1: Tests First - Constructor Context + Provider Discovery Injection

### Overview

Introduce tests that define the new constructor behavior (construction-time discovery) and the ability to inject already-fetched provider discovery data.

### Changes Required

#### 1. RP constructor tests
**File**: `rp/rp_test.go` and/or new `rp/new_test.go`
**Changes**:
- Add a failing test that asserts `New(ctx, ...)` performs discovery when `WithProviderDiscovery` is not used.
- Add a failing test that asserts `WithProviderDiscovery(...)` suppresses any HTTP discovery calls.

Test intent sketch:

```go
func TestNew_PerformsDiscoveryByDefault(t *testing.T) {
  // httptest server serves /.well-known/openid-configuration
  // New(ctx, issuer, ...) should call it during construction.
}

func TestNew_WithProviderDiscovery_SkipsDiscoveryHTTP(t *testing.T) {
  // provide provider metadata via option
  // use an http.Client transport that fails if any request happens
  // New(ctx, ...) must succeed without network.
}
```

#### 2. RP constructor signature + provider storage
**File**: `rp/rp.go`
**Changes**:
- Change signature:

```go
func New(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, opts ...Option) (*RP, error)
```

- Add RP fields for provider discovery injection (e.g., `provider oidc.ProviderMetadata` + `providerSet bool`).
- In `New`, after options + validation + `oidcClient` init:
  - If provider not injected: call `r.oidcClient.DiscoverProvider(ctx, r.issuer)` and store the result.
  - If provider injected: use it as-is.

#### 3. New option: WithProviderDiscovery
**File**: `rp/options.go`
**Changes**:
- Add:

```go
func WithProviderDiscovery(provider oidc.ProviderMetadata) Option
```

### Success Criteria

#### Automated Verification
- [x] `go test ./...` passes after implementation.
- [x] New tests fail before implementation and pass after.

#### Manual Verification
- [x] A simple RP instantiation performs discovery during `New(ctx, ...)`.

---

## Phase 2: Tests First - AuthMethod API + Typed Errors + Constructor-Time Negotiation

### Overview

Define and validate the auth method selection API and its interaction with provider metadata.

### Changes Required

#### 1. Auth method tests
**File**: `rp/rp_test.go` and/or new `rp/auth_method_test.go`
**Changes**:
- Add failing tests for:
  - auto-negotiation prefers POST over Basic when provider metadata supports both
  - explicit `WithAuthMethod(AuthMethodPost)` is validated against provider metadata
  - typed error returned when explicit method is unsupported
  - selecting a secret-based method with empty secret fails at construction

#### 2. AuthMethod type + constants
**File**: `rp/auth_method.go` (new) or `rp/rp.go`
**Changes**:

```go
type AuthMethod string

const (
  AuthMethodBasic AuthMethod = "client_secret_basic"
  AuthMethodPost  AuthMethod = "client_secret_post"
)
```

#### 3. WithAuthMethod option
**File**: `rp/options.go`
**Changes**:
- Add `WithAuthMethod(method AuthMethod) Option`.

#### 4. Typed error for unsupported methods
**File**: `rp/errors.go`
**Changes**:
- Add a sentinel error (e.g., `ErrAuthMethodNotSupported`).
- Add `type AuthMethodError struct { Method AuthMethod; Supported []string; Err error }` with `Error()`, `Unwrap()`, and `Is()` modeled after patterns in `oidc/errors.go:16-56` and `jwks/errors.go:15-58`.

#### 5. Resolve method in constructor
**File**: `rp/rp.go`
**Changes**:
- Add RP fields:
  - `authMethod AuthMethod` (user preference; empty means auto)
  - `resolvedAuthMethod AuthMethod` (final method used for requests)
  - `allowMethodFallback bool` (only true when metadata does not declare supported methods)
  - a small mutex to protect these values
- In `New(ctx, ...)`, after provider is available:
  - If provider metadata includes `token_endpoint_auth_methods_supported` (non-empty):
    - if explicit method set: validate membership; else pick preferred method (POST if present else Basic)
    - if neither Basic nor Post supported: return `*AuthMethodError`
    - set `allowMethodFallback=false`
  - If provider metadata omits the field / empty:
    - if explicit method set: accept it (and validate required secret)
    - else default `resolvedAuthMethod=AuthMethodPost` and set `allowMethodFallback=true`.
- Validate `clientSecret` is non-empty when resolved method is Basic or Post.

### Success Criteria

#### Automated Verification
- [x] `go test ./rp/...` passes.
- [x] New auth-method unit tests are red-first and then green.

#### Manual Verification
- [x] Creating an RP with `WithAuthMethod(AuthMethodPost)` yields POST auth on token exchange.
- [x] Creating an RP against a provider that only supports basic fails if forced to post.

---

## Phase 3: Tests First - Token Exchange Request Shape + Fallback + Caching

### Overview

Implement request shaping for POST auth and implement POST->Basic fallback only when metadata does not declare supported methods.

### Changes Required

#### 1. Token exchange tests
**File**: `rp/token_exchange_test.go`
**Changes**:
- Add failing tests for:
  - POST auth: request body contains `client_id` and `client_secret`, and Authorization header is absent
  - Fallback behavior: when `allowMethodFallback=true`, first attempt POST; on 400/401 (or specific error), retry once with Basic and cache Basic for subsequent calls

#### 2. Conditional auth in token exchange
**File**: `rp/token_exchange.go`
**Changes**:
- When `resolvedAuthMethod==AuthMethodPost`: add `client_id` and `client_secret` to form body; do not set Authorization header.
- When `resolvedAuthMethod==AuthMethodBasic`: set Basic auth header; do not add credentials to body.
- When `allowMethodFallback==true` and auto-selected method was POST:
  - If POST attempt fails with an auth-related HTTP status (prefer 400/401 handling based on how errors surface in current code), retry once with Basic.
  - On success, cache the successful method in `resolvedAuthMethod` and set `allowMethodFallback=false`.

### Success Criteria

#### Automated Verification
- [x] `go test ./rp/...` passes.
- [x] New fallback/caching test passes and is deterministic.

#### Manual Verification
- [x] In a local scenario where the provider omits `token_endpoint_auth_methods_supported`, an RP can still complete token exchange via fallback.

---

## Phase 4: Repo-Wide Updates for New Constructor Signature

### Overview

Update all internal call sites and examples to compile and to keep existing tests hermetic.

### Changes Required

#### 1. Update all `rp.New` call sites
**Files**:
- `rp/authrequest_test.go`
- `rp/idtoken_test.go`
- `rp/token_exchange_test.go`
- `cmd/example-rp/main.go`
- any other `rp.New(...)` call sites

**Changes**:
- Pass `context.Background()` (or test contexts) to `rp.New(ctx, ...)`.
- Where tests should not perform discovery network calls, inject metadata via `WithProviderDiscovery(...)`.

### Success Criteria

#### Automated Verification
- [x] `go test ./...` passes.

#### Manual Verification
- [x] `go run ./cmd/example-rp` starts and can initiate login flow.

---

## Phase 5: Conformance Harness Enhancements (TDD) - Force client_auth_type=client_secret_post

### Overview

Extend the local conformance harness to support forcing suite variants so we can run a `client_secret_post` verification plan automatically.

### Changes Required

#### 1. Add failing unit tests for variant override plumbing
**File**: `conformance/harness/*.go` (add tests near `profiles_test.go` or new `variants_test.go`)
**Changes**:
- Add tests that verify:
  - parsing a flag like `-force-variant client_auth_type=client_secret_post` produces the expected override map
  - overrides are merged into the plan variant map used by `CreatePlan(...)`
  - overrides are merged into the per-module variant passed to `CreateTestInstance(...)`

#### 2. Add flags + config fields
**File**: `conformance/harness/harness_test.go` / `conformance/harness/config.go`
**Changes**:
- Add a repeatable flag (or a JSON flag) for forced variants.
- Store parsed variants on `harnessConfig`.

#### 3. Apply forced variants during execution
**File**: `conformance/harness/execute.go`
**Changes**:
- Merge forced variants into:
  - `planVariant` before calling `CreatePlan(...)`
  - `module.Variant` before calling `CreateTestInstance(...)`

### Success Criteria

#### Automated Verification
- [x] `go test ./conformance/harness/...` passes.

#### Manual Verification
- [x] Running the harness with forced variants creates a plan and test instances without suite API errors.

---

## Phase 6: Conformance Suite Verification (Two Runs)

### Overview

Run conformance suite tests locally to (1) ensure we didn’t regress the certification profile, and (2) verify token endpoint `client_secret_post` behavior via suite variants.

### Automated Verification

- Run the certification regression plan (Basic RP):

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-basic-certification-test-plan$'
```

- Run a `client_secret_post` verification run using a broader RP plan but forcing client auth variant:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^oidcc-client-test$' \
  -force-variant='client_auth_type=client_secret_post' \
  -force-variant='response_type=code' \
  -force-variant='response_mode=default'
```

### Manual Verification

- [x] Stack starts:
  - `docker compose -f conformance/docker-compose.yml up -d`
  - Suite UI reachable at `https://suite.test`, RP at `https://rp.test`
- [x] Both runs finish with `failed=false` and artifacts written under `./artifacts/<run-id>/report.json`.

## Deviations from Plan

### Phase 2: AuthMethod API + Typed Errors + Constructor-Time Negotiation
- **Original Plan**: Resolve and cache auth method only during constructor-time negotiation.
- **Actual Implementation**: Kept constructor-time negotiation and additionally re-applied auth-method resolution during callback when freshly discovered provider metadata explicitly declares `token_endpoint_auth_methods_supported`.
- **Reason for Deviation**: Conformance flows reuse the same RP process across modules while provider metadata can vary per test instance; constructor-only resolution could keep a stale cached method (e.g., Basic) and fail `client_secret_post` runs.
- **Impact Assessment**: Preserves constructor behavior while improving correctness for dynamic metadata environments; fallback caching behavior for metadata-omitted providers is unchanged.
- **Date/Time**: 2026-02-24T01:24:00Z

### Phase 6: Conformance Suite Verification (Two Runs)
- **Original Plan**: Run `oidcc-client-test-plan` under `-profile=oidc-rp` using include/module filters and forced variants.
- **Actual Implementation**: Added `oidcc-client-test-plan` to explicit OIDC plan matching in harness profile selection so the requested verification command selects the intended plan.
- **Reason for Deviation**: Existing profile heuristics filtered out `oidcc-client-test-plan`, causing "no plans selected" despite a valid include regex.
- **Impact Assessment**: Improves harness plan selection for OIDC RP verification runs and aligns behavior with documented phase commands.
- **Date/Time**: 2026-02-24T01:24:00Z

## Testing Strategy

### Unit Tests

- RP constructor discovery behavior and `WithProviderDiscovery` (no network).
- Auth method negotiation:
  - provider supports both -> chooses POST
  - provider supports only basic/post -> chooses supported
  - explicit override invalid -> typed error
- Token exchange request shaping:
  - header vs body placement
  - fallback and caching semantics

### Integration Tests

- Local conformance harness variant forcing + suite execution.

### Manual Testing Steps

1. Run `go test ./...`.
2. Run the two conformance commands in Phase 6.

## Performance Considerations

- Constructor-time discovery adds a network call to `New(ctx, ...)` unless `WithProviderDiscovery` is used. Callers can prefetch discovery with a shared `oidc.Client` and inject it to avoid repeated network calls.
- Auth method caching is per-RP-instance and should be guarded by a mutex to avoid races.

## Migration Notes

- `rp.New` signature changes to include `context.Context`. All call sites must be updated.
- Prefer using `WithProviderDiscovery(...)` in tests to keep unit tests hermetic.

## References

- Original ticket: `thoughts/tickets/feature_client_secret_post_auth.md`
- Research: `thoughts/research/2026-02-24_client_secret_post_auth.md`
- Current hardcoded basic auth: `rp/token_exchange.go:26`
- Provider metadata field: `oidc/metadata_oauth_as.go:17`
- Conformance variant enum: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/variant/OIDCCClientAuthType.java:5-20`
