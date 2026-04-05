# Codebase Simplification Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce incidental complexity across `rp`, `metadata`, `jwks`, and `httputil` without changing public behavior, by collapsing duplicated flows and making core control paths easier to read and test.

**Architecture:** Start with the lowest-risk shared simplifications, then move upward into `jwks` and `rp` where the complexity is concentrated. Prefer small private helpers over new abstractions, keep all public APIs stable, and lock in behavior with targeted tests before and after each refactor.

**Tech Stack:** Go, `go test`, `gofumpt`, standard library HTTP tests, existing package-local test suites in `rp`, `metadata`, `jwks`, and `httputil`

---

### Task 1: Consolidate repeated JSON fetch plumbing

**Files:**
- Modify: `httputil/fetchjson.go`
- Modify: `metadata/http_fetch.go`
- Modify: `jwks/http_fetch.go`
- Modify: `jwks/http_fetch_test.go`
- Modify: `metadata/discovery_integration_test.go`
- Test: `httputil/fetchjson.go`

**Step 1: Lock in current fetch behavior with focused tests**

Add or extend tests so the common fetch contract is explicit:

```go
func TestFetchJSON_NotModifiedPreservesMetadata(t *testing.T) {}
func TestFetchJSON_Non200ReturnsBodyPreview(t *testing.T) {}
func TestFetchJSON_WrapsDecodeErrors(t *testing.T) {}
```

The important assertions are:

- `If-None-Match` is still sent when `priorETag` is set
- `304` still returns `NotModified == true`
- non-`200` responses still expose trimmed preview text
- decoder failures still unwrap as `*DecodeError`

**Step 2: Run the tests before refactoring**

Run: `go test ./httputil ./metadata ./jwks -run 'TestFetchJSON|TestDiscovery|TestFetchJWKS' -count=1`
Expected: PASS

**Step 3: Introduce one private result-mapping helper per caller package**

Keep `httputil.FetchJSON` as the shared primitive. In `metadata/http_fetch.go` and `jwks/http_fetch.go`, extract the repeated result-copying and status handling into one package-local helper each, not a new cross-package framework.

Target shape:

```go
func mapFetchResult(result httputil.FetchJSONResult) rawFetchResult {
    return rawFetchResult{
        notModified: result.NotModified,
        etag:        result.ETag,
        freshUntil:  result.FreshUntil,
        fetchedAt:   result.FetchedAt,
    }
}
```

In `jwks/http_fetch.go`, keep package-specific error wrapping in place, but stop manually copying the same metadata fields in-line.

**Step 4: Remove duplicated request/response boilerplate**

Refactor both call sites so each file reads as:

1. build request
2. call `httputil.FetchJSON`
3. translate package-specific decode/status errors
4. return package-specific result

Do not move JSON decoding into reflection or generics; the simplification goal is fewer branches and less repeated assignment, not more abstraction.

**Step 5: Run package tests**

Run: `go test ./httputil ./metadata ./jwks -count=1`
Expected: PASS

**Step 6: Commit**

```bash
git add httputil/fetchjson.go metadata/http_fetch.go jwks/http_fetch.go jwks/http_fetch_test.go metadata/discovery_integration_test.go
git commit -m "refactor: simplify shared json fetch plumbing"
```

**Expected payoff:** Small implementation risk, immediate readability gain in two packages, and a better base for later `metadata` and `jwks` cleanup.

### Task 2: Simplify metadata discovery configuration

**Files:**
- Modify: `metadata/discovery.go`
- Modify: `metadata/discovery_refresh.go`
- Modify: `metadata/cache.go`
- Modify: `metadata/discovery_integration_test.go`
- Modify: `metadata/metadata_test.go`
- Test: `metadata/discovery.go`

**Step 1: Add regression tests around both discovery modes**

Add or extend tests for the two public entry points:

```go
func TestDiscoverProvider_UsesCachedFreshEntry(t *testing.T) {}
func TestDiscoverAuthorizationServer_UsesCachedFreshEntry(t *testing.T) {}
func TestDiscoverProvider_RefreshesOnConformanceMode(t *testing.T) {}
```

These tests should prove that both provider and authorization-server discovery still:

- validate issuer first
- use distinct cache prefixes
- return typed values
- preserve stale/background refresh behavior

**Step 2: Run targeted metadata tests**

Run: `go test ./metadata -run 'TestDiscover|TestDiscovery' -count=1`
Expected: PASS

**Step 3: Replace `interface{}`-heavy config with explicit typed helpers**

The current `discoveryConfig` shape in `metadata/discovery.go` carries several function fields using `interface{}` and repeated type assertions. Replace that with one of these minimal designs:

Option A, preferred: keep `discover` private but split the two typed paths into small wrappers:

```go
func (c *Client) discoverProvider(ctx context.Context, issuer string) (Provider, error)
func (c *Client) discoverAuthorizationServer(ctx context.Context, issuer string) (AuthorizationServer, error)
```

Both should share only the common cache/read/refresh flow, while the typed conversion stays local and compile-time checked.

Option B, acceptable: retain a config struct, but remove `interface{}` return values from `metadataEntry`, `validate`, and `newEntry` by making the shared helper narrower and the typed work explicit in the public functions.

Do not introduce type parameters unless the final code is clearly shorter than two dedicated helpers.

**Step 4: Keep the cache flow identical while flattening control flow**

The final structure should still support:

- fresh cache hit returns immediately
- conformance mode forces blocking refresh
- stale cache hit serves cached value and launches background refresh
- cache miss performs blocking refresh

Express that flow once, with typed extraction done outside the common path.

**Step 5: Run metadata tests**

Run: `go test ./metadata -count=1`
Expected: PASS

**Step 6: Commit**

```bash
git add metadata/discovery.go metadata/discovery_refresh.go metadata/cache.go metadata/discovery_integration_test.go metadata/metadata_test.go
git commit -m "refactor: simplify metadata discovery configuration"
```

**Expected payoff:** Medium payoff. Removes runtime casts from a core package path, makes discovery easier to reason about, and reduces the chance of subtle type mismatches in future edits.

### Task 3: Collapse JWKS cache and refresh branching

**Files:**
- Modify: `jwks/remote_keyset.go`
- Modify: `jwks/remote_keyset_test.go`
- Modify: `jwks/remote_keyset_integration_test.go`
- Test: `jwks/remote_keyset.go`

**Step 1: Add tests that pin down the current edge cases**

Add or extend tests for these specific branches:

```go
func TestRemoteKeySetKey_ReturnsCachedKeyWithoutRefresh(t *testing.T) {}
func TestRemoteKeySetKey_RefreshesUnknownKidOncePerMinGap(t *testing.T) {}
func TestRemoteKeySetKey_ReturnsKeyNotFoundWhenRefreshFailsWithCachedKeys(t *testing.T) {}
```

Use the existing fake HTTP servers and cache-backed tests. Verify both the returned error type and the number of refresh attempts.

**Step 2: Run JWKS tests before refactoring**

Run: `go test ./jwks -run 'TestRemoteKeySet' -count=1`
Expected: PASS

**Step 3: Extract one cache-key helper and one entry-loading helper**

In `jwks/remote_keyset.go`, introduce minimal private helpers such as:

```go
func (r *RemoteKeySet) cacheKey() string {
    return cacheKeyPrefix + r.jwksURL
}

func (r *RemoteKeySet) cachedEntry() (*CacheEntry, bool) {
    entry, ok := r.cache.Get(r.cacheKey())
    return entry, ok && entry != nil
}
```

Then rewrite `Keys` and `Key` so they stop rebuilding the cache key and stop repeating cache lookups in-line.

**Step 4: Isolate the “refresh for unknown kid” policy**

Move the `lastRefreshAttempt` mutation and min-refresh-gap check into a helper with a narrow contract:

```go
func (r *RemoteKeySet) markUnknownKidRefresh(entry *CacheEntry) bool
```

Return `false` when the caller should not refresh yet. This lets `Key` read as:

1. load keys
2. try `findKey`
3. decide whether a refresh is allowed
4. refresh once
5. try `findKey` again
6. return `KeyNotFoundError`

**Step 5: Keep stale-key fallback behavior unchanged**

When refresh fails after cached keys already existed, keep returning `KeyNotFoundError` instead of surfacing the transport error directly. That behavior is subtle and should remain intact.

**Step 6: Run JWKS tests**

Run: `go test ./jwks -count=1`
Expected: PASS

**Step 7: Commit**

```bash
git add jwks/remote_keyset.go jwks/remote_keyset_test.go jwks/remote_keyset_integration_test.go
git commit -m "refactor: simplify jwks cache refresh flow"
```

**Expected payoff:** Medium-to-high payoff. `RemoteKeySet.Key` becomes much easier to audit, which matters because the current logic mixes cache reads, mutation, refresh rate-limiting, and fallback error policy in one function.

### Task 4: Break `rp.New` into focused initialization stages

**Files:**
- Modify: `rp/rp.go`
- Modify: `rp/rp_test.go`
- Modify: `rp/discovery_test.go`
- Modify: `rp/auth_method_test.go`
- Test: `rp/rp.go`

**Step 1: Add constructor-focused tests for initialization stages**

Add tests that cover the major branches in `rp.New`:

```go
func TestNew_InitializesDefaultNonceStore(t *testing.T) {}
func TestNew_CreatesMetadataClientWhenMissing(t *testing.T) {}
func TestNew_UsesProvidedProviderWithoutDiscovery(t *testing.T) {}
func TestNew_DefaultsAllowUnsecuredIDTokensOutsideFAPI(t *testing.T) {}
```

Use existing table-driven style where possible.

**Step 2: Run targeted RP constructor tests**

Run: `go test ./rp -run 'TestNew_' -count=1`
Expected: PASS

**Step 3: Extract small private initialization helpers**

Refactor `rp.New` in `rp/rp.go` into a straight-line constructor plus a few narrow helpers:

```go
func newRPWithDefaults(issuer, clientID, clientSecret, redirectURI string) *RP
func (r *RP) initNonceStore()
func (r *RP) initMetadataClient()
func (r *RP) initProvider(ctx context.Context) error
func (r *RP) initStateStore()
func (r *RP) finalizeSecurityDefaults()
```

The main function should read as:

1. normalize inputs and defaults
2. apply options
3. initialize internal dependencies
4. validate config
5. discover/load provider
6. resolve auth method and endpoint readiness
7. finalize optional defaults

Keep all helpers private and in `rp/rp.go` unless the file becomes unwieldy.

**Step 4: Keep behavior identical, including ordering-sensitive behavior**

Do not change when these actions happen:

- option application before validation
- metadata client setup before discovery
- auth-method resolution after provider is present
- state store defaulting after validation

That ordering is part of the constructor contract.

**Step 5: Run RP tests**

Run: `go test ./rp -count=1`
Expected: PASS

**Step 6: Commit**

```bash
git add rp/rp.go rp/rp_test.go rp/discovery_test.go rp/auth_method_test.go
git commit -m "refactor: stage rp constructor initialization"
```

**Expected payoff:** High payoff for maintainability. The constructor is central to the package, and flattening it into named stages will make future option and provider changes safer.

### Task 5: De-duplicate authorization and callback flow assembly in `rp`

**Files:**
- Modify: `rp/authrequest.go`
- Modify: `rp/callback.go`
- Modify: `rp/par.go`
- Modify: `rp/authrequest_test.go`
- Modify: `rp/par_test.go`
- Modify: `rp/callback_test.go`
- Test: `rp/authrequest.go`

**Step 1: Add regression tests for PAR and non-PAR URL assembly**

Extend `rp/authrequest_test.go` and `rp/par_test.go` to prove that both flows still:

- save state once
- preserve `request_uri` behavior for PAR
- preserve direct query parameters for non-PAR
- keep `client_id` handling unchanged for signed PAR requests
- preserve configured `response_mode` and `authorization_details`

Useful test names:

```go
func TestAuthorizationURL_SavesCorrelationForPARAndNonPAR(t *testing.T) {}
func TestAuthorizationURL_PARBuildsRequestURIRedirect(t *testing.T) {}
func TestAuthorizationURL_NonPARBuildsQueryParametersDirectly(t *testing.T) {}
```

In `rp/callback_test.go`, add coverage for issuer checks and provider-loading branches if not already present.

**Step 2: Run targeted RP flow tests before editing**

Run: `go test ./rp -run 'TestAuthorizationURL|TestHandleCallback' -count=1`
Expected: PASS

**Step 3: Extract shared authorization URL assembly helpers**

In `rp/authrequest.go`, extract private helpers for the duplicated end-of-flow work:

```go
func (r *RP) saveAuthorizationCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state, nonce, verifier string, par *parResponse) error
func buildAuthorizationRedirect(endpoint string, params url.Values) (string, error)
```

For the PAR case, pass only `client_id` and `request_uri` into `buildAuthorizationRedirect`. For the non-PAR case, pass the original authorization params.

Do not create a new type for every intermediate value; a single `*parResponse` argument is enough.

**Step 4: Extract callback validation steps into sequential helpers**

In `rp/callback.go`, split the current long method into narrow private stages such as:

```go
func (r *RP) parseAuthorizationResponse(ctx context.Context, params callbackParams) (code, state, iss string, err error)
func (r *RP) consumeCallbackState(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) (CallbackCorrelation, error)
func (r *RP) providerForCallback(ctx context.Context, issuer string) (metadata.Provider, error)
```

The top-level `HandleCallback` should read as a linear pipeline:

1. validate request presence
2. parse response/JARM
3. require state and code
4. consume state
5. validate issuer expectations
6. load provider and negotiate auth method
7. exchange token
8. return OAuth-only result or continue to OIDC validation
9. validate ID token and userinfo

**Step 5: Keep public behavior and errors stable**

Preserve the existing sentinel errors and message fragments where tests depend on them:

- `ErrInvalidState`
- `ErrMissingCode`
- `ErrTokenExchangeFailed`
- `ErrIDTokenValidationFailed`
- `ErrUserInfoValidationFailed`

This refactor is about simplifying structure, not changing caller-facing semantics.

**Step 6: Run RP tests**

Run: `go test ./rp -count=1`
Expected: PASS

**Step 7: Run full repository verification**

Run: `gofumpt ./...`
Expected: no output

Run: `go test ./...`
Expected: PASS

**Step 8: Commit**

```bash
git add rp/authrequest.go rp/callback.go rp/par.go rp/authrequest_test.go rp/par_test.go rp/callback_test.go
git commit -m "refactor: simplify rp authorization and callback flows"
```

**Expected payoff:** Highest payoff. These are the most visible and behaviorally dense code paths in the repository, and simplifying them lowers the cost of future PAR, JARM, FAPI, and callback changes.

### Task 6: Final verification and follow-up cleanup

**Files:**
- Modify: `docs/plans/2026-04-05-codebase-simplification-refactor.md`
- Test: whole repository

**Step 1: Run verification from a clean understanding of the branch**

Run: `git status --short`
Expected: only intended changes for this plan

**Step 2: Run the full validation suite**

Run: `gofumpt ./...`
Expected: no output

Run: `go vet ./...`
Expected: PASS

Run: `go test ./...`
Expected: PASS

**Step 3: Record actual payoff and any deferred work**

Update this plan file with a short “Execution Notes” section summarizing:

- helpers added
- code removed or branches collapsed
- any simplification that was intentionally deferred because it increased abstraction instead of reducing it

**Step 4: Commit**

```bash
git add docs/plans/2026-04-05-codebase-simplification-refactor.md
git commit -m "docs: record codebase simplification execution notes"
```

**Expected payoff:** Ensures the branch finishes with evidence, not assumptions, and leaves a written record of what simplifications were worth keeping.

## Design Notes

1. Prefer small private helpers over new exported types.
2. Avoid generics unless they remove more code than they add. In this codebase, the `metadata` discovery path is more likely to get simpler with explicit typed helpers than with parameterized abstractions.
3. Preserve error wrapping and sentinel error behavior exactly where current tests exercise it.
4. Keep background refresh and stale-cache behavior unchanged in `metadata` and `jwks`; those policies are subtle and valuable.
5. Refactor in the listed order. Shared fetch cleanup first reduces noise for later edits; `rp` flow cleanup should happen last because it touches the most behavior.

## Expected Payoff Summary

1. `httputil` / fetch wrappers: low risk, low-to-medium payoff, quick readability win.
2. `metadata` discovery: medium risk, medium payoff, removes runtime casts and indirection.
3. `jwks` remote keyset: medium risk, medium-to-high payoff, improves auditability of cache/refresh policy.
4. `rp.New`: low-to-medium risk, high payoff, makes the package entry point easier to maintain.
5. `rp` auth/callback flows: medium risk, highest payoff, reduces duplication in the most change-prone code.

## Rough Effort Estimate

1. Task 1: 30-45 minutes
2. Task 2: 45-75 minutes
3. Task 3: 45-60 minutes
4. Task 4: 30-45 minutes
5. Task 5: 60-90 minutes
6. Task 6: 15-20 minutes

Total expected effort: roughly half a day to one focused day, depending on how many tests need to be tightened while preserving current behavior.
