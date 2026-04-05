# Codebase Simplification Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce code duplication across four targets: token-request/DPoP retry logic, discovery pipeline, metadata validation, and JOSE algorithm mapping.

**Architecture:** Extract shared helpers that each flow delegates to, keeping per-flow uniqueness in the calling code. No behavioral changes — all existing tests must continue to pass without modification.

**Tech Stack:** Go, `go test`, `gofumpt`, `go vet`, `github.com/google/go-cmp/cmp`

---

## Target 1: Extract shared token-request helper with DPoP retry

**Problem:** `rp/token_exchange.go:60-155`, `rp/client_credentials.go:285-387`, and `rp/userinfo.go:16-95` all repeat the same pattern:
1. Build an HTTP request
2. Attach DPoP proof with cached nonce
3. Execute via `doJSONStatus`
4. Extract and store DPoP nonce from response
5. Detect `use_dpop_nonce` challenge
6. Retry once with server nonce

This is ~100 lines of near-identical control flow repeated three times.

### Task 1.1: Define the `doRequestWithDPoPRetry` helper

**Files:**
- Create helper in: `rp/dpop.go` (alongside existing DPoP logic)
- No test changes needed initially

**Design:**

```go
// dpopRequestConfig parameterizes a single HTTP request with optional DPoP.
type dpopRequestConfig struct {
    // buildRequest constructs the initial HTTP request (without DPoP headers).
    buildRequest func() (*http.Request, error)
    // attachDPoP attaches a DPoP proof to the request. May be nil if DPoP is not used.
    attachDPoP func(req *http.Request, nonce string) error
    // handleResponse is called for each successful (2xx) response.
    // Returns a jsonDecodeError sentinel on decode failure.
    handleResponse func(body io.Reader) error
    // storeNonce stores the DPoP nonce from a successful response.
    storeNonce func(nonce string)
    // successStatus is the expected HTTP status code (http.StatusOK for most flows).
    successStatus int
}

// doRequestWithDPoPRetry executes an HTTP request with optional DPoP nonce retry.
// On a use_dpop_nonce challenge, it rebuilds the request with the server-provided
// nonce and retries exactly once.
func (r *RP) doRequestWithDPoPRetry(ctx context.Context, cfg dpopRequestConfig) (*http.Response, error)
```

The helper:
1. Calls `cfg.buildRequest()` to get the initial request
2. If `cfg.attachDPoP != nil`, calls `cfg.attachDPoP(req, r.cachedDPoPNonce)` using the cached nonce
3. Calls `doJSONStatus(req, r.httpClient, cfg.successStatus, cfg.handleResponse)`
4. If response is available, calls `cfg.storeNonce` with any new `DPoP-Nonce` header
5. If `isUseDPoPNonce(resp)` is true, builds a fresh request, attaches proof with the server nonce, retries once
6. Returns the response and any error

**Verification:** `go build ./...` must compile. Existing tests unchanged.

### Task 1.2: Refactor `exchangeTokenOnce` to use the helper

**Files:**
- Modify: `rp/token_exchange.go`

**Changes:**
- Replace the DPoP attach / execute / nonce-store / retry block in `exchangeTokenOnce` (~lines 96-151) with a call to `doRequestWithDPoPRetry`.
- The `buildRequest` closure captures `form`, `method`, `tokenEndpoint`, and `ctx`.
- The `handleResponse` closure calls `parseTokenResponse`.
- Auth-method fallback (POST→Basic) stays in the caller `exchangeToken` — that logic is unique to the browser flow.

**Verification:** `go test ./rp/` passes.

### Task 1.3: Refactor `ClientCredentials.requestToken` to use the helper

**Files:**
- Modify: `rp/client_credentials.go`

**Changes:**
- Replace the DPoP attach / execute / nonce-store / retry block (~lines 319-375) with a call to `doRequestWithDPoPRetry`.
- The `buildRequest` closure captures `form`, `method`, and `ctx`.
- The `handleResponse` closure calls `parseTokenResponse`.
- Post-parse validation (`AccessToken != ""`) stays after the helper returns — unique to this flow.

**Verification:** `go test ./rp/` passes.

### Task 1.4: Refactor `fetchUserInfo` to use the helper

**Files:**
- Modify: `rp/userinfo.go`

**Changes:**
- Replace the DPoP attach / execute / nonce-store / retry block (~lines 22-75) with a call to `doRequestWithDPoPRetry`.
- The `buildRequest` closure calls `buildUserInfoRequest`.
- The `handleResponse` closure does `json.NewDecoder(body).Decode(&payload)`.
- Subject validation and distributed claims resolution stay after the helper returns.

**Verification:** `go test ./rp/` passes. `go test ./...` passes.

---

## Target 2: Collapse duplicated discovery pipeline

**Problem:** `DiscoverProvider` and `DiscoverAuthorizationServer` in `metadata/discovery.go:15-146` are structurally identical — same cache lookup, same SWR logic, same refresh delegation — differing only in cache key prefix, kind, well-known URL, fetch function, validate function, and cache field accessor. Similarly, `refreshProvider` and `refreshAuthorizationServer` (~lines 80-146) are thin wrappers that inject those differences into `refreshDiscovery` via `discoveryRefreshOptions`.

The public methods are 30 lines each with ~25 lines of identical control flow.

### Task 2.1: Introduce a typed discovery config struct

**Files:**
- Modify: `metadata/discovery.go`

**Design:**

```go
type discoveryConfig[T any] struct {
    cachePrefix    string
    cacheKind      cacheEntryKind
    wellKnown      func(issuer string) string
    fetch          func(ctx context.Context, c *Client, url, etag string) (T, error)
    validate       func(ctx context.Context, c *Client, issuer string, md T) error
    newEntry       func(md T, etag string, freshUntil, fetchedAt time.Time) *CacheEntry
    entryMetadata  func(entry *CacheEntry) T
}
```

Wait — Go generics would require the cache entry to be parameterized too, which touches too many files. Instead, keep it simple with function fields (like `discoveryRefreshOptions` already does):

```go
type discoveryConfig struct {
    cachePrefix   string
    cacheKind     cacheEntryKind
    wellKnown     func(issuer string) string
    fetch         func(ctx context.Context, rawURL, priorETag string) (any, error)
    validate      func(issuer string, md any) error
    newEntry      func(md any, etag string, freshUntil, fetchedAt time.Time) *CacheEntry
    entryMetadata func(entry *CacheEntry) any
}
```

This is essentially a public-method-level version of `discoveryRefreshOptions` in `discovery_refresh.go`.

### Task 2.2: Extract a generic `discover` method

**Files:**
- Modify: `metadata/discovery.go`

**Changes:**
- Add a private method `func (c *Client) discover(ctx context.Context, issuer string, cfg discoveryConfig) (any, error)` that contains the current SWR/cache logic (lines 15-45 of the current `DiscoverProvider`).
- Rewrite `DiscoverProvider` to call `c.discover(ctx, issuer, providerDiscoveryConfig)` and type-assert the result to `Provider`.
- Rewrite `DiscoverAuthorizationServer` to call `c.discover(ctx, issuer, asDiscoveryConfig)` and type-assert the result to `AuthorizationServer`.
- Define `providerDiscoveryConfig` and `asDiscoveryConfig` as package-level vars.

The `refreshProvider` / `refreshAuthorizationServer` methods (lines 80-146) are then collapsible: each becomes a single call to `refreshDiscovery` with the appropriate options derived from the same `discoveryConfig`.

**Result:** ~60 lines of duplicated control flow removed. Each public method becomes ~8 lines.

**Verification:** `go test ./metadata/` passes.

### Task 2.3: Merge the two fetch result types in `http_fetch.go`

**Files:**
- Modify: `metadata/http_fetch.go`

**Changes:**
- `providerFetchResult` and `authorizationServerFetchResult` (lines 15-29) are identical structs with the same three fields: `metadata`, `notModified`, `etag`.
- Replace both with a single `fetchResult[T]` generic struct, or more simply, a single `discoveryFetchResult` with `metadata any`.
- Simplify `fetchProvider` and `fetchAuthorizationServer` into a single private helper that `fetchProvider`/`fetchAuthorizationServer` delegate to.

**Verification:** `go test ./metadata/` passes. `go test ./...` passes.

---

## Target 3: Deduplicate metadata validation field checks

**Problem:** `validateProvider` (lines 100-142) and `validateAuthorizationServer` (lines 144-164) in `metadata/validate.go` share:
- Issuer non-empty check
- Issuer match check via `issuerMatches`
- `response_types_supported` non-empty check
- `token_endpoint` HTTPS URL check

The only difference is that `validateProvider` enforces `authorization_endpoint`, `jwks_uri`, `subject_types_supported`, and `id_token_signing_alg_values_supported` as required, while `validateAuthorizationServer` treats the first two as optional and doesn't check the last two at all.

### Task 3.1: Extract shared validation helpers

**Files:**
- Modify: `metadata/validate.go`

**New helpers:**

```go
type fieldCheck struct {
    name     string
    value    string
    required bool
}

func validateIssuer(issuer, expected string) error { ... }
func validateRequiredSlice(name string, slice []string) error { ... }
func validateFields(issuer string, checks []fieldCheck) error { ... }
```

### Task 3.2: Rewrite `validateAuthorizationServer` using helpers

**Files:**
- Modify: `metadata/validate.go`

**Changes:**
- Replace the inline checks (lines 145-162) with:
  ```go
  func (c *Client) validateAuthorizationServer(expectedIssuer string, server AuthorizationServer) error {
      if err := validateIssuer(server.Issuer, expectedIssuer); err != nil {
          return err
      }
      if err := validateIssuerMatch(expectedIssuer, server.Issuer, c.issuerTrailingSlashTolerance); err != nil {
          return err
      }
      if err := validateRequiredSlice("response_types_supported", server.ResponseTypesSupported); err != nil {
          return err
      }
      return validateFields(expectedIssuer, []fieldCheck{
          {"authorization_endpoint", server.AuthorizationEndpoint, false},
          {"jwks_uri", server.JWKSURI, false},
          {"token_endpoint", server.TokenEndpoint, false},
      })
  }
  ```

### Task 3.3: Rewrite `validateProvider` using helpers

**Files:**
- Modify: `metadata/validate.go`

**Changes:**
- Replace the inline checks (lines 100-139) with:
  ```go
  func (c *Client) validateProvider(expectedIssuer string, provider Provider) error {
      if err := validateIssuer(provider.Issuer, expectedIssuer); err != nil {
          return err
      }
      if err := validateIssuerMatch(expectedIssuer, provider.Issuer, c.issuerTrailingSlashTolerance); err != nil {
          return err
      }
      // OIDC-specific required fields
      for _, check := range []struct{ name, value string }{
          {"authorization_endpoint", provider.AuthorizationEndpoint},
          {"jwks_uri", provider.JWKSURI},
      } {
          if err := validateRequired(check.name, check.value); err != nil {
              return err
          }
      }
      for _, check := range []struct{ name string; values []string }{
          {"response_types_supported", provider.ResponseTypesSupported},
          {"subject_types_supported", provider.SubjectTypesSupported},
          {"id_token_signing_alg_values_supported", provider.IDTokenSigningAlgValuesSupported},
      } {
          if err := validateRequiredSlice(check.name, check.values); err != nil {
              return err
          }
      }
      return validateFields(expectedIssuer, []fieldCheck{
          {"token_endpoint", provider.TokenEndpoint, false},
          {"userinfo_endpoint", provider.UserinfoEndpoint, false},
      })
  }
  ```

**Verification:** `go test ./metadata/` passes. Existing test cases cover all validation branches. `go test ./...` passes.

---

## Target 4: Consolidate JOSE algorithm mapping

**Problem:** Three separate switch blocks map string algorithm names to `jose.SignatureAlgorithm`:
- `rp/request_object.go:178-192` — `signingAlgorithm()` — 5 algs, returns `""` on unknown
- `rp/dpop.go:133-155` — `algToJose()` — 9 algs, returns `""` on unknown
- `rp/client_credentials.go:431-454` — inline in `signClientAssertion()` — 9 algs, returns error on unknown

All three map the same string→`jose.SignatureAlgorithm` pairs, just with different coverage and error handling.

### Task 4.1: Create a shared `signatureAlgorithm` function

**Files:**
- Create: `rp/jose.go` (or add to `rp/dpop.go` which already has the most complete mapping)

**Design:**

```go
// signatureAlgorithm maps a JWS algorithm name string to a jose.SignatureAlgorithm.
// Returns ("", nil) for unrecognized algorithms.
func signatureAlgorithm(alg string) jose.SignatureAlgorithm {
    switch alg {
    case "PS256":
        return jose.PS256
    case "PS384":
        return jose.PS384
    case "PS512":
        return jose.PS512
    case "RS256":
        return jose.RS256
    case "RS384":
        return jose.RS384
    case "RS512":
        return jose.RS512
    case "ES256":
        return jose.ES256
    case "ES384":
        return jose.ES384
    case "ES512":
        return jose.ES512
    default:
        return ""
    }
}
```

This covers the union of all three current mappings (9 algorithms).

### Task 4.2: Replace `signingAlgorithm` in `request_object.go`

**Files:**
- Modify: `rp/request_object.go`

**Changes:**
- Delete the local `signingAlgorithm` function (lines 178-192).
- Replace call at line ~95-99 with the shared `signatureAlgorithm`.
- The caller already handles `""` return by checking `joseAlg == ""` and returning an error, so behavior is preserved.
- The extra algorithms (PS512, RS384, RS512, ES512) that weren't in the original mapping are harmless — they're valid JOSE algorithms that `jose.NewSigner` accepts.

**Verification:** `go test ./rp/` passes.

### Task 4.3: Replace `algToJose` in `dpop.go`

**Files:**
- Modify: `rp/dpop.go`

**Changes:**
- Delete the local `algToJose` function (lines 133-155).
- Replace call at line ~71-75 with the shared `signatureAlgorithm`.

**Verification:** `go test ./rp/` passes.

### Task 4.4: Replace inline switch in `client_credentials.go`

**Files:**
- Modify: `rp/client_credentials.go`

**Changes:**
- Replace the switch block in `signClientAssertion` (lines 431-454) with a call to `signatureAlgorithm`.
- Keep the error return for unknown algorithms (check `joseAlg == ""` and return the existing error message).

**Verification:** `go test ./rp/` passes. `go test ./...` passes.

---

## Execution Order

Execute targets in this order to minimize merge conflicts and maximize test coverage at each step:

1. **Target 4** (JOSE mapping) — Smallest change, self-contained, no cross-file dependencies beyond adding one function.
2. **Target 3** (Validation) — Self-contained within `metadata/validate.go`, no external callers change.
3. **Target 2** (Discovery pipeline) — Moderate complexity, contained within `metadata/`.
4. **Target 1** (Token-request/DPoP retry) — Largest change, touches three files in `rp/`, most risk.

After each target: run `go build ./...`, `go test ./...`, `gofmt`, `go vet`.

## Estimated Impact

| Target | Lines Removed | Lines Added | Net Reduction |
|--------|--------------|-------------|---------------|
| 1. Token/DPoP retry | ~200 | ~60 | ~140 |
| 2. Discovery pipeline | ~80 | ~40 | ~40 |
| 3. Validation | ~40 | ~30 | ~10 |
| 4. JOSE mapping | ~45 | ~20 | ~25 |
| **Total** | **~365** | **~150** | **~215** |
