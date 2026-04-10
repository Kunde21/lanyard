# OIDCC Config `request_uri` Hosting Implementation Plan

## Overview

Implement RP-hosted `request_uri` support so OIDCC configuration certification tests using `request_type=request_uri` send an actual `request_uri` parameter instead of embedding the signed request object as `request` by value.

## Current State Analysis

### How it works now

For OIDCC config variants with `request_type=request_uri`:

1. The harness passes `request_type=request_uri` in the runtime config (`conformance/harness/rpruntime.go:233`).
2. The example-rp maps this to `requestMethod=signed_non_repudiation` (`cmd/example-rp/runtime_resolution.go:262-264`).
3. In `AuthorizationURL()`, `shouldUsePAR()` returns false because there is no FAPI profile and PAR is not explicitly required (`rp/par.go:24-29`).
4. Since `requestMethod.isSigned()` is true, the RP signs a request object (`rp/authrequest.go:117-127`).
5. The signed JWT is added as `request=<JWT>` in the authorization redirect query.
6. The conformance suite expects `request_uri=<url>` instead, fails with `FetchRequestUriAndExtractRequestObject`, and marks the test INTERRUPTED.

### Why FAPI `request_uri` works

For FAPI profiles, `runtimeRequiresPAR()` returns true when `request_type=request_uri` and a FAPI profile is set (`cmd/example-rp/runtime_resolution.go:217-221`). PAR returns a `request_uri` from the authorization server, and the authorization redirect contains `client_id` + `request_uri` (`rp/authrequest.go:113`). This flow works because PAR provides the hosted URI.

### Key Discovery

The OIDCC conformance suite expects the RP to self-host the request object at a URL (the classic OIDC `request_uri` pattern). The suite will `GET` that URL to retrieve the signed request object JWT.

### Files involved

- `rp/authrequest.go:116-127` — non-PAR signed request branch (sets `request`, never `request_uri`)
- `rp/request_object.go:34-82` — `buildSignedRequestObject` (works correctly)
- `rp/options.go:351-360` — `WithRequestMethod` option
- `rp/rp.go:50-85` — `requestMethodType` and `isSigned()`
- `cmd/example-rp/runtime_resolution.go:258-266` — maps `request_uri` to `signed_non_repudiation`
- `cmd/example-rp/main.go:33` — route registration
- `conformance/harness/execute.go:812-901` — `buildPlanConfig` (suite config)
- `conformance/harness/rpruntime.go:204-241` — runtime request building

## Desired End State

When the OIDCC conformance variant requires `request_type=request_uri`:

1. The RP creates a signed request object JWT.
2. The RP stores it in a transient in-memory store keyed by a random ID.
3. The RP constructs a `request_uri` URL pointing to a self-hosted endpoint (e.g., `https://rp.localhost/request/{id}`).
4. The authorization redirect contains `request_uri=<url>` instead of `request=<JWT>`.
5. The conformance suite fetches the request object from the hosted URL and proceeds normally.

### Verification

- OIDCC config `request_uri` variants no longer fail with `FetchRequestUriAndExtractRequestObject`.
- The three affected modules (`oidcc-client-test-idtoken-sig-none`, `oidcc-client-test-signing-key-rotation`, `oidcc-client-test-signing-key-rotation-just-before-signing`) progress past interruption.
- Existing `plain_http_request` and `request_object` variants remain unaffected.
- FAPI request handling is not regressed.

## What We're NOT Doing

- Changing how FAPI `request_uri` works (it uses PAR and should remain unchanged).
- Adding `request_uri` support to the core `rp/` library as a general-purpose feature. The request object store and endpoint live in `cmd/example-rp/` for now.
- Supporting persistent or distributed request object storage (in-memory only).
- Registering `request_uris` in suite plan config unless the suite requires it (to be verified during testing).

## Implementation Approach

Add a `RequestURIMode` option to the RP library that, when enabled, calls a callback to store the signed request object and return a hosted URL. The example-rp provides the callback implementation using an in-memory store and a new `/request/{id}` HTTP endpoint.

## Phase 1: Request Object Store & Endpoint

### Overview

Add an in-memory request object store and a `GET /request/{id}` endpoint in `cmd/example-rp/` that serves stored signed request objects as `application/jwt`.

### Changes Required

#### 1. New file: `cmd/example-rp/request_object_store.go`

A thread-safe, TTL-based in-memory store for signed request objects.

```go
type requestObjectStore struct {
    mu    sync.RWMutex
    items map[string]*requestObjectEntry
}

type requestObjectEntry struct {
    jwt       string
    expiresAt time.Time
}

func newRequestObjectStore(ttl time.Duration) *requestObjectStore
func (s *requestObjectStore) Store(jwt string) (id string)
func (s *requestObjectStore) Load(id string) (jwt string, ok bool)
func (s *requestObjectStore) Remove(id string)
func (s *requestObjectStore) StartCleanup(interval time.Duration)
```

- `Store()` generates a random 32-byte ID (base64url), stores the JWT with expiry, and returns the ID.
- `Load()` returns the JWT if it exists and hasn't expired.
- `StartCleanup()` runs a background goroutine that evicts expired entries.
- TTL should be 5 minutes (matching request object `exp` claim).

#### 2. New file: `cmd/example-rp/handle_request_object.go`

HTTP handler that serves stored request objects.

```go
func handleRequestObject(store *requestObjectStore) http.HandlerFunc
```

- Matches `GET /request/{id}` where `{id}` is the base64url ID.
- Looks up the ID in the store.
- Returns the JWT as `application/jwt` with `Cache-Control: no-store`.
- Returns 404 if not found or expired.
- Returns 405 for non-GET methods.

#### 3. Modify: `cmd/example-rp/main.go`

Add the store as a package-level variable and register the new route.

```go
var requestObjectStore = newRequestObjectStore(5 * time.Minute)

// In main():
mux.HandleFunc("/request/", handleRequestObject(requestObjectStore))
```

- Initialize cleanup goroutine on startup.
- The route pattern `/request/` matches any path with prefix `/request/`.

### Success Criteria

#### Automated Verification
- [x] `go build ./cmd/example-rp` compiles without errors.
- [x] `go test ./cmd/example-rp/...` passes.
- [x] Unit test: `Store` then `Load` returns the same JWT.
- [x] Unit test: expired entries return `ok=false`.
- [x] Unit test: `GET /request/{valid_id}` returns 200 with `application/jwt`.
- [x] Unit test: `GET /request/{unknown_id}` returns 404.

#### Manual Verification
- [ ] The `/request/` endpoint is accessible when the RP is running.

---

## Phase 2: RP Library Support for `request_uri` Mode

### Overview

Add a `RequestURIMode` option and callback mechanism to `rp/` so `AuthorizationURL()` can emit a `request_uri` parameter instead of embedding `request` by value.

### Changes Required

#### 1. Modify: `rp/options.go`

Add a new option type and functional option.

```go
type RequestURIHandler func(signedJWT string) (requestURI string, err error)

func WithRequestURIMode(handler RequestURIHandler) Option
```

- When set, the RP stores the signed JWT via the handler and uses the returned URL as `request_uri`.
- The handler is responsible for storing the JWT and returning the hosted URL.

#### 2. Modify: `rp/rp.go`

Add a field to the `RP` struct.

```go
type RP struct {
    // ... existing fields ...
    requestURIHandler RequestURIHandler
}
```

#### 3. Modify: `rp/authrequest.go`

Update the non-PAR signed request branch in `AuthorizationURL()`.

Current code at `rp/authrequest.go:116-127`:

```go
redirectParams := params
if r.requestMethod.isSigned() {
    signed, err := r.buildSignedRequestObject(...)
    // ...
    redirectParams.Set("request", signed)
}
```

New logic:

```go
redirectParams := params
if r.requestMethod.isSigned() {
    signed, err := r.buildSignedRequestObject(...)
    if err != nil {
        return "", err
    }

    if r.requestURIHandler != nil {
        uri, err := r.requestURIHandler(signed)
        if err != nil {
            return "", fmt.Errorf("failed to store request object: %w", err)
        }
        redirectParams = url.Values{}
        redirectParams.Set("client_id", r.clientID)
        redirectParams.Set("request_uri", uri)
        redirectParams.Set("scope", params.Get("scope"))
        if v := params.Get("response_mode"); v != "" {
            redirectParams.Set("response_mode", v)
        }
    } else {
        redirectParams = url.Values{}
        for key, values := range params {
            redirectParams[key] = append([]string(nil), values...)
        }
        redirectParams.Set("request", signed)
    }
}
```

When `requestURIHandler` is set:
- The redirect contains only `client_id`, `request_uri`, `scope`, and optionally `response_mode`.
- The suite will fetch the request object from the hosted URL.
- Parameters like `state`, `nonce`, `code_challenge` are inside the signed request object (they already are per `rp/request_object.go:41-56`).

When `requestURIHandler` is nil (existing behavior):
- The redirect contains the full parameter set with `request=<JWT>` — unchanged.

### Success Criteria

#### Automated Verification
- [x] `go build ./rp` compiles without errors.
- [x] `go test ./rp/...` passes — existing tests unchanged.
- [x] New unit test: when `requestURIHandler` is set, `AuthorizationURL` returns a URL containing `request_uri` parameter.
- [x] New unit test: when `requestURIHandler` is set, the `request` parameter is absent from the redirect URL.
- [x] New unit test: when `requestURIHandler` is nil, existing `request` by value behavior is preserved.

#### Manual Verification
- [ ] Inspect the redirect URL in logs to confirm `request_uri` is present.

---

## Phase 3: Wire Runtime Config for `request_uri` Mode

### Overview

When `request_type=request_uri` and PAR is not required (OIDCC config), pass the request object store handler to the RP so it uses `request_uri` mode.

### Changes Required

#### 1. Modify: `cmd/example-rp/runtime_resolution.go`

Add a `requestURI` field to `resolvedRPRequest`.

```go
type resolvedRPRequest struct {
    // ... existing fields ...
    useRequestURI bool
}
```

In `resolveRPRequestFromRuntimeConfig()` and `applyRuntimeConfig()`, set `useRequestURI` when the conditions are met:

```go
resolved.useRequestURI = shouldUseRequestURI(cfg)
```

New helper function:

```go
func shouldUseRequestURI(cfg rpRuntimeConfig) bool {
    if strings.ToLower(strings.TrimSpace(cfg.RequestType)) != "request_uri" {
        return false
    }
    if runtimeRequiresPAR(cfg) {
        return false
    }
    return true
}
```

This ensures `request_uri` mode is only used for OIDCC config variants where PAR is not forced.

#### 2. Modify: `cmd/example-rp/runtime_resolution.go`

In `buildRPFromResolvedRequest()`, add the `requestURIHandler` option when `useRequestURI` is true.

```go
if resolved.useRequestURI {
    opts = append(opts, rp.WithRequestURIMode(func(signedJWT string) (string, error) {
        id := requestObjectStore.Store(signedJWT)
        return "https://rp.localhost/request/" + id, nil
    }))
}
```

This wires the store from Phase 1 to the RP library callback from Phase 2.

### Success Criteria

#### Automated Verification
- [x] `go test ./cmd/example-rp/...` passes.
- [x] Unit test: `shouldUseRequestURI` returns true for OIDCC `request_uri` without FAPI profile.
- [x] Unit test: `shouldUseRequestURI` returns false when `runtimeRequiresPAR` is true (FAPI case).
- [x] Unit test: `shouldUseRequestURI` returns false for `request_object` and `plain_http_request`.

#### Manual Verification
- [ ] Authorization redirect URL contains `request_uri` for OIDCC `request_uri` variants.

---

## Phase 4: Suite Config & Conformance Verification

### Overview

Verify that the conformance suite accepts the hosted `request_uri`. If the suite requires `request_uris` registration in the plan config, add it.

### Changes Required

#### 1. Investigate: Suite `request_uris` field

The OIDCC conformance suite may require the plan config to list allowed `request_uri` values (similar to `redirect_uris`). This needs to be tested empirically:

1. Run an OIDCC config `request_uri` variant.
2. Check suite logs for any `request_uri` validation errors.
3. If the suite rejects unregistered URIs, add `request_uris` to the plan config.

#### 2. Potential change: `conformance/harness/execute.go`

If the suite requires `request_uris` registration, modify `buildPlanConfig()`:

```go
if strings.EqualFold(strings.TrimSpace(requestType), "request_uri") {
    cfg["client"].(map[string]any)["request_uris"] = []string{
        "https://rp.localhost/request/",
    }
    cfg["client2"].(map[string]any)["request_uris"] = []string{
        "https://rp.localhost/request/",
    }
}
```

This uses a prefix-based registration if the suite supports it, or a wildcard pattern. The exact format depends on what the suite accepts.

Similarly for `buildStandaloneModuleConfig()`.

#### 3. Run conformance tests

Execute the OIDCC config matrix and verify the affected modules:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=oidcc-config-full
```

Then check results specifically for:
- `oidcc-client-test-idtoken-sig-none`
- `oidcc-client-test-signing-key-rotation`
- `oidcc-client-test-signing-key-rotation-just-before-signing`

### Success Criteria

#### Automated Verification
- [ ] `go test ./...` remains green.
- [ ] OIDCC config `request_uri` variants no longer fail with `FetchRequestUriAndExtractRequestObject`.
- [ ] The three affected modules progress past `INTERRUPTED` in `request_uri` variants.
- [ ] Existing `plain_http_request` and `request_object` variant tests are not regressed.
- [ ] FAPI conformance tests are not regressed (run `fapi2-sp-full` or `fapi2-ms-full` preset).

#### Manual Verification
- [ ] Suite logs show `request_uri` present on authorization requests for OIDCC config `request_uri` variants.
- [ ] Suite can successfully fetch the request object from `https://rp.localhost/request/{id}`.
- [ ] No unexpected errors in RP logs during `request_uri` flow.

---

## Testing Strategy

### Unit Tests

- **Request object store**: Store/Load lifecycle, expiry, concurrent access, cleanup.
- **Request object handler**: HTTP GET returns JWT, 404 for unknown, 405 for non-GET, correct content type.
- **RP `requestURIHandler`**: When set, `AuthorizationURL` returns `request_uri` in URL. When nil, preserves `request` by value.
- **`shouldUseRequestURI`**: True for OIDCC `request_uri`, false for FAPI/PAR, false for other request types.
- **Integration**: Full flow from runtime config resolution through `AuthorizationURL` with `request_uri` mode enabled.

### Integration Tests

- Run OIDCC config certification matrix and verify `request_uri` variants pass.
- Run FAPI2 SP/MS smoke tests to verify no regression.

### Manual Testing Steps

1. Start the conformance stack: `bash conformance/scripts/setup.sh && bash conformance/scripts/build_suite.sh && cd conformance && docker compose up -d`.
2. Run a single `request_uri` variant against the OIDCC config plan.
3. Check the suite UI at `https://suite.localhost` for the test result.
4. Inspect the authorization redirect URL in RP logs — should contain `request_uri`.
5. Verify the suite can fetch the request object by checking access logs for `GET /request/{id}`.

## Performance Considerations

- The in-memory store has negligible overhead — request objects are small JWTs (< 2KB), stored for 5 minutes.
- The cleanup goroutine runs every 60 seconds and removes expired entries.
- No persistent storage is needed; request objects are single-use and short-lived.
- The `/request/{id}` endpoint is a simple map lookup — sub-microsecond latency.

## Migration Notes

- No database or configuration migration needed.
- The change is backward-compatible: existing `request_object` and `plain_http_request` variants are unaffected.
- FAPI profiles continue using PAR for `request_uri` as before.

## References

- Original ticket: `thoughts/tickets/bug_oidcc_config_request_uri_not_sent.md`
- Related plan: `thoughts/plans/2026-04-08-oidc-config-certification-matrix.md`
- Authorization request construction: `rp/authrequest.go:49-133`
- Request object signing: `rp/request_object.go:34-82`
- Runtime config resolution: `cmd/example-rp/runtime_resolution.go:258-266`
- Matrix variant definitions: `conformance/harness/matrix.go:127-175`
