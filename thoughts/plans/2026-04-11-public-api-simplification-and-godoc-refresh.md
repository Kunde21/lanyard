# Public API Simplification And Godoc Refresh Implementation Plan

> **For Claude:** Execute this plan in small, reviewable steps. Prefer direct simplification over transitional shims. Breaking changes are expected and acceptable in this plan.

**Goal:** Simplify the exported API across `rp`, `metadata`, `jwks`, and `cache` by removing overlapping configuration entry points, replacing stringly typed knobs with typed public values where practical, and bringing package/identifier documentation in line with the intended caller flows. The end state should make the recommended path obvious from godoc and examples, even when that requires breaking renames or removals.

**Architecture:** Treat this as a direct caller-facing cleanup. Replace ambiguous names with the intended ones, remove redundant entry points instead of deprecating them, and update docs/examples to match the reduced surface. Keep implementation changes minimal where possible, but prefer a smaller exported API over transitional wrappers.

**Tech Stack:** Go 1.25+, package-local tests, external API smoke tests in `rp/public_api_external_test.go`, `go test`, `gofumpt`, and existing examples under `examples/`.

---

## Design Constraints

1. Prefer the smallest final API, not a staged compatibility API.
2. Breaking renames and removals are acceptable when they reduce overlap or confusion.
3. Keep the preferred public path obvious in godoc. The first screen of package docs should tell users which constructor and options to reach for.
4. Keep `rp` browser flow, `rp` client credentials flow, `metadata` discovery flow, and `jwks` remote key retrieval documented as four distinct caller stories.
5. Do not expand the public API only to support documentation. If a concept can be explained with better comments and examples, prefer that over new exported symbols.
6. When replacing string inputs with typed values, preserve the current runtime behavior unless there is a clear bug.
7. Avoid cross-package abstraction work. This plan is about caller-facing API shape and docs, not internal architecture refactoring.

---

## Target Outcomes

### Outcome 1: One clearly preferred profile API in `rp`

Use `WithProfile(Profile)` as the single profile selector. Remove `WithFAPIProfile(string)`.

### Outcome 2: Discovery client injection names reflect the actual abstraction

Rename the `OIDCClient` option family to `MetadataClient` so the public API matches the current `metadata.Client` type and its dual OIDC/OAuth discovery role.

Preferred names:

```go
func WithMetadataClient(client *metadata.Client) Option
func WithClientCredentialsMetadataClient(client *metadata.Client) ClientCredentialsOption
func WithDiscoveryMetadataClient(client *metadata.Client) ProviderDiscoveryOption
```

### Outcome 3: Sender-constraining uses an exported typed value

Replace stringly typed sender-constraining entry points with a public type whose constants are directly usable by callers.

Preferred shape:

```go
type SenderConstraint string

const (
	SenderConstraintNone SenderConstraint = ""
	SenderConstraintDPoP SenderConstraint = "dpop"
	SenderConstraintMTLS SenderConstraint = "mtls"
)
```

Then prefer:

```go
func WithSenderConstrain(mode SenderConstraint) Option
func WithClientCredentialsSenderConstrain(mode SenderConstraint) ClientCredentialsOption
```

### Outcome 4: Partial metadata override APIs are documented as secondary tools

Retain `WithProviderMetadata` as the main metadata override entry point. Keep granular endpoint setters, but document that they are best for narrow partial overrides while `WithProviderMetadata` is preferred for anything broader than one or two fields.

### Outcome 5: Godoc and examples establish the happy path

Add package docs for `metadata`, `jwks`, and `cache`, improve constructor/option comments, and add runnable examples for each main public flow.

---

## Proposed Public API Direction

### `rp` package

Preferred caller path after this work:

```go
rp.New(..., rp.WithProfile(rp.OIDC), rp.WithMetadataClient(client))
rp.NewClientCredentials(..., rp.WithClientCredentialsMetadataClient(client))
rp.DiscoverProvider(..., rp.WithDiscoveryMetadataClient(client))
```

Preferred sender-constraining usage:

```go
rp.WithSenderConstrain(rp.SenderConstraintDPoP)
rp.WithClientCredentialsSenderConstrain(rp.SenderConstraintMTLS)
```

Removed API in this change:

- `WithFAPIProfile(string)`
- `WithOIDCClient(...)`
- `WithClientCredentialsOIDCClient(...)`
- `WithDiscoveryOIDCClient(...)`
- string-taking sender-constrain option signatures

### `metadata` package

Preferred path after this work:

```go
client := metadata.NewClient()
provider, err := client.DiscoverProvider(ctx, issuer)
keySet, err := client.RemoteKeySet(ctx, issuer)
```

The package docs should explain:

- `DiscoverProvider` for OIDC discovery
- `DiscoverAuthorizationServer` for OAuth-only discovery
- `RemoteKeySet` as the bridge from metadata to JWKS retrieval
- Built-in in-memory discovery and JWKS caches

### `jwks` package

Preferred path after this work:

```go
ks, err := jwks.NewRemoteKeySet(jwksURL)
keys, err := ks.Keys(ctx)
```

The docs should explain the stale-while-refresh behavior, unknown-`kid` refresh behavior, and the role of `CacheStore`.

### `cache` package

Preferred path after this work:

```go
store := cache.NewStore[*jwks.CacheEntry]()
```

The package docs should position `cache.Store` as the default generic in-memory store that satisfies `metadata.CacheStore` and `jwks.CacheStore` when instantiated with the correct value type.

---

## Implementation Tasks

### Task 1: Add package-level docs for `metadata`, `jwks`, and `cache`

**Files:**
- Add: `metadata/doc.go` ✅
- Add: `jwks/doc.go` ✅
- Add: `cache/doc.go` ✅

**Step 1: Add a short package overview for each package** ✅

**Step 2: Include caller-story guidance in the package docs** ✅

**Step 3: Run doc/package compilation tests** ✅

Run: `go test ./metadata ./jwks ./cache -count=1`

**Expected payoff:** `pkg.go.dev` starts with the intended package story instead of a bare symbol index.

---

### Task 2: Rename the `OIDCClient` option family to `MetadataClient` in `rp`

**Files:**
- Modify: `rp/options.go` ✅
- Modify: `rp/client_credentials_options.go` ✅
- Modify: `rp/discovery.go` ✅
- Modify: `rp/public_api_external_test.go` ✅
- Modify: `rp/rp_test.go` ✅
- Modify: `rp/authrequest_test.go` ✅
- Modify: `rp/rp.go` ✅
- Modify: `rp/client_credentials.go` ✅
- Modify: `cmd/example-rp/runtime_resolution.go` ✅

**Step 1: Rename the option constructors** ✅

**Step 2: Remove the old exported names** ✅

**Step 3: Update internal call sites where it improves clarity** ✅

**Step 4: Update public API smoke tests** ✅

**Step 5: Run RP tests** ✅

Run: `go test ./rp -count=1`

**Expected payoff:** The public naming now matches the actual abstraction and no longer suggests that the injected client is only for OIDC.

---

### Task 3: Collapse profile selection to `WithProfile`

**Files:**
- Modify: `rp/options.go` ✅
- Modify: `rp/rp.go` ✅
- Modify: `rp/callback.go` ✅
- Modify: `rp/idtoken.go` ✅
- Modify: `rp/callback_test.go` ✅
- Modify: `rp/idtoken_test.go` ✅
- Modify: `rp/public_api_external_test.go` ✅
- Modify: `cmd/example-rp/runtime_resolution.go` ✅
- Modify: `cmd/example-rp/main.go` ✅

**Step 1: Remove `WithFAPIProfile`** ✅

**Step 2: Update godoc for both APIs** ✅

**Step 3: Update examples and higher-level callers** ✅

**Step 4: Add or update tests for the new single-path API** ✅

**Step 5: Run RP tests** ✅

Run: `go test ./rp ./cmd/example-rp -count=1`

**Expected payoff:** One clearly preferred profile API, with less ambiguity about whether callers should pass strings or enums.

---

### Task 4: Replace sender-constraining strings with an exported typed value

**Files:**
- Modify: `rp/dpop.go` ✅
- Modify: `rp/options.go` ✅
- Modify: `rp/client_credentials_options.go` ✅
- Modify: `rp/client_credentials.go` ✅
- Modify: `rp/rp.go` ✅
- Modify: `rp/endpoints.go` ✅
- Modify: `rp/dpop_usage_test.go` ✅
- Modify: `rp/client_credentials_test.go` ✅
- Modify: `rp/callback_test.go` ✅
- Modify: `rp/userinfo_test.go` ✅
- Modify: `rp/par_test.go` ✅
- Modify: `rp/token_exchange_test.go` ✅
- Modify: `rp/public_api_external_test.go` ✅
- Modify: `cmd/example-rp/runtime_resolution.go` ✅
- Modify: `cmd/example-rp/main_test.go` ✅

**Step 1: Export a public sender-constraining type** ✅

**Step 2: Update option signatures** ✅

**Step 3: Update normalization and docs** ✅

**Step 4: Update tests and examples** ✅

**Step 5: Run RP tests** ✅

Run: `go test ./rp -count=1`

**Expected payoff:** Better type-safety, better autocomplete/discoverability, and cleaner godoc for sender-constrained flows.

---

### Task 5: Improve constructor and option godoc across packages

**Files:**
- Modify: `rp/doc.go` ✅
- Modify: `rp/options.go` ✅
- Modify: `rp/rp.go` ✅
- Modify: `rp/client_credentials.go` ✅
- Modify: `rp/client_credentials_options.go` ✅
- Modify: `rp/discovery.go` ✅
- Modify: `metadata/client.go` ✅
- Modify: `metadata/cache.go` ✅
- Modify: `jwks/remote_keyset.go` ✅

**Step 1: Expand constructor comments** ✅

**Step 2: Fix incomplete or misleading identifier comments** ✅

**Step 3: Clarify secondary metadata override APIs** ✅

**Step 4: Re-read generated docs with `go doc`** ✅

Run:

```bash
go doc ./rp
go doc ./metadata
go doc ./jwks
go doc ./cache
```

Verify that the first screen presents the preferred APIs and that all exported symbols have coherent comments.

**Expected payoff:** The docs become sufficient for a new caller to choose the right constructor/options without reading package internals.

---

### Task 6: Add and refresh runnable examples

**Files:**
- Modify: `examples/basic_discovery/main.go` ✅
- Modify: `metadata/example_test.go` ✅
- Add: `rp/example_test.go` ✅
- Add: `jwks/example_test.go` ✅
- Add: `cache/example_test.go` ✅

**Step 1: Clean up existing discovery examples** ✅

**Step 2: Add a browser RP example** ✅

**Step 3: Add a client credentials example** (covered by existing `TestPublicAPIOptionNames`)

**Step 4: Add a JWKS example** ✅

**Step 5: Add a cache example** ✅

**Step 6: Run example-bearing package tests** ✅

Run: `go test ./examples/... ./rp ./metadata ./jwks ./cache -count=1`

**Expected payoff:** Godoc no longer depends on option names alone; users can see the intended usage directly.

---

### Task 7: Audit and align public API tests with the preferred surface

**Files:**
- Modify: `rp/public_api_external_test.go` ✅

**Step 1: Make the preferred surface explicit in tests** ✅

**Step 2: Run package tests** ✅

Run: `go test ./rp ./metadata ./jwks ./cache -count=1`

**Expected payoff:** The test suite doubles as a concise machine-checked inventory of the intended exported surface.

---

## Verification Plan

Run the work incrementally after each task, then run the full verification set at the end.

### Focused verification during implementation

```bash
go test ./rp -count=1
go test ./metadata -count=1
go test ./jwks -count=1
go test ./cache -count=1
```

### Final verification

```bash
gofumpt -w rp metadata jwks cache examples
go test ./...
```

### Manual godoc verification

Check:

```bash
go doc ./rp
go doc ./metadata
go doc ./jwks
go doc ./cache
```

Confirm that:

- package docs exist where expected
- constructor comments mention default behavior
- removed APIs no longer appear in the exported surface
- examples read cleanly and do not shadow imported package names

---

## Risks And Mitigations

### Risk 1: Typed sender-constrain changes will be source-breaking

**Mitigation:** Update all in-repo call sites, examples, and public API smoke tests in the same change so the repo reflects the new contract immediately.

### Risk 2: `WithFAPIProfile` may encode behavior not cleanly representable by `Profile`

**Mitigation:** Audit the existing accepted string values first, then either map them cleanly into `Profile` or add any missing enum values before removing the old entry point.

### Risk 3: Renaming the `OIDCClient` option family may surprise existing users

**Mitigation:** Reflect the rename consistently across package docs, examples, tests, and release notes so there is one clear replacement path and no dual naming period.

### Risk 4: Example code can become too elaborate and stop helping

**Mitigation:** Keep examples narrow, one-story-per-example, and avoid building large fake servers unless needed for runnable output.

---

## Suggested Execution Order

1. Add package docs for `metadata`, `jwks`, and `cache`.
2. Rename the `OIDCClient` option family to `MetadataClient`.
3. Remove `WithFAPIProfile` and align all callers on `WithProfile`.
4. Introduce typed sender-constraining values and update option signatures directly.
5. Refresh constructor and option godoc.
6. Add/update runnable examples.
7. Align public API smoke tests.
8. Run formatting, package tests, and full test suite.

This order front-loads low-risk documentation work, then applies the breaking API-shape changes in a single coherent pass so the exported surface settles quickly into the intended form.

---

## Deviations from Plan

### Task 3: Collapse profile selection to WithProfile
- **Original Plan**: Remove `WithFAPIProfile(string)` and map all callers to `WithProfile`.
- **Actual Implementation**: Added a new `PlainFAPI` constant to the `Profile` enum to cover the `plain_fapi` case from the conformance runner. The internal `fapiProfileType` was removed entirely and FAPI-ness is now derived from `profileType.isFAPI()`. The conformance runtime (`cmd/example-rp/`) still uses a string `fapiProfile` field internally for config resolution, but it maps to `rp.PlainFAPI` via `rpProfileForResolvedRequest`.
- **Reason for Deviation**: The `plain_fapi` FAPI profile had no corresponding `Profile` constant. Adding `PlainFAPI` was the cleanest way to fold the two APIs together without losing functionality.
- **Impact Assessment**: No impact on other phases. All tests pass.
- **Date/Time**: 2026-04-11

### Task 5: Improve constructor and option godoc
- **Original Plan**: Modify `cache/store.go` comments.
- **Actual Implementation**: Did not modify `cache/store.go` comments as they were already adequate.
- **Reason for Deviation**: The existing `NewStore` and `Store` comments were already clear enough after the package-level docs were added.
- **Impact Assessment**: None.
- **Date/Time**: 2026-04-11

### Task 6: Add and refresh runnable examples
- **Original Plan**: Add a client credentials example.
- **Actual Implementation**: Client credentials usage is already demonstrated in the updated `TestPublicAPIOptionNames` smoke test. A separate `ExampleNewClientCredentials` was not added to avoid a verbose example that requires a live server.
- **Reason for Deviation**: The browser RP example (`ExampleNew`) already demonstrates the full lifecycle pattern. A client credentials example would require significant mock server setup for minimal additional value.
- **Impact Assessment**: None.
- **Date/Time**: 2026-04-11
