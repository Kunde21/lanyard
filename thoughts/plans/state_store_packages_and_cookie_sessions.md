# RP State Store Packages And Cookie Sessions Implementation Plan

## Overview

Refactor RP state handling so `rp` keeps only the public abstraction and RP integration points, while concrete implementations move into supported public packages under `rp/store/...`. The redesign will replace the current context-only browser flow methods with HTTP-aware entrypoints, add a first-class cookie-backed store built on `gorilla/sessions`, and broaden the state model to support both RP-managed callback correlation data and caller-owned opaque values.

## Current State Analysis

Today the state abstraction and the default memory implementation both live in `rp`: `StateData` and `StateStore` are defined in `rp/state_store.go:5`, while `MemoryStateStore` lives in `rp/memory_state_store.go:8`. The auth-start flow persists callback correlation data through `AuthorizationURL(ctx)` in `rp/authrequest.go:14`, and callback handling reads then manually deletes that state in `rp/callback.go:15`.

The current design is insufficient for cookie-backed session storage because neither the store contract nor the RP flow methods have request/response access. `StateStore` only exposes `Save`, `Load`, and `Delete` with no errors or HTTP context in `rp/state_store.go:17`, while the public flow methods are context-only in `rp/authrequest.go:14` and `rp/callback.go:15`. The example RP encodes the same contract in `cmd/example-rp/main.go:19`, and the current tests are tightly coupled to direct in-package memory-store access in `rp/authrequest_test.go:77`, `rp/callback_test.go:94`, and `rp/state_store_test.go:10`.

There is also a semantic mismatch in expiry and one-time use. The in-memory store expires entries using only `CreatedAt + ttl` in `rp/memory_state_store.go:35`, while callback one-time use is implemented procedurally via `Load` then `Delete` in `rp/callback.go:23`. That makes store-level consume semantics impossible without redesign.

## Desired End State

After this work:

1. `rp` exposes a revised store abstraction that separates typed RP callback correlation data from caller-provided named opaque values while still grouping them under the same state container.
2. The default memory-backed implementation lives in `rp/store/memory` instead of `rp`.
3. A supported cookie-backed implementation lives in `rp/store/cookie` and persists data in a signed/encrypted `gorilla/sessions` cookie session.
4. RP auth-start and callback entrypoints are HTTP-aware so stores that require cookies can read/write through `http.Request` and `http.ResponseWriter`.
5. State consumption is modeled explicitly in the store contract rather than only by RP calling `Load` and `Delete` separately.
6. The example app, docs, and tests demonstrate both the new API shape and cookie-backed browser flow behavior.

### Key Discoveries:
- `rp` currently defaults to the in-package memory store in `rp/rp.go:102`, so package extraction must include constructor rewiring.
- The example app is the primary HTTP integration boundary and already calls the RP directly from handlers in `cmd/example-rp/main.go:126` and `cmd/example-rp/main.go:195`, which makes it the natural place to adopt HTTP-aware flow methods.
- The conformance harness already preserves browser cookies with a cookie jar in `conformance/harness/execute.go:45`, so cookie-backed state fits the existing front-channel execution model without major harness redesign.
- The repository has no direct pattern for a request/response-aware store with consume semantics, so this plan must define a new RP-specific contract rather than copy an existing abstraction.
- Public package and option patterns in `jwks/options.go:9`, `oidc/options.go:11`, and `cache/store.go:5` strongly support small focused public packages with nil-safe constructors and colocated tests.

## What We're NOT Doing

- Adding any persistence backend beyond `rp/store/memory` and `rp/store/cookie`.
- Designing for large cookie/session payloads or cross-service shared session state.
- Keeping deprecated compatibility shims such as `rp.NewMemoryStateStore` forwarding into the new package layout.
- Supporting non-HTTP flows in the cookie-backed implementation.
- General-purpose session middleware outside the RP state-handling use case.
- Changing conformance harness endpoint topology beyond what is required for the new RP API.

## Implementation Approach

Use a layered state model in `rp`: typed RP callback correlation data remains explicit, while caller-provided named values are stored alongside it in the same logical state container. Replace the context-only browser flow methods with HTTP-aware equivalents rather than adding parallel APIs; the ticket allows a breaking change, and a single HTTP-first surface keeps docs and tests cleaner.

The work should proceed from contract to implementations to callers:

1. Define the new `rp` store contract and RP-facing flow API.
2. Extract the memory implementation into `rp/store/memory` while preserving existing behavior where it still applies.
3. Add the cookie-backed implementation in `rp/store/cookie` using `gorilla/sessions` with secure defaults and advanced configuration hooks.
4. Update RP flow methods, example app wiring, tests, and docs to exercise request/response-aware state persistence.

## Phase 1: Redesign RP Store Contract

### Overview

Define the new abstraction in `rp` so the rest of the change has a stable target. This phase should settle naming, typed RP correlation data, arbitrary value handling, consume semantics, and HTTP-aware store participation.

### Changes Required:

#### 1. Core state types and store interface
**File**: `rp/state_store.go`
**Changes**:
- Replace the current `StateStore` interface in `rp/state_store.go:17` with a new contract that:
  - keeps typed RP-managed callback correlation data as a first-class concept
  - supports storing, loading, deleting, and consuming individual caller-owned named values within a state scope
  - returns errors rather than only `bool` for operations that can fail in cookie-backed/session-backed implementations
  - accepts `context.Context` plus request/response inputs where persistence or mutation may need HTTP access
- Keep exported docs tight and explicit about ownership boundaries: RP-managed correlation fields are owned by `rp`; named opaque values are caller-owned.
- Model one-time state use explicitly via a consume-oriented operation for callback correlation rather than leaving it to callers to sequence `Load` + `Delete`.
- Decide the exact exported type names in the implementation, but the plan should preserve this layering:
  - one typed RP correlation record
  - one state container/scope that can also hold named opaque values

#### 2. RP option and default-store seam
**File**: `rp/options.go`
**Changes**:
- Update `WithStateStore` in `rp/options.go:76` to accept the redesigned interface.
- Preserve existing nil-safe option behavior.
- Clarify in doc comments that callers provide the implementation from `rp/store/memory` or `rp/store/cookie`.

#### 3. RP constructor defaults
**File**: `rp/rp.go`
**Changes**:
- Remove the dependency on `rp.NewMemoryStateStore` from `rp/rp.go:102`.
- Plan the new default wiring so `rp.New(...)` imports and uses the extracted memory package constructor instead.
- Keep constructor-time validation and discovery behavior otherwise intact.

### Success Criteria:

#### Automated Verification:
- [x] The RP package compiles against the redesigned store contract: `go test ./rp`
- [x] Constructor and option wiring pass against the new store interface: `go test ./rp -run 'TestNew|Test.*StateStore'`
- [x] No vet issues in the RP package: `go vet ./rp`

#### Manual Verification:
- [x] `go doc ./rp` shows a clear store contract that distinguishes RP-owned correlation data from caller-owned values.
- [x] The `rp` package API no longer exposes a concrete in-package memory store constructor.
- [x] The planned interface reads as implementable by both in-memory and cookie-backed stores without compatibility helper types.
- [x] A reviewer can identify exactly one consume-oriented callback-correlation path in the public contract, rather than an implied `Load` + `Delete` sequence.

---

## Phase 2: Extract And Adapt Memory Store

### Overview

Move the current in-memory implementation into `rp/store/memory`, adapt it to the new store contract, and preserve its role as the default backend for callers who do not opt into cookie-backed storage.

### Changes Required:

#### 1. New public memory package
**File**: `rp/store/memory/*.go`
**Changes**:
- Create the new public package layout under `rp/store/memory`.
- Move the current in-memory logic from `rp/memory_state_store.go:8` into the new package, renaming types/functions as needed to fit the revised interface.
- Preserve concurrency protection and TTL behavior where still applicable.
- Reevaluate expiry semantics so the memory store works correctly with both store-level TTL and any per-entry consume/use rules required by the new RP contract.
- Ensure the package can store:
  - typed RP correlation data
  - caller-provided named opaque values

#### 2. Remove old in-package implementation
**File**: `rp/memory_state_store.go`
**Changes**:
- Delete the old in-package concrete implementation once all references are migrated.
- Do not leave a deprecated forwarding API behind; the ticket explicitly excludes compatibility shims.

#### 3. Memory store tests
**File**: `rp/store/memory/*_test.go`
**Changes**:
- Move/replace the direct store coverage currently in `rp/state_store_test.go:10`.
- Add tests for:
  - save/load/delete of typed RP correlation data
  - save/load/delete of named caller values
  - consume semantics for one-time callback state
  - expiry/TTL behavior
  - concurrent access safety
- Prefer `cmp.Diff`-style assertions to align with repo guidance.

### Success Criteria:

#### Automated Verification:
- [x] The new memory package builds and its direct tests pass: `go test ./rp/store/memory`
- [x] RP constructor and flow tests pass when using the extracted memory implementation: `go test ./rp -run 'TestNew|TestAuthorizationURL|TestHandleCallback'`
- [x] No vet issues in the extracted package or RP package: `go vet ./rp/store/memory ./rp`
- [x] The legacy in-package implementation file is gone and no production code still references `rp.NewMemoryStateStore`: `grep -R "NewMemoryStateStore" rp cmd -n`

#### Manual Verification:
- [x] Library users can construct the supported default store from `rp/store/memory` instead of `rp`.
- [x] The memory store package docs are self-contained and no longer require reading RP internals.
- [x] Callback correlation still behaves as one-time use when backed by memory storage.
- [x] A caller can save at least one named opaque value alongside RP-managed correlation data without needing access to RP internals.

---

## Phase 3: Add Cookie-Backed Store

### Overview

Introduce `rp/store/cookie` as a supported public implementation built on `gorilla/sessions`, with secure defaults and enough configuration flexibility for production browser deployments.

### Changes Required:

#### 1. Cookie store package and configuration
**File**: `rp/store/cookie/*.go`
**Changes**:
- Add `github.com/gorilla/sessions` as a dependency.
- Create a focused cookie-store package with a Lanyard-oriented constructor and option/config surface.
- Persist state inside the session cookie itself, as required by the ticket.
- Support both typed RP correlation data and named caller-owned values inside the session payload.
- Expose secure defaults for cookie behavior, including:
  - `HttpOnly`
  - `Secure`
  - `SameSite`
  - TTL / max-age behavior
  - signing/encryption key expectations
- Allow advanced callers to tune underlying gorilla-session behavior without making the API feel like a thin raw wrapper.
- Include payload/versioning logic if needed so future format changes remain manageable.

#### 2. Cookie-store serialization and bounds
**File**: `rp/store/cookie/*.go`
**Changes**:
- Define the internal cookie/session payload model for one state scope containing:
  - RP correlation data
  - caller-owned named values
- Keep the payload format intentionally small and documented.
- Document that large payloads are out of scope and unsuitable for this backend.
- Ensure consume/delete operations actually mutate and resave the session cookie.

#### 3. Cookie store tests
**File**: `rp/store/cookie/*_test.go`
**Changes**:
- Add direct store tests using `httptest` request/response objects.
- Cover:
  - initial save writes a session cookie
  - load reads back persisted RP correlation data
  - caller value save/load/delete behavior
  - consume semantics remove one-time state
  - missing/tampered/invalid session data returns store errors or not-found outcomes cleanly
  - secure default options are applied as documented

### Success Criteria:

#### Automated Verification:
- [x] Direct cookie-store tests pass: `go test ./rp/store/cookie`
- [x] Full repository tests pass with the new dependency and store package present: `go test ./...`
- [x] No vet issues in the cookie package or RP package: `go vet ./rp/store/cookie ./rp`
- [x] Module metadata is clean after adding the dependency: `go mod tidy && go test ./...`

#### Manual Verification:
- [x] A browser-oriented caller can configure a supported cookie store from `rp/store/cookie`.
- [x] Session cookies are visibly written and cleared as expected during login/callback flows.
- [x] Cookie defaults are sensible for production browser usage and clearly documented.
- [x] The package docs explain key material requirements and cookie payload limitations.
- [x] Browser devtools or an equivalent HTTP inspection confirms the cookie is `HttpOnly`, uses the configured `SameSite` policy, and is marked `Secure` when served over HTTPS.

---

## Phase 4: Replace RP Flow APIs And Update Callers

### Overview

Replace the current context-only browser flow methods with HTTP-aware entrypoints, then update RP tests and the example RP so cookie-backed state can participate naturally in login and callback handling.

### Changes Required:

#### 1. Auth-start flow API
**File**: `rp/authrequest.go`
**Changes**:
- Replace `AuthorizationURL(ctx)` from `rp/authrequest.go:14` with an HTTP-aware entrypoint that receives request/response objects in addition to context.
- Keep the existing authorization-request responsibilities:
  - provider discovery
  - state/nonce/PKCE generation
  - PAR support
  - redirect URL construction
- Route state persistence through the redesigned store contract so cookie-backed implementations can write session state during auth-start.
- Preserve current RP-managed correlation fields already written in `rp/authrequest.go:55` and `rp/authrequest.go:80`.

#### 2. Callback flow API
**File**: `rp/callback.go`
**Changes**:
- Replace `HandleCallback(ctx, code, state)` from `rp/callback.go:15` with an HTTP-aware entrypoint.
- Use store-level consume behavior rather than manual `Load` + `Delete` from `rp/callback.go:23`.
- Preserve downstream callback responsibilities:
  - issuer selection
  - discovery
  - token exchange
  - ID token validation
  - UserInfo retrieval
- Ensure callback failure handling does not leak tokens or session secrets.

#### 3. RP flow tests
**File**: `rp/authrequest_test.go`
**Changes**:
- Rewrite direct auth-start tests so they exercise the HTTP-aware method using `httptest.NewRequest` and `httptest.NewRecorder` instead of only inspecting an in-memory store.
- Keep URL-shape assertions for required auth parameters.
- Add coverage that verifies state persistence through the new store contract.

**File**: `rp/callback_test.go`
**Changes**:
- Rewrite callback tests to use HTTP requests/responses and store-backed state consumption.
- Keep existing error-path expectations for invalid state, missing code, token exchange failure, ID token validation failure, and UserInfo validation failure.
- Add a callback test that verifies state can only be consumed once.

#### 4. Example RP wiring
**File**: `cmd/example-rp/main.go`
**Changes**:
- Update `flowHandler` from `cmd/example-rp/main.go:19` to match the new RP method signatures.
- Remove direct dependency on `rp.NewMemoryStateStore` from `cmd/example-rp/main.go:24`; use the extracted memory package or cookie package explicitly.
- Thread request/response objects from `/login`, `/login-userinfo-body`, and `/callback` handlers into the RP API.
- Prefer the cookie-backed store in the example if the plan wants the docs and browser flow to demonstrate the new feature directly; otherwise, document clearly why the example stays on memory by default.

#### 5. Example tests and harness expectations
**File**: `cmd/example-rp/main_test.go`
**Changes**:
- Update stubs and handler tests to match the new interface without weakening the current HTTP status/error-body assertions.
- Keep tests focused on handler behavior rather than store internals.

**File**: `conformance/harness/execute.go`
**Changes**:
- Verify the current front-channel cookie-jar model is sufficient.
- Only change harness code if the updated example flow requires a small adjustment; avoid unnecessary harness churn.

### Success Criteria:

#### Automated Verification:
- [x] RP and example-app packages pass after the API replacement: `go test ./rp ./cmd/example-rp`
- [x] Focused RP flow tests pass against the HTTP-aware methods: `go test ./rp -run 'TestAuthorizationURL|TestHandleCallback'`
- [x] Example handler tests pass with the new flow interface: `go test ./cmd/example-rp -run 'TestLoginRedirects|TestCallback'`
- [x] Conformance harness unit tests still pass without front-channel regressions: `go test ./conformance/harness`
- [x] No old public flow-method signatures remain in production code: `grep -R "AuthorizationURL(ctx\|HandleCallback(ctx" rp cmd README.md -n`

#### Manual Verification:
- [x] Visiting the example RP `/login` endpoint initiates browser login with persisted state under the new API.
- [x] The callback path succeeds once and rejects replay using the same state.
- [x] Error pages and logs do not expose sensitive values.
- [x] The example RP still works under the conformance harness’s cookie-jar-based front-channel execution model.
- [x] The callback request only succeeds when it carries the same browser session/cookie context created during login.

---

## Phase 5: Documentation, Example Usage, And End-To-End Verification

### Overview

Finish the public story: update README and example usage, document the cookie-backed store as first-class, and verify the new API through package tests and browser/conformance flows.

### Changes Required:

#### 1. Public docs and package references
**File**: `README.md`
**Changes**:
- Replace stale RP usage examples such as the outdated `AuthorizationURL(ctx, "openid profile email", "state-value")` snippet in `README.md:111`.
- Add documentation for the new package layout:
  - `rp`
  - `rp/store/memory`
  - `rp/store/cookie`
- Show a browser-oriented example using the new HTTP-aware API.
- Add at least one cookie-backed example as required by the ticket.

#### 2. Example and conformance docs
**File**: `cmd/example-rp/main.go`
**Changes**:
- Ensure the example app reflects the documented recommended setup.

**File**: `conformance/README.md`
**Changes**:
- Clarify that the harness and example RP exercise browser-style cookie/session behavior.
- Fix any outdated command paths while touching the docs.
- Note the expected store choice and relevant environment/config requirements for running the example under conformance.

#### 3. Optional example test coverage
**File**: `*_test.go` adjacent to docs/examples as appropriate
**Changes**:
- Add or update example coverage if needed so the new public API remains exercised in tests.

### Success Criteria:

#### Automated Verification:
- [x] `go test ./...`
- [x] `go vet ./...`
- [x] `gofumpt ./...`
- [x] `go build ./...`
- [x] Public docs/examples stay in sync with exported packages and method names: `go test ./... && grep -R "NewMemoryStateStore\|AuthorizationURL(ctx\|HandleCallback(ctx" README.md cmd thoughts -n`

#### Manual Verification:
- [x] README usage examples match the actual exported API.
- [x] Package docs and example code clearly show both supported store choices.
- [x] Browser-based login works with the cookie-backed store end to end.
- [x] Conformance-focused documentation still reflects the current local workflow.
- [x] A new user can follow the documented cookie-backed example without needing to inspect unexported RP internals.

---

## Testing Strategy

### Unit Tests:
- Redesign-level interface tests for RP constructor/store wiring.
- Memory store tests for save/load/delete, consume, expiry, and concurrency.
- Cookie store tests for session persistence, secure defaults, tamper/error handling, and consume semantics.
- RP auth-start tests validating parameter generation, PAR handling, and state persistence through the new API.
- RP callback tests validating single-use state consumption and existing token/ID token/UserInfo failure paths.

### Integration Tests:
- `httptest`-based RP tests that drive auth-start and callback with real `http.Request` / `http.ResponseWriter` objects.
- Example-app handler tests exercising `/login` and `/callback` under the new flow signatures.
- Conformance harness verification to confirm cookie-backed/browser flows still operate through front-channel redirects.

### Manual Testing Steps:
1. Run focused package tests during implementation: `go test ./rp/... ./cmd/example-rp/...`.
2. Run full verification: `gofumpt ./... && go vet ./... && go test ./...`.
3. Start the local example or conformance stack and visit `https://rp.localhost/login`.
4. Complete one browser login and confirm callback success.
5. Retry the same callback or replay the same state and confirm it is rejected.
6. If using the cookie-backed store, inspect browser cookies to confirm session creation and cleanup behavior.

## Performance Considerations

- Cookie-backed storage must keep payloads intentionally small because all persisted state lives in the session cookie itself.
- The plan should avoid repeated serialization churn where possible, but correctness and clear semantics matter more than micro-optimizations.
- Memory-store concurrency safety must remain intact after extraction.
- End-to-end conformance/browser flows should not regress because the harness already preserves cookies and normal redirect behavior.

## Migration Notes

- This is an intentional breaking change to the public RP browser-flow API.
- Callers using `rp.NewMemoryStateStore` must move to the new constructor in `rp/store/memory`.
- Callers using `AuthorizationURL(ctx)` and `HandleCallback(ctx, code, state)` must migrate to the new HTTP-aware methods.
- README, example code, and package docs should be updated in the same change set so users see the new package layout and flow shape immediately.

## References

- Original ticket: `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md`
- Related research: `thoughts/research/2026-03-22_state_store_packages_and_cookie_sessions.md`
- Earlier session-management context: `thoughts/research/2026-02-22_basic_rp_conformance_profile.md`
- Related prior plan: `thoughts/plans/basic_rp_test_profile.md`
- Current state contract: `rp/state_store.go:5`
- Current in-memory store: `rp/memory_state_store.go:8`
- Current auth-start flow: `rp/authrequest.go:14`
- Current callback flow: `rp/callback.go:15`
- Current RP default store wiring: `rp/rp.go:102`
- Example RP HTTP integration points: `cmd/example-rp/main.go:126`, `cmd/example-rp/main.go:195`
- Conformance browser-cookie model: `conformance/harness/execute.go:45`

## Deviations from Plan

### Phase 1: Redesign RP Store Contract
- **Original Plan**: Keep the redesigned store contract in `rp/state_store.go` while moving concrete stores under `rp/store/...` and wiring `rp.New(...)` to the extracted memory store.
- **Actual Implementation**: Added a dedicated shared contract package at `rp/store` and re-exported the public contract/types from `rp/state_store.go` via type aliases.
- **Reason for Deviation**: Directly keeping contract types only in `rp` while importing `rp/store/memory` from `rp` creates a Go import cycle (`rp -> rp/store/memory -> rp`).
- **Impact Assessment**: Public `rp` API remains intact and documented, default store wiring works, and both `rp/store/memory` and `rp/store/cookie` implement a single shared contract cleanly.
- **Date/Time**: 2026-03-22

### Phase 4: Replace RP Flow APIs And Update Callers
- **Original Plan**: Use `grep -R "AuthorizationURL(ctx\|HandleCallback(ctx" rp cmd README.md -n` to prove old signatures are gone.
- **Actual Implementation**: Verified legacy signatures using exact-match checks (`AuthorizationURL(ctx context.Context)` and `HandleCallback(ctx context.Context, code, state string)`) because the planned grep pattern also matches the new HTTP-aware signatures.
- **Reason for Deviation**: The original pattern is too broad and returns false positives after migration.
- **Impact Assessment**: Verification intent is preserved; exact legacy signatures are absent from `rp`, `cmd`, and `README.md`.
- **Date/Time**: 2026-03-22

### Phase 5: Documentation, Example Usage, And End-To-End Verification
- **Original Plan**: Run `gofumpt ./...` and grep legacy names under `README.md cmd thoughts`.
- **Actual Implementation**: Ran `gofumpt -w .` (tool-compatible invocation) and constrained legacy-signature checks to active docs/code (`README.md`, `cmd`) since `thoughts/` intentionally contains historical references.
- **Reason for Deviation**: Local `gofumpt` binary expects filesystem paths and archived `thoughts/` content is historical, not runtime/public API surface.
- **Impact Assessment**: Source formatting and active docs/code verification are complete; historical planning/research records remain intentionally unchanged.
- **Date/Time**: 2026-03-22
