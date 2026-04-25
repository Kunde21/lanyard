# Simplify State Store Core Correlation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** Narrow the core RP dependency on state storage to callback correlation only, while preserving caller-owned state value APIs unless compatibility analysis proves they can be removed safely.

**Architecture:** Split the storage contract in `rp/store/store.go` into small role interfaces so `rp.RP` depends only on correlation save/consume behavior. Keep full state/value capabilities available for store implementations and external callers through a composed interface, with `rp.StateStore` remaining source-compatible unless a deliberate breaking change is accepted.

**Tech Stack:** Go, `net/http`, `context`, `rp/store/memory`, `rp/store/cookie`, `github.com/google/go-cmp/cmp`.

---

## Investigation Summary

Core RP production code only needs callback correlation operations:

- `rp/authrequest.go:28` calls `r.stateStore.SaveCorrelation(...)`.
- `rp/callback.go:76` calls `r.stateStore.ConsumeCorrelation(...)`.
- `rp/options.go:199` exposes `WithStateStore(store StateStore)`.
- `rp/rp.go:76` stores the dependency as `stateStore StateStore`.
- `rp/rp.go:335` defaults to `memory.New(10 * time.Minute)`.

The broader API is still public and tested:

- `rp/store/store.go:39` defines `StateStore` with correlation, whole-state, and caller-value methods.
- `rp/state_store.go:17` aliases that broad interface as `rp.StateStore`.
- `rp/store/memory/store.go` implements all methods.
- `rp/store/cookie/store.go` implements all methods.
- `rp/store/memory/store_test.go` and `rp/store/cookie/store_test.go` directly test `LoadState`, `DeleteState`, `SaveValue`, `LoadValue`, `DeleteValue`, and `ConsumeValue`.
- `cmd/example-rp/state_store_namespace.go` and `cmd/example-rp/state_store_issuer.go` wrap the full interface, but only production RP flow requires correlation methods.
- `cmd/example-rp/state_store_namespace_test.go` explicitly verifies `SaveValue` namespacing.
- `cmd/example-rp/state_store_issuer_test.go` includes full-interface test doubles because the wrapper types currently satisfy `rp.StateStore`.

No production caller-owned state value usage was found outside store implementations and example wrapper pass-through. Because these methods are exported from `rp/store` and re-exported as `rp.StateStore`, removing them is a breaking public API change even if the core RP no longer needs them.

## Compatibility And Migration Analysis

The safe path is to split interfaces without removing capabilities:

- Add a narrow correlation interface for core RP use in `rp/store/store.go`, for example `CorrelationStore` with `SaveCorrelation` and `ConsumeCorrelation`.
- Keep the current full `StateStore` name as a composed interface that embeds the narrow correlation interface plus state-scope and value interfaces.
- Change only the private `RP.stateStore` field and any internal helper expectations to the narrow interface if no test requires direct access to full methods through `r.stateStore`.
- Keep `rp.WithStateStore(store StateStore)` initially source-compatible for existing custom stores.
- Optionally add a new `rp.WithCorrelationStore(store rpstore.CorrelationStore)` only if there is a concrete need to let minimal implementations configure RP without implementing value methods.
- Do not delete `StateScope`, `LoadState`, `DeleteState`, or value methods in the first pass; they are exported and tested.

Breaking-change alternative, only if explicitly approved:

- Redefine `rp.StateStore` as correlation-only.
- Move full state/value behavior to a new exported `rpstore.StateScopeStore` or `rpstore.ValueStore` composition.
- Update example wrappers and test doubles to implement only the methods they actually need.
- Document the migration for users with custom `StateStore` implementations that previously exposed caller-owned values through the `rp.StateStore` alias.

Recommended migration stance:

- Treat this as a non-breaking internal simplification first.
- Defer public method removal to a major-version or explicitly breaking cleanup ticket.
- Preserve cookie and memory store behavior because they are useful public implementations and already support the full surface.

## TDD Implementation Tasks

### Task 1: Add Compile-Time Coverage For Narrow Core Dependency

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/rp_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/store/store.go`

**Step 1: Write the failing test**

Add a test-only minimal correlation store in `/home/kunde21/development/AI/lanyard/rp/rp_test.go` that implements only `SaveCorrelation` and `ConsumeCorrelation`. Add a constructor or option test that proves RP can be configured with the narrow contract if a new narrow option is introduced.

If no new option is introduced, instead add compile-time assertions in `/home/kunde21/development/AI/lanyard/rp/store/store.go` tests or package docs proving `StateStore` embeds the new narrow interface and implementations satisfy both.

**Step 2: Run test to verify it fails**

Run: `go test ./rp -run 'Test.*StateStore|TestNew'`

Expected: fails because the narrow interface or option does not exist yet.

**Step 3: Implement minimal interface split**

In `/home/kunde21/development/AI/lanyard/rp/store/store.go`, split the current methods into role interfaces:

```go
// CorrelationStore persists RP-managed callback correlation data.
type CorrelationStore interface {
	SaveCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string, correlation CallbackCorrelation) error
	ConsumeCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) (CallbackCorrelation, bool, error)
}

// StateScopeStore persists and loads complete state scopes.
type StateScopeStore interface {
	LoadState(ctx context.Context, req *http.Request, state string) (StateScope, bool, error)
	DeleteState(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) error
}

// ValueStore persists caller-owned values scoped by state.
type ValueStore interface {
	SaveValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string, value []byte) error
	LoadValue(ctx context.Context, req *http.Request, state, name string) ([]byte, bool, error)
	DeleteValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) error
	ConsumeValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) ([]byte, bool, error)
}

// StateStore persists RP callback correlation data and caller-owned state values.
type StateStore interface {
	CorrelationStore
	StateScopeStore
	ValueStore
}
```

Keep doc comments explicit about RP-owned versus caller-owned data.

**Step 4: Run test to verify it passes**

Run: `go test ./rp -run 'Test.*StateStore|TestNew'`

Expected: pass.

### Task 2: Narrow Internal RP Field If Source-Compatible

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/rp.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/options.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/authrequest_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/callback_test.go`

**Step 1: Write or adjust failing tests**

If adding `WithCorrelationStore`, add a test in `/home/kunde21/development/AI/lanyard/rp/rp_test.go` showing a correlation-only test double can be injected.

Before changing the private field, inspect tests that access `r.stateStore.LoadState` directly:

- `/home/kunde21/development/AI/lanyard/rp/authrequest_test.go:84`
- `/home/kunde21/development/AI/lanyard/rp/callback_test.go:1043`
- `/home/kunde21/development/AI/lanyard/rp/callback_test.go:1187`

Rewrite those tests to keep a concrete memory store variable and inject it via `WithStateStore`, then call `store.LoadState(...)` on the concrete variable instead of `r.stateStore.LoadState(...)`.

**Step 2: Run test to verify current coupling**

Run: `go test ./rp -run 'TestAuthorizationURL|TestHandleCallback_HybridFlow'`

Expected: pass before field narrowing; after changing only the field, these tests should fail until rewritten.

**Step 3: Narrow the private field**

Change `/home/kunde21/development/AI/lanyard/rp/rp.go` so `RP.stateStore` uses `rpstore.CorrelationStore` or the `rp` alias for that narrow interface. Keep `/home/kunde21/development/AI/lanyard/rp/options.go:199` source-compatible unless adding an optional narrow setter.

Do not change `AuthorizationURL` or `HandleCallback` behavior; they already use only correlation methods.

**Step 4: Run focused tests**

Run: `go test ./rp -run 'TestAuthorizationURL|TestHandleCallback|TestNew|Test.*StateStore'`

Expected: pass.

### Task 3: Simplify Example Wrappers Only If Safe

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/cmd/example-rp/state_store_namespace.go`
- Modify: `/home/kunde21/development/AI/lanyard/cmd/example-rp/state_store_issuer.go`
- Modify: `/home/kunde21/development/AI/lanyard/cmd/example-rp/state_store_namespace_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/cmd/example-rp/state_store_issuer_test.go`

**Step 1: Write failing wrapper tests**

If the example wrappers can accept only a correlation store, replace full-interface test doubles with narrow doubles and assert `SaveCorrelation` and `ConsumeCorrelation` behavior still works.

Keep `SaveValue` namespacing coverage only if the wrapper remains a full `StateStore` wrapper for external/example utility purposes.

**Step 2: Run example tests**

Run: `go test ./cmd/example-rp -run 'TestNamespacedStateStore|TestIssuerShorthandStore|TestResolveRPRequest_UsesIssuerAliasStateStoreForRegisteredRuntime'`

Expected: fail only for intentional type mismatch while narrowing wrappers.

**Step 3: Apply minimal wrapper change**

Prefer no wrapper changes if `stateStoreForRuntime` and `resolvedRP.stateStore` still expose `rp.StateStore` for cookie and memory stores. If changing, narrow only internal fields that do not need value methods.

Do not remove value pass-through methods from wrappers if tests or downstream example behavior still rely on namespacing caller-owned values.

**Step 4: Run example tests again**

Run: `go test ./cmd/example-rp -run 'TestNamespacedStateStore|TestIssuerShorthandStore|TestResolveRPRequest_UsesIssuerAliasStateStoreForRegisteredRuntime'`

Expected: pass.

### Task 4: Preserve Store Implementation Compatibility

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/store/memory/store_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/store/cookie/store_test.go`

**Step 1: Add compile-time assertions**

Add assertions that both implementations satisfy all relevant interfaces:

```go
var _ rpstore.CorrelationStore = (*Store)(nil)
var _ rpstore.StateScopeStore = (*Store)(nil)
var _ rpstore.ValueStore = (*Store)(nil)
var _ rpstore.StateStore = (*Store)(nil)
```

Use the appropriate package import aliases in each test file.

**Step 2: Run direct store tests**

Run: `go test ./rp/store/memory ./rp/store/cookie`

Expected: pass.

**Step 3: Do not alter persistence semantics**

Leave `/home/kunde21/development/AI/lanyard/rp/store/memory/store.go` and `/home/kunde21/development/AI/lanyard/rp/store/cookie/store.go` behavior unchanged unless the interface split requires doc comment updates.

### Task 5: Documentation And Public API Notes

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/state_store.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/store/store.go`
- Optionally modify: `/home/kunde21/development/AI/lanyard/rp/doc.go`

**Step 1: Update exported docs**

Document that core RP requires only correlation storage, while full `StateStore` also supports caller-owned values for applications that need them.

**Step 2: Run docs-related checks**

Run: `go vet ./rp ./rp/store/...`

Expected: no exported comment or vet failures.

## Verification Commands

Run these before claiming completion:

```bash
gofumpt ./...
go vet ./...
go test ./...
```

Focused commands during implementation:

```bash
go test ./rp -run 'TestAuthorizationURL|TestHandleCallback|TestNew|Test.*StateStore'
go test ./rp/store/memory ./rp/store/cookie
go test ./cmd/example-rp -run 'TestNamespacedStateStore|TestIssuerShorthandStore|TestResolveRPRequest_UsesIssuerAliasStateStoreForRegisteredRuntime'
```

## Safe Completion Criteria

- `RP` production code depends only on correlation save/consume behavior.
- Existing public `rp.StateStore` and `rp/store.StateStore` users remain source-compatible unless an explicit breaking-change decision is recorded.
- Memory and cookie stores still support whole-state and caller-owned value APIs.
- Example RP behavior remains unchanged.
- No source changes are made beyond the planned implementation scope when this plan is executed.
