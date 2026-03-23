---
type: feature
priority: medium
model: gpt-5.4
created: 2026-03-22T03:48:50Z
status: implemented
tags: [rp, state-store, sessions, cookies, gorilla-sessions, api-design]
keywords: [StateStore, StateData, NewMemoryStateStore, WithStateStore, AuthorizationURL, HandleCallback, gorilla/sessions, cookie store, consume semantics, HTTP-aware API]
patterns: [option pattern, callback correlation, request-response API, public package split, signed cookie session storage, store extensibility, RP integration tests]
---

# FEATURE-XXX: Extract RP state stores into public packages and add gorilla-sessions cookie store

## Description

Refactor RP state storage so the `rp` package keeps only the store interface and related RP integration points, while concrete store implementations move into dedicated public packages. As part of this change, provide two supported public implementations:

- `rp/store/memory` for the current in-memory behavior
- `rp/store/cookie` for a cookie-backed implementation built on `gorilla/sessions`

The store interface should be expanded beyond the current `Save`/`Load`/`Delete` model for `StateData` so it can also support save/load/delete of individual arbitrary values and user-provided opaque state. The new design must support HTTP-aware storage flows so cookie-backed implementations can persist state during authorization start and callback handling.

This ticket explicitly allows breaking changes to the current public API in favor of a cleaner long-term design.

## Context

Today, the RP package contains both the state-store abstraction and the in-memory implementation:

- `rp/state_store.go` defines `StateStore` and `StateData`
- `rp/memory_state_store.go` defines `MemoryStateStore`
- `rp/rp.go` defaults to `NewMemoryStateStore(10 * time.Minute)`
- `rp/authrequest.go` and `rp/callback.go` directly use the current store contract

The current design keeps implementation details in `rp`, which makes the package docs busier and leaves no first-class out-of-the-box alternative for browser-session-backed storage.

The goal is to make supported store choices more discoverable without cluttering `rp`, while also enabling a documented cookie-based store for normal browser RP flows.

## Requirements

### Functional Requirements

- Move concrete state store implementations out of `rp` into public packages:
  - `rp/store/memory`
  - `rp/store/cookie`
- Keep `rp` responsible only for:
  - the store abstraction
  - RP integration with that abstraction
  - configuration hooks such as `WithStateStore`
- Provide a supported `gorilla/sessions`-backed cookie store implementation.
- Expand the store abstraction to support arbitrary named values, not only RP-managed callback correlation fields.
- Support save/load/delete of individual values so callers can attach opaque state without needing RP internals to know its structure.
- Add first-class consume semantics for one-time state usage, rather than relying only on separate load/delete calls.
- Add HTTP-aware RP entrypoints so stores that need `http.Request` / `http.ResponseWriter` can participate in authorization-start and callback flows.
- Persist cookie-backed store data in the signed/encrypted session cookie itself.
- Ensure the cookie-backed implementation supports both:
  - RP callback correlation state
  - caller-provided arbitrary values
- Keep memory and cookie stores as documented, supported public APIs.

### Non-Functional Requirements

- **Security**: Cookie store must ship with secure defaults, including documented/configurable handling for `HttpOnly`, `Secure`, `SameSite`, TTL, and signing/encryption expectations.
- **API Design**: Public API may break if needed; clean design is preferred over compatibility shims.
- **Extensibility**: The store abstraction should support future caller use cases without tying itself only to current RP fields.
- **Documentation**: Add API docs plus at least one example showing cookie-backed RP usage.
- **Testing**: Include direct store tests and RP-level integration tests for the new interface/API.
- **Ergonomics**: Cookie package should use a Lanyard-focused config surface while still allowing advanced access to underlying gorilla-session settings where needed.

### Scope Boundaries

**In Scope**
- New public package split for memory and cookie stores
- Concrete `gorilla/sessions` cookie-backed implementation
- HTTP-aware RP API changes required to support cookie persistence
- Expanded store abstraction for arbitrary values
- Consume semantics
- API docs and example
- Unit tests and RP integration tests

**Out of Scope**
- Any persistence backend beyond memory and gorilla cookie sessions
- Server-side session stores
- Large-payload state/session design
- Cross-service shared session support
- Non-HTTP use cases
- Temporary compatibility shims such as keeping `rp.NewMemoryStateStore` as a deprecated forwarder

## Current State

Current implementation locations:

- `rp/state_store.go`
  - defines `StateData`
  - defines `StateStore` with:
    - `Save(state string, data StateData)`
    - `Load(state string) (StateData, bool)`
    - `Delete(state string)`
- `rp/memory_state_store.go`
  - in-memory implementation with TTL based on `CreatedAt`
- `rp/authrequest.go`
  - stores correlation data via `r.stateStore.Save(...)`
- `rp/callback.go`
  - reads with `r.stateStore.Load(state)` and then deletes with `r.stateStore.Delete(state)`
- `rp/rp.go`
  - defaults to `NewMemoryStateStore(10 * time.Minute)`
- `cmd/example-rp/main.go`
  - uses `rp.NewMemoryStateStore(...)`
  - current flow methods are context-only:
    - `AuthorizationURL(ctx)`
    - `HandleCallback(ctx, code, state)`

This shape is not sufficient for cookie persistence because the store API has no request/response access and no generic value model.

## Desired State

1. `rp` exposes a revised public store abstraction tailored for RP state handling plus caller-extensible values.
2. Memory storage lives in `rp/store/memory`.
3. Cookie-backed storage lives in `rp/store/cookie` and uses `gorilla/sessions`.
4. RP exposes HTTP-aware auth/callback methods so cookie-backed stores can read/write session state.
5. Store semantics include one-time consume behavior for callback correlation.
6. Callers can store arbitrary named values in the same state context.
7. Cookie-backed storage is documented as a supported first-class option with secure defaults.
8. Tests cover both store packages directly and RP integration against the new flow.

## Research Context

### Keywords to Search

- `StateStore` - current abstraction that needs redesign
- `StateData` - current RP correlation payload to generalize or preserve
- `NewMemoryStateStore` - current constructor that moves out of `rp`
- `WithStateStore` - option hook that likely remains but may need a new type signature
- `AuthorizationURL` - current auth-start API that lacks request/response access
- `HandleCallback` - current callback API that lacks request/response access
- `gorilla/sessions` - target library for cookie-backed implementation
- `Consume` - likely new operation to model one-time state usage
- `cmd/example-rp` - example app that demonstrates current public flow and will need updates
- `authrequest.go` - current state write path
- `callback.go` - current state read/delete path
- `rp/rp.go` - default store wiring and constructor integration

### Patterns to Investigate

- `Option` pattern in `rp/options.go` - how public configuration is added and kept stable
- State lifecycle across `AuthorizationURL` and `HandleCallback` - where API changes must land
- Current TTL handling in `rp/memory_state_store.go` - how expiry semantics should map to both stores
- Example-app usage in `cmd/example-rp/main.go` - impact of moving to HTTP-aware RP APIs
- Existing test patterns in `rp/authrequest_test.go`, `rp/callback_test.go`, and `rp/state_store_test.go`
- Package-split patterns elsewhere in the repo for small public subpackages
- How arbitrary caller values should coexist with RP-managed values without leaking implementation details
- How secure cookie defaults should be exposed while allowing advanced gorilla-session customization

### Key Decisions Made

- Use public implementation packages under `rp/store/...` - keeps `rp` docs focused while exposing supported store choices
- `rp` keeps the interface only - implementations should not live in the core RP package
- Provide a concrete cookie store - not just an extension point
- Cookie store is documented and supported - not only an example
- Expand to generic key/value storage - supports future extensibility and user-provided opaque state
- Add HTTP-aware RP methods - required for cookie-backed persistence
- Allow breaking public API changes - clean long-term design is preferred
- Cookie store should support both RP internals and caller values - keeps the model consistent across implementations
- Store actual state data in the cookie-backed session - no extra backend in this ticket
- Require secure defaults - cookie handling must not be left entirely to users
- Add a consume operation - safer one-time callback semantics
- Use a hybrid config approach - Lanyard-focused API with room for advanced gorilla-session customization
- No additional backends - scope limited to memory and gorilla cookie sessions
- No support for large payloads, cross-service sessions, or non-HTTP use cases - keeps the ticket atomic

## Success Criteria

### Automated Verification

- [ ] `go test ./...` passes
- [ ] New tests verify `rp/store/memory` behavior, including expiry and consume semantics
- [ ] New tests verify `rp/store/cookie` behavior with `gorilla/sessions`
- [ ] RP integration tests verify authorization-start persists state through the new HTTP-aware API
- [ ] RP integration tests verify callback flow consumes state exactly once
- [ ] RP integration tests verify arbitrary caller values can be saved, loaded, and deleted
- [ ] Example-related tests updated for the new public API where applicable

### Manual Verification

- [ ] Library users can configure a memory store from `rp/store/memory`
- [ ] Library users can configure a cookie store from `rp/store/cookie`
- [ ] Browser-based RP login flow works with the cookie-backed store
- [ ] Cookie configuration defaults are documented and sensible for production browser usage
- [ ] Package docs and example clearly show how to use the cookie-backed store

## Related Information

- Current files of interest:
  - `rp/state_store.go`
  - `rp/memory_state_store.go`
  - `rp/authrequest.go`
  - `rp/callback.go`
  - `rp/options.go`
  - `rp/rp.go`
  - `cmd/example-rp/main.go`
- External dependency:
  - `github.com/gorilla/sessions`

## Notes

### Open Design Questions For Research

- Exact shape of the new store abstraction:
  - whether RP-managed values and caller values share one namespace or layered APIs
  - how much typed structure remains around `StateData`
- Exact HTTP-aware RP surface:
  - whether to replace current methods entirely or introduce new explicit HTTP-first entrypoints and migrate callers
- Caller ergonomics for arbitrary state values:
  - direct store interactions only vs additional RP helpers/options
- Cookie payload modeling:
  - how values are serialized, bounded, and versioned within the session cookie
- Consume semantics:
  - whether consume is the primary API with load/delete retained secondarily, or a mixed contract

### Likely Files To Change

- `rp/state_store.go`
- `rp/options.go`
- `rp/rp.go`
- `rp/authrequest.go`
- `rp/callback.go`
- `cmd/example-rp/main.go`
- `rp/authrequest_test.go`
- `rp/callback_test.go`
- `rp/state_store_test.go`
- new package: `rp/store/memory/...`
- new package: `rp/store/cookie/...`
