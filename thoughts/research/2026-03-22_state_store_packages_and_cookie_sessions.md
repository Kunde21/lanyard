---
date: 2026-03-22T11:04:15+07:00
git_commit: 06ea8adff98a59307c2afbae3f6118a1ff5ecf6b
branch: master
repository: lanyard
topic: "Extract RP state stores into public packages and add gorilla-sessions cookie store"
tags: [research, codebase, rp, state-store, sessions, cookies]
last_updated: 2026-03-22
---

## Ticket Synopsis

This ticket proposes a breaking redesign of RP state storage. The `rp` package should keep only the abstraction and RP integration points, while the current in-memory implementation moves to `rp/store/memory` and a new `gorilla/sessions`-backed implementation is added in `rp/store/cookie`. The new design must support arbitrary caller values, explicit consume semantics, and HTTP-aware auth/callback entrypoints so cookie-backed state can be persisted and consumed through normal browser flows.

## Summary

The current code couples the state abstraction, the default memory implementation, and RP flow APIs tightly inside `rp`. `StateStore` only supports `Save`/`Load`/`Delete` over a typed `StateData` payload, `AuthorizationURL` and `HandleCallback` are context-only methods with no request/response access, and one-time use is enforced in `HandleCallback` by calling `Load` followed by `Delete` rather than by the store itself. This shape works for the current in-memory map but does not support cookie persistence or caller-owned arbitrary values. The main blast radius is concentrated in `rp/state_store.go:17`, `rp/memory_state_store.go:8`, `rp/authrequest.go:14`, `rp/callback.go:15`, `rp/options.go:76`, `rp/rp.go:102`, and `cmd/example-rp/main.go:19`.

## Detailed Findings

### Current Store Contract

- `StateData` is a typed RP-owned correlation payload containing nonce, PKCE verifier, timestamps, issuer, PAR fields, and userinfo transport configuration in `rp/state_store.go:5`.
- `StateStore` currently exposes only `Save`, `Load`, and `Delete` over that typed payload in `rp/state_store.go:17`.
- The concrete in-memory implementation also lives in `rp`, via `MemoryStateStore` and `NewMemoryStateStore`, in `rp/memory_state_store.go:8`.
- `RP.New` silently defaults to the in-package memory store when no custom store is supplied in `rp/rp.go:102`.
- `WithStateStore` is the existing configuration seam, but it only accepts the narrow current interface in `rp/options.go:76`.

### State Lifecycle Across RP Flow

- `AuthorizationURL` generates `state`, `nonce`, and PKCE material, then persists state before returning the redirect URL in `rp/authrequest.go:14`.
- In the PAR branch, the stored payload includes `Expiry`, `RequestURI`, and `UsedPAR` in `rp/authrequest.go:55`.
- In the non-PAR branch, the stored payload includes only the basic RP correlation fields in `rp/authrequest.go:80`.
- `HandleCallback` validates the input, loads the stored payload, and then immediately deletes it in `rp/callback.go:15`.
- The callback path depends on stored `Issuer`, `CodeVerifier`, `Nonce`, and `UserInfoTokenTransport` to finish discovery, token exchange, ID token validation, and userinfo fetch in `rp/callback.go:29`, `rp/callback.go:48`, `rp/callback.go:59`, and `rp/callback.go:66`.

### Expiry And Consume Semantics

- The memory store expires entries only by `CreatedAt + ttl` in `rp/memory_state_store.go:44`.
- The PAR-specific `Expiry` field is written into `StateData` but is not consulted by the memory store, so provider-supplied PAR lifetime is currently informational only across `rp/authrequest.go:55` and `rp/memory_state_store.go:44`.
- One-time use is not part of the store contract; it is implemented procedurally in `HandleCallback` by calling `Load` and then `Delete` in `rp/callback.go:23` and `rp/callback.go:27`.
- Existing tests mirror this contract: save/load/delete and TTL expiry are tested in `rp/state_store_test.go:10`, while auth and callback tests only assert state persistence and invalid-state behavior against the current API in `rp/authrequest_test.go:13` and `rp/callback_test.go:18`.

### API Surface Constraints For Cookie Storage

- Both public RP flow methods are context-only today, with signatures `AuthorizationURL(ctx)` and `HandleCallback(ctx, code, state)` in `rp/authrequest.go:14` and `rp/callback.go:15`.
- The example app encodes the same context-only contract in its `flowHandler` interface in `cmd/example-rp/main.go:19`.
- The example app also shares a global in-memory store created with `rp.NewMemoryStateStore` in `cmd/example-rp/main.go:24` and injected through `rp.WithStateStore` in `cmd/example-rp/main.go:85`.
- Because no request or response writer reaches the store during login or callback, a cookie-backed implementation cannot persist or clear browser state without new HTTP-aware RP entrypoints.

### Package Split And Configuration Patterns

- Functional options are the dominant public API pattern across packages: `rp/options.go:12`, `oidc/options.go:11`, and `jwks/options.go:9` all use `type Option func(...)` and nil-safe setters.
- The codebase already favors focused public packages such as `oidc`, `jwks`, and `rp`, which aligns with moving implementations into `rp/store/...` while leaving the core RP package focused on abstractions and flow orchestration, as reflected in `README.md:173`.
- The current README still documents an outdated RP API example that calls `AuthorizationURL(ctx, "openid profile email", "state-value")` in `README.md:111`, so the ticket will need documentation cleanup in addition to any new cookie-store example.

### Test And Example Impact

- `rp/rp_test.go:44` asserts that `WithStateStore` preserves an injected custom memory store, so test coverage already treats store injection as a first-class extension point.
- `rp/state_store_test.go:10` is tightly coupled to `NewMemoryStateStore` living in `rp`, so these tests will need to move or be split alongside the package extraction.
- `cmd/example-rp/main_test.go:14` defines a stub flow interface matching the current context-only API, so example tests will need updating if HTTP-aware methods replace or supplement the existing flow methods.
- The example handlers call `AuthorizationURL` and `HandleCallback` directly from HTTP handlers in `cmd/example-rp/main.go:126`, `cmd/example-rp/main.go:157`, `cmd/example-rp/main.go:195`, and `cmd/example-rp/main.go:225`, which is exactly where request/response-aware replacements would be threaded in.

### Browser And Cookie-Oriented Patterns

- The conformance harness already models browser state with a cookie jar in `conformance/harness/execute.go:45` and attaches it to the front-channel client in `conformance/harness/execute.go:50`.
- Front-channel login execution happens through ordinary HTTP requests into `/login` and callback-oriented flows in `conformance/harness/execute.go:248`, `conformance/harness/execute.go:252`, and `conformance/harness/execute.go:296`.
- That means a cookie-backed RP state store fits the existing end-to-end testing model naturally: the harness already preserves cookies across redirects and repeated front-channel requests.
- There is currently no `gorilla/sessions` usage in the Go codebase, so the cookie store will introduce a new dependency and API surface rather than conforming to an existing in-repo session abstraction.

## Code References

- `rp/state_store.go:5` - Current `StateData` definition and all RP-managed fields.
- `rp/state_store.go:17` - Current `StateStore` interface with only `Save`/`Load`/`Delete`.
- `rp/memory_state_store.go:8` - In-memory implementation that still lives in `rp`.
- `rp/memory_state_store.go:44` - TTL enforcement based only on `CreatedAt + ttl`.
- `rp/authrequest.go:14` - Auth-start API surface that currently lacks HTTP request/response access.
- `rp/authrequest.go:55` - PAR branch storing `Expiry`, `RequestURI`, and `UsedPAR`.
- `rp/authrequest.go:80` - Non-PAR branch storing the normal callback correlation payload.
- `rp/callback.go:15` - Callback API surface that currently lacks HTTP request/response access.
- `rp/callback.go:23` - Callback load path for stored state.
- `rp/callback.go:27` - Manual delete-based one-time use behavior.
- `rp/options.go:76` - `WithStateStore` option hook that stays central to configuration.
- `rp/rp.go:102` - Default wiring to `NewMemoryStateStore(10 * time.Minute)`.
- `rp/par.go:18` - PAR response shape carrying `request_uri` and `expires_in`.
- `cmd/example-rp/main.go:19` - Example flow interface encoding the current public RP method shapes.
- `cmd/example-rp/main.go:24` - Example app global dependency on `rp.NewMemoryStateStore`.
- `cmd/example-rp/main.go:85` - Example injection through `rp.WithStateStore`.
- `cmd/example-rp/main.go:126` - Login handler calling `AuthorizationURL` from an HTTP handler.
- `cmd/example-rp/main.go:195` - Callback handler calling `HandleCallback` from an HTTP handler.
- `rp/state_store_test.go:10` - Direct memory store tests tied to current package location.
- `rp/authrequest_test.go:77` - Auth request test verifying state is persisted for later callback use.
- `rp/callback_test.go:94` - Callback tests constructing stored `StateData` directly.
- `rp/rp_test.go:48` - Constructor test using a custom injected memory store.
- `README.md:19` - Public docs still describe only in-memory state management.
- `README.md:111` - README RP example is out of sync with the current `AuthorizationURL` signature.
- `oidc/options.go:11` - Cross-package option pattern reference.
- `jwks/options.go:9` - Cross-package option pattern reference.
- `conformance/harness/execute.go:45` - Browser-like cookie jar setup in test harness.
- `conformance/harness/execute.go:248` - Front-channel trigger entrypoint relevant to cookie-backed browser flows.

## Architecture Insights

The RP state store is currently designed around a single RP-owned payload type and a storage backend that is invisible to HTTP. That keeps the in-memory implementation simple, but it bakes three assumptions into the public API: state is only for RP callback correlation, state lifetime is store-global rather than per entry, and state consumption is orchestrated by RP code instead of the store. The ticket pushes all three boundaries.

A clean redesign likely needs two separations:

1. The `rp` package continues to own RP flow orchestration and whichever typed correlation data it needs.
2. Concrete storage implementations move into `rp/store/...`, where request/response-aware implementations can manage persistence details.

The least disruptive design path appears to be keeping `WithStateStore` as the stable configuration hook while expanding the store contract to support:

- atomic consume behavior for one-time state use,
- arbitrary named values alongside RP-managed data,
- and an HTTP-aware path for stores that must read or write cookies during auth start and callback.

The existing example app and harness suggest that HTTP-aware RP entrypoints should sit at the boundary where handlers already call into `AuthorizationURL` and `HandleCallback`, rather than trying to hide request/response access inside unrelated lower layers.

## Historical Context (from thoughts/)

The ticket itself is the main architectural source for this topic:

- `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md:16` - States the package split goal: interface stays in `rp`, implementations move to `rp/store/memory` and `rp/store/cookie`.
- `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md:50` - Requires arbitrary named values, not only RP-managed correlation fields.
- `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md:52` - Requires first-class consume semantics.
- `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md:53` - Requires HTTP-aware RP entrypoints.
- `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md:62` - Defines cookie-store security defaults and configuration expectations.
- `thoughts/tickets/feature_state_store_packages_and_cookie_sessions.md:155` - Records the explicit decision to move concrete stores under `rp/store/...`.

Related prior research provides useful background on why session storage now matters in RP flows:

- `thoughts/research/2026-02-22_basic_rp_conformance_profile.md:32` - Earlier RP research identified session management as missing foundational work.
- `thoughts/research/2026-02-22_basic_rp_conformance_profile.md:34` - Earlier implementation guidance expected RP login and callback handlers to own stateful browser flow orchestration.
- `thoughts/research/2026-02-22_basic_rp_conformance_profile.md:163` - Earlier conformance research treated in-memory session storage as sufficient for the first implementation, which explains the current shape now being generalized.

## Related Research

- `thoughts/research/2026-02-22_basic_rp_conformance_profile.md`
- `thoughts/research/2026-02-23_conformance_suite_execution_automation.md`
- `thoughts/research/2026-02-22_openid_conformance_local_setup.md`

## Open Questions

- Should the new store API expose RP correlation data and caller values through one shared namespace or through layered methods?
- Should the HTTP-aware RP methods replace `AuthorizationURL` and `HandleCallback`, or should they be added as explicit HTTP-first variants?
- How should arbitrary values be serialized and bounded inside the cookie-backed session payload?
- Should consume become the primary callback-state API, with plain load/delete retained only for secondary use cases?
