---
date: 2026-03-22T00:00:00Z
repository: lanyard
topic: "Aggressive public API cleanup for rp"
tags: [architecture, rp, api, cleanup, breaking-change]
last_updated: 2026-03-22
---

# RP API Cleanup Proposal

## Summary

The `rp` package should move to a smaller, more intentional public API centered on two caller stories:

- browser-based OpenID Connect relying party flows
- machine-to-machine token acquisition through client credentials

The current surface area mixes those primary entrypoints with implementation-shaped exports, mutable lifecycle helpers, and a few names that do not read clearly in godoc. This proposal recommends an aggressive redesign that keeps the happy path small, merges overlapping token types, and hides exports that do not have a direct caller use case.

A key design constraint is that `TokenResponse` should be merged into `Token`. The token endpoint response used by client credentials is a strict subset of the authorization code token response, so one public token model is sufficient.

## Goals

- Make `go doc ./rp` read like a compact, intentional API
- Preserve the two core use cases: browser RP flow and client credentials
- Remove or internalize exports that exist because of implementation details rather than user needs
- Reduce naming ambiguity in constructors and options
- Unify overlapping token models into a single public `Token` type
- Clarify lifecycle expectations around discovery and mutable `RP` state

## Non-Goals

- Preserve backward compatibility for every current export
- Design a full v2 module split unless cleanup cannot be achieved within `rp`
- Add new end-user features unrelated to API shape

## Current Problems

### 1. The public surface is larger than the user story

The package exposes types such as `PARResponse`, `TokenResponse`, `DPoPProof`, `DPoPHeader`, `DPoPJWK`, and `DPoPPayload`, but the main API does not return or require most of them. In godoc, these look like supported extension points even though they are mostly implementation details.

### 2. Token modeling is split unnecessarily

`Token` is the client-credentials-facing type and `TokenResponse` is the authorization-code-facing type. In practice, the authorization code token response is a superset of the client credentials response. Splitting these types adds cognitive overhead without giving callers a better model.

### 3. Naming is misleading in godoc

`WithProviderDiscovery` and `WithClientCredentialsProviderDiscovery` accept already-discovered metadata, not a discovery strategy. The names suggest behavior, but the values are data.

### 4. Discovery and lifecycle behavior are hard to reason about

`New` performs discovery by default, `AuthorizationURL` performs discovery again, and `Discover`, `DiscoverWithJWKS`, and `DiscoverFromWebFinger` mutate the same `RP` object after construction. This makes the instance lifecycle feel less deterministic than the main user story requires.

### 5. Godoc quality is inconsistent

Several exported identifiers do not have adequate doc comments, and the package lacks a top-level narrative that helps users understand which types are core and which are advanced.

## Recommended Public API Shape

### Keep exported

These form the intended long-term public surface:

- `RP`
- `New`
- `Option`
- `WithAuthMethod`
- `WithClientKeyProvider`
- `WithClockSkew`
- `WithHTTPClient`
- `WithLogger`
- `WithOIDCClient`
- `WithProviderMetadata` (rename from `WithProviderDiscovery`)
- `WithRequirePAR`
- `WithScopes`
- `WithStateStore`
- `WithUserInfoTokenTransport`
- `CallbackResult`
- `AuthMethod` and auth method constants
- `ClientCredentials`
- `NewClientCredentials`
- `ClientCredentialsOption`
- `WithClientCredentialsAuthMethod`
- `WithClientCredentialsHTTPClient`
- `WithClientCredentialsKeyProvider`
- `WithClientCredentialsLogger`
- `WithClientCredentialsOIDCClient`
- `WithClientCredentialsProviderMetadata` (rename from `WithClientCredentialsProviderDiscovery`)
- `WithClientCredentialsScopes`
- `Token`
- `TokenSource`
- `WithTokenScopes`
- `ClientKeyProvider`
- `NewStaticClientKeyProvider`
- `StateStore`
- `StateScope`
- `CallbackCorrelation`
- `UserInfoTokenTransport` and transport constants
- sentinel errors intended for callers
- `AuthMethodError`

### Remove from the public surface

These should become unexported or move behind explicitly internal implementation boundaries:

- `TokenResponse`
- `PARResponse`
- `DPoPProof`
- `DPoPHeader`
- `DPoPJWK`
- `DPoPPayload`

### Standalone provider discovery

Users still need provider discovery outside of `RP` construction, especially when validating issuer configuration as it is being entered. That use case should not require constructing an `RP` instance or mutating long-lived RP state.

The recommended shape is a standalone function:

```go
func DiscoverProvider(ctx context.Context, issuer string, opts ...ProviderDiscoveryOption) (oidc.ProviderMetadata, error)
```

This function should:

- return the discovery payload directly to callers
- support plain issuer discovery and WebFinger-based discovery through options
- optionally preload JWKS for validation-oriented workflows
- accept HTTP/logging/client overrides through discovery-specific options

This keeps `RP` constructor-first for the browser-flow story while still supporting configuration validation and inspection as a first-class public API.

## Token Type Consolidation

### Recommendation

Merge `TokenResponse` into `Token` and use `Token` everywhere token endpoint data crosses package boundaries.

### Proposed shape

```go
type Token struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int64  `json:"expires_in"`
    IDToken      string `json:"id_token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    Scope        string `json:"scope,omitempty"`
}
```

This design keeps the public type aligned with token endpoint payloads while still serving client credentials cleanly. Client credentials callers naturally ignore `IDToken` and other fields that are absent for that grant.

### Why one type is better

- The token endpoint domain model is singular even if different grants populate different fields
- Callers do not need to learn which token type belongs to which flow
- Godoc becomes simpler
- Internal code no longer needs a separate public-shaped transport struct

### Trade-offs

- `Token` becomes slightly broader than the minimal client credentials shape
- The name `Token` now carries both protocol payload and public API meaning

These trade-offs are acceptable because the fields still belong to one conceptual object: the OAuth token endpoint response.

## Naming Changes

### Rename metadata options

Rename:

- `WithProviderDiscovery` -> `WithProviderMetadata`
- `WithClientCredentialsProviderDiscovery` -> `WithClientCredentialsProviderMetadata`

Rationale:

- the current names imply an action
- the option values are already-discovered metadata
- the new names read correctly in godoc without extra explanation

### Keep auth and transport names

`AuthMethod`, `ClientKeyProvider`, and `UserInfoTokenTransport` are understandable and should remain, though their docs should be tightened.

## RP Lifecycle Simplification

### Constructor behavior

`New` should produce a fully usable RP instance. If it performs discovery, that discovery should be authoritative for the instance unless the caller supplied provider metadata explicitly.

### Authorization start

`AuthorizationURL` should use already-resolved provider state rather than rediscovering every time. Re-discovery should only happen through a deliberate refresh path, not as a side effect of building an authorization URL.

### Callback handling

`HandleCallback` may still need provider data keyed by the stored issuer, but the API should prefer stable instance configuration over mutation-heavy rediscovery where possible.

### Advanced discovery

Advanced discovery should live behind `DiscoverProvider` options rather than mutable `RP` methods. That keeps discovery available without diluting the main `RP` lifecycle.

## Documentation Expectations

The cleanup should also treat godoc as a first-class API artifact.

### Add a package doc

The package comment should explain:

- what `rp` is for
- the two primary usage modes
- the main entrypoints for each mode
- where state store implementations live

### Add or improve docs for all remaining exports

Every remaining exported type, option, and constructor should have a doc comment that answers one question clearly:

- what it is
- when to use it
- what assumptions or constraints matter

### Document advanced behavior explicitly

If PAR, private key JWT, mTLS, or DPoP support remains caller-configurable but implementation-shaped, the docs should explain them as behavior of existing options and interfaces rather than by exposing transport structs unnecessarily.

## Migration Strategy

This cleanup shipped as an intentional breaking revision within the branch.

### Breaking changes

- remove `TokenResponse`
- remove exported `PARResponse`
- remove exported `DPoP*` structs
- rename provider metadata options
- remove exported `RP` discovery mutators in favor of standalone discovery

### Compatibility aids if needed

Short-term compatibility shims were considered during implementation, but the shipped branch does not keep the option aliases or the `TokenResponse` alias.

If the repository later wants a softer landing before a major version boundary, the following temporary measures would be acceptable:

- keep renamed option aliases temporarily with deprecation comments
- keep `TokenResponse` as a deprecated alias to `Token` for one release window
- add a standalone discovery function before removing RP-bound discovery methods

For the aggressive target state, these should be transitional only, not permanent. The branch now follows that target state for renamed options and token types.

### Final branch stance

- `WithProviderDiscovery` and `WithClientCredentialsProviderDiscovery` are removed
- `TokenResponse` is removed rather than retained as a deprecated alias
- constructor-owned provider metadata is authoritative for `AuthorizationURL`
- mutable RP discovery methods are removed from `RP`
- standalone discovery remains available through `DiscoverProvider`

## Proposed End State In Godoc

A user running `go doc ./rp` should mainly see:

- one browser-flow client type: `RP`
- one machine-to-machine client type: `ClientCredentials`
- one token model: `Token`
- one state abstraction: `StateStore`
- one auth customization seam: `AuthMethod` and `ClientKeyProvider`
- one small set of construction options

That is the right scale for this package.

## Implementation Outline

1. Add package-level documentation for `rp`
2. Rename provider metadata options
3. Merge `TokenResponse` into `Token` and update all internal call sites
4. Internalize `PARResponse`
5. Internalize `DPoP*` structs unless a real public use case emerges
6. Stop rediscovery inside `AuthorizationURL`
7. Add standalone `DiscoverProvider` with discovery-specific options
8. Remove RP-bound discovery mutators
9. Update README and examples to reflect the reduced API
10. Add release notes that describe the new stable surface

## Open Questions

- Should `Token` include only currently used response fields, or should it include other common token endpoint fields such as `refresh_token` and `scope` now to avoid another public shape change later?
- Should `DiscoverProvider` expose both issuer-based and WebFinger-based lookup through one option set, or should WebFinger validation remain a separate helper?
- Is there any real external caller for exported `DPoP*` structs today, or are they purely accidental API?

## Recommendation

Adopt the aggressive cleanup.

The package already has a strong core API, but it is diluted by implementation-shaped exports and a few naming and lifecycle mismatches. The best end state is not a larger set of advanced public types; it is a smaller surface with clearer semantics.

The highest-value design moves are:

- merge `TokenResponse` into `Token`
- rename provider metadata options
- internalize `PARResponse` and `DPoP*`
- simplify `RP` lifecycle around constructor-owned discovery
- keep standalone provider discovery available for configuration validation via `DiscoverProvider`
- invest in package docs and export comments so godoc reflects the intended API story
