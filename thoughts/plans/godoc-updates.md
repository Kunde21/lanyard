# Godoc Updates Plan

## Goal

Improve godoc quality across all four public packages (`rp`, `metadata`, `jwks`, `cache`) by adding missing package docs, expanding terse constructor/option comments, fixing stale references, and adding runnable `Example*` test functions for the main entry points.

---

## 1. Package-level Documentation

### 1.1 Add `metadata/doc.go`

Create `metadata/doc.go` with a package comment covering:

- Purpose: fetches, validates, and caches OIDC Provider and OAuth 2.0 Authorization Server metadata.
- Main type: `Client` constructed with `NewClient`.
- Discovery methods: `DiscoverProvider`, `DiscoverAuthorizationServer`, `DiscoverProviderFromResource`.
- JWKS integration: `RemoteKeySet`, `RemoteKeySetFromJWKSURI`.
- Built-in caching: `Client` ships with in-memory caches for both discovery metadata and JWKS keys; callers can supply custom `CacheStore` / `jwks.CacheStore` implementations.
- Utility: `OIDCWellKnownURL`, `OAuthASWellKnownURL`, `ResolveIssuerFromWebFinger`.

Template:

```
// Package metadata fetches, validates, and caches OpenID Connect Provider
// and OAuth 2.0 Authorization Server metadata.
//
// The main entry point is [NewClient], which returns a discovery client that
// supports OIDC discovery, OAuth 2.0 authorization server metadata (RFC 8414),
// and WebFinger issuer resolution. The client caches results in memory by
// default; supply custom [CacheStore] or [jwks.CacheStore] implementations
// to override storage.
//
// Typical usage:
//
//	client := metadata.NewClient()
//	provider, err := client.DiscoverProvider(ctx, "https://accounts.google.com")
//
// For lower-level URL construction, see [OIDCWellKnownURL] and [OAuthASWellKnownURL].
package metadata
```

### 1.2 Add `jwks/doc.go`

Create `jwks/doc.go` with a package comment covering:

- Purpose: fetches and caches JSON Web Key Sets (JWKS) from a remote endpoint with stale-while-reserve semantics.
- Main type: `RemoteKeySet` constructed with `NewRemoteKeySet`.
- Key methods: `Keys(ctx)` returns all keys; `Key(ctx, kid)` returns a single key and triggers a refresh if the kid is unknown.
- Caching: built-in in-memory cache; configurable TTL, expiry delta, and minimum refresh interval.
- Cache interface: `CacheStore` for custom implementations.

Template:

```
// Package jwks fetches and caches JSON Web Key Sets from a remote JWKS endpoint.
//
// Create a key set with [NewRemoteKeySet] and look up keys with [RemoteKeySet.Keys]
// or [RemoteKeySet.Key]:
//
//	keySet, _ := jwks.NewRemoteKeySet("https://example.com/.well-known/jwks.json")
//	keys, err := keySet.Keys(ctx)
//
// Keys are cached in memory with stale-while-reuse semantics: expired entries are
// returned immediately while a background refresh runs. Supply a custom [CacheStore]
// to override the default in-memory store.
package jwks
```

### 1.3 Add `cache/doc.go`

Create `cache/doc.go` with a package comment covering:

- Purpose: generic concurrent-safe in-memory cache used internally by `metadata` and `jwks`.
- Type: `Store[V]` with `Get`, `Set`, `Delete`.
- When to use: directly when you need a simple cache; used implicitly by the other packages.

Template:

```
// Package cache provides a generic concurrent-safe in-memory cache.
//
// The [Store] type is a simple key-value cache suitable for small to medium
// workloads. It is used internally by the [metadata] and [jwks] packages for
// discovery and key-set caching.
//
// Create a store with [NewStore]:
//
//	s := cache.NewStore[string]()
//	s.Set("key", "value")
//	v, ok := s.Get("key")
package cache
```

### 1.4 Update `rp/doc.go`

The existing package doc is good. Minor refinements:

- Add a sentence about the default state store (`rp/store/memory` with 10-minute TTL).
- Mention that `NewClientCredentials` is the service-to-service entry point and shares the same `Token` type.
- Add a brief note about profiles: "Use [WithProfile] to select a behavior profile (e.g., [FAPI2SecurityProfile]) that applies secure defaults."

---

## 2. Constructor Comment Expansion

### 2.1 `rp.New` — `rp/rp.go:144-146`

Current:

```
// New creates a browser-flow relying party that is ready to generate an
// authorization URL immediately after construction.
```

Update to:

```
// New creates a browser-flow relying party that is ready to generate an
// authorization URL immediately after construction.
//
// New discovers provider metadata from issuer unless [WithProviderMetadata] or
// granular endpoint options (e.g., [WithAuthorizationEndpoint]) supply enough
// information to skip discovery. The default profile is [OIDC]; use [WithProfile]
// to select a different profile.
//
// A state store is required for callback correlation. If [WithStateStore] is not
// provided, New installs an in-memory store from rp/store/memory with a 10-minute
// TTL. For production browser flows, consider rp/store/cookie or a persistent
// implementation.
```

### 2.2 `rp.NewClientCredentials` — `rp/client_credentials.go:52-53`

Current:

```
// NewClientCredentials creates a new Client Credentials client.
```

Update to:

```
// NewClientCredentials creates an OAuth 2.0 Client Credentials grant client
// (RFC 6749 §4.4).
//
// NewClientCredentials discovers provider metadata from issuer to resolve the
// token endpoint and supported auth methods. Supply [WithClientCredentialsProviderMetadata]
// to skip discovery. The default auth method is [AuthMethodPost]; the method is
// auto-selected from the provider's token_endpoint_auth_methods_supported when
// no explicit method is set.
```

### 2.3 `metadata.NewClient` — `metadata/client.go:31-32`

Current:

```
// NewClient constructs a discovery client.
```

Update to:

```
// NewClient constructs a discovery client with built-in in-memory caches for
// provider metadata and JWKS key sets. Use options to supply custom HTTP clients,
// loggers, cache implementations, or discovery TTL.
```

### 2.4 `jwks.NewRemoteKeySet` — `jwks/remote_keyset.go:37-38`

Current:

```
// NewRemoteKeySet creates a new remote key set client.
```

Update to:

```
// NewRemoteKeySet creates a remote JWKS client that fetches keys from jwksURL
// and caches them with stale-while-reuse semantics. Expired entries are returned
// immediately while a background refresh is started. The default TTL is 1 hour;
// use [WithDefaultTTL] to override.
```

### 2.5 `cache.NewStore` — `cache/store.go:12-13`

Current:

```
// NewStore creates a new in-memory cache store.
```

Update to:

```
// NewStore creates a new concurrent-safe in-memory cache store. The zero value
// is not usable; always call NewStore.
```

---

## 3. Fix Stale or Missing Identifier Comments

### 3.1 `rp.WithClientCredentialsDPoPNonceTTL` — `rp/client_credentials_options.go:108`

**Missing comment entirely.** Add:

```
// WithClientCredentialsDPoPNonceTTL sets the TTL for cached DPoP nonces on the
// ClientCredentials client. Defaults to 5 minutes when not set.
```

### 3.2 `metadata.CacheStore` — `metadata/cache.go:5-6`

Current:

```
// CacheStore is the minimal cache interface used by the oidc package.
```

Update to:

```
// CacheStore is the minimal cache interface for storing discovery metadata.
// Implementations must be safe for concurrent use. The default implementation
// is [cache.Store].
```

### 3.3 `rp.WithStateStore` — `rp/options.go:188-191`

Current:

```
// WithStateStore sets the state store used for callback correlation and caller values.
//
// Callers typically provide implementations from `rp/store/memory` or `rp/store/cookie`.
```

Update to:

```
// WithStateStore sets the state store used for callback correlation and caller values.
//
// When not set, New installs rp/store/memory with a 10-minute TTL. For browser-based
// flows, rp/store/cookie is recommended. Callers can also implement [StateStore]
// directly for custom persistence.
```

### 3.4 `rp.WithSenderConstrain` — `rp/options.go:223-225`

Current:

```
// WithSenderConstrain sets the sender-constraining mode used for outbound requests.
// Supported values are "", "mtls", and "dpop".
```

Update to:

```
// WithSenderConstrain sets the sender-constraining mode for outbound token requests.
// Accepted values are "" (none, the default), "dpop" (RFC 9449 DPoP), and "mtls"
// (RFC 8705 mutual TLS). When set to "dpop", a [ClientKeyProvider] must also be
// configured via [WithClientKeyProvider].
```

### 3.5 `rp.WithClientCredentialsSenderConstrain` — `rp/client_credentials_options.go:83-84`

Current:

```
// WithClientCredentialsSenderConstrain sets the sender-constraining mode for DPoP or mTLS.
```

Update to:

```
// WithClientCredentialsSenderConstrain sets the sender-constraining mode for
// ClientCredentials token requests. Accepted values are "" (none), "dpop"
// (RFC 9449), and "mtls" (RFC 8705). When set to "dpop", a [ClientKeyProvider]
// must also be configured via [WithClientCredentialsKeyProvider].
```

### 3.6 `rp.WithProfile` — `rp/options.go:419-421`

Current:

```
// WithProfile sets an RP behavior profile that applies sensible defaults
// for scopes, discovery mode, and security settings. Profile defaults only
// fill fields that the caller has not already set via explicit options.
```

No change needed — this is already clear. Consider adding a one-liner example of the profile values in the doc for discoverability:

```
// Valid profiles are [OIDC], [OAuth2], [FAPI1Adv], [FAPI2SecurityProfile],
// and [FAPI2MessageSigning].
```

### 3.7 `rp.WithDiscoveryMode` — `rp/options.go:456-457`

Current:

```
// WithDiscoveryMode sets the discovery policy for provider metadata resolution.
```

Update to:

```
// WithDiscoveryMode sets the discovery policy for provider metadata resolution.
// The default ([DiscoveryAuto]) selects OIDC or OAuth 2.0 discovery based on
// the active profile. Use [DiscoveryDisabled] when all endpoints are supplied
// via [WithProviderMetadata] or granular endpoint options.
```

### 3.8 `jwks.CacheStore` — `jwks/cache.go:9-11`

Current:

```
// CacheStore is the minimal cache interface used by the jwks package.
// Implementations must be safe for concurrent use.
```

Update to:

```
// CacheStore is the cache interface for storing JWKS entries. Implementations
// must be safe for concurrent use. The default implementation is [cache.Store].
```

### 3.9 `rp.WithScopes` — `rp/options.go:53-54`

Current:

```
// WithScopes sets requested authorization scopes.
```

Update to:

```
// WithScopes sets the OAuth scopes requested during authorization. When not set,
// the default profile (OIDC) uses ["openid"]. Pass explicit scopes to override
// profile defaults.
```

### 3.10 `rp.Token.DecodeRaw` — `rp/token_source.go` (wherever Token is defined)

Current:

```
// DecodeRaw unmarshals the preserved raw token payload into target.
```

Update to:

```
// DecodeRaw unmarshals the full raw token endpoint response body into target.
// Use this to access custom fields not mapped to Token struct fields.
```

### 3.11 `rp.Token.Extra` — same file

Current:

```
// Extra returns a string field from the preserved raw token payload.
```

Update to:

```
// Extra returns a single string field from the raw token endpoint response by name.
// Returns an error if the field is not present or not a string.
```

### 3.12 `rp.DPoPNonceForEndpoint` and `rp.StoreDPoPNonce` — `rp/dpop.go`

These are exposed for advanced use. Add context:

```
// DPoPNonceForEndpoint returns the cached DPoP nonce for the given endpoint, if any.
// Most callers do not need this; the RP manages nonces automatically during
// token and userinfo requests.
```

```
// StoreDPoPNonce stores a DPoP nonce for the given endpoint. Most callers do not
// need this; the RP manages nonces automatically.
```

### 3.13 `rp.ShouldUseDPoP` — `rp/dpop.go:258-261`

Current:

```
// ShouldUseDPoP reports whether the RP is configured to use DPoP.
```

Update to:

```
// ShouldUseDPoP reports whether the RP will attach DPoP proofs to token requests.
// This returns true only when sender constraining is set to "dpop" and a
// [ClientKeyProvider] is configured.
```

---

## 4. Add Runnable Example Tests

### 4.1 `metadata/example_test.go` — already exists

**Fix variable shadowing** at line 33: rename local `metadata` to `provider`:

```go
func ExampleClient_DiscoverProvider() {
	// ...
	provider, err := client.DiscoverProvider(context.Background(), issuer)
	// ...
	fmt.Println(provider.Issuer)
}
```

**Add new examples:**

```go
func ExampleNewClient() {
	client := metadata.NewClient()
	_ = client // Use client.DiscoverProvider, DiscoverAuthorizationServer, etc.
}

func ExampleClient_DiscoverAuthorizationServer() {
	client := metadata.NewClient()
	as, err := client.DiscoverAuthorizationServer(context.Background(), "https://example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(as.Issuer)
}

func ExampleClient_RemoteKeySet() {
	client := metadata.NewClient()
	keySet, err := client.RemoteKeySet(context.Background(), "https://example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	_, _ = keySet.Keys(context.Background())
}
```

### 4.2 `jwks/example_test.go` — new file

Create `jwks/example_test.go`:

```go
package jwks_test

import (
	"context"
	"fmt"

	"github.com/Kunde21/lanyard/jwks"
)

func ExampleNewRemoteKeySet() {
	keySet, err := jwks.NewRemoteKeySet("https://example.com/.well-known/jwks.json")
	if err != nil {
		fmt.Println(err)
		return
	}
	keys, err := keySet.Keys(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("got %d keys\n", len(keys))
}
```

### 4.3 `cache/example_test.go` — new file

Create `cache/example_test.go`:

```go
package cache_test

import (
	"fmt"

	"github.com/Kunde21/lanyard/cache"
)

func ExampleNewStore() {
	s := cache.NewStore[string]()
	s.Set("key", "value")
	v, ok := s.Get("key")
	fmt.Println(v, ok)
	// Output: value true
}
```

### 4.4 `rp/example_test.go` — new file

Create `rp/example_test.go` with examples for the two main entry points:

```go
package rp_test

import (
	"fmt"

	"github.com/Kunde21/lanyard/rp"
)

func ExampleProfile() {
	fmt.Println(rp.OIDC)
	fmt.Println(rp.OAuth2)
	fmt.Println(rp.FAPI2SecurityProfile)
	// Output: ...
}

func ExampleToken_DecodeRaw() {
	tok := rp.Token{AccessToken: "at", TokenType: "Bearer"}
	var extra struct {
		Scope string `json:"scope"`
	}
	_ = tok.DecodeRaw(&extra)
	fmt.Println(tok.AccessToken)
	// Output: at
}
```

A full browser-flow example is difficult in a test because it requires an OIDC
provider. Add a comment-only example showing the construction pattern:

```go
func ExampleNew() {
	// Construct a browser-flow relying party. New discovers provider metadata
	// from the issuer automatically.
	//
	//	rp, err := rp.New(
	//		ctx,
	//		"https://accounts.google.com",
	//		"client-id",
	//		"client-secret",
	//		"https://example.com/callback",
	//		rp.WithScopes("openid", "profile", "email"),
	//	)
	//
	// Then generate an authorization URL:
	//
	//	authURL, err := rp.AuthorizationURL(ctx, w, req)
	//
	// And handle the callback:
	//
	//	result, err := rp.HandleCallback(ctx, w, req)
	fmt.Println("see package docs for the browser flow")
}
```

### 4.5 `examples/basic_discovery/main.go` — fix variable shadowing

Rename local `metadata` variable to `provider`:

```go
provider, err := client.DiscoverProvider(context.Background(), issuer)
// ...
fmt.Printf("issuer: %s\n", provider.Issuer)
```

---

## 5. Implementation Order

Do these in order to minimize review churn:

1. **Package docs** (Section 1): `cache/doc.go`, `jwks/doc.go`, `metadata/doc.go`, `rp/doc.go` update.
2. **Constructor comments** (Section 2): Expand the five constructor comments.
3. **Fix stale/missing identifier comments** (Section 3): Update all 13 items.
4. **Fix variable shadowing** (Section 4.1, 4.5): Rename `metadata` locals to `provider`.
5. **Add example tests** (Section 4.1-4.4): Create `jwks/example_test.go`, `cache/example_test.go`, `rp/example_test.go`; extend `metadata/example_test.go`.
6. **Verify**: Run `go vet ./...` and `go test ./...` to confirm everything compiles and passes.

---

## 6. Files to Create/Modify

| Action | File |
|--------|------|
| Create | `cache/doc.go` |
| Create | `jwks/doc.go` |
| Create | `metadata/doc.go` |
| Create | `jwks/example_test.go` |
| Create | `cache/example_test.go` |
| Create | `rp/example_test.go` |
| Edit | `rp/doc.go` |
| Edit | `rp/rp.go` (New comment) |
| Edit | `rp/client_credentials.go` (NewClientCredentials comment) |
| Edit | `rp/client_credentials_options.go` (DPoPNonceTTL + SenderConstrain comments) |
| Edit | `rp/options.go` (multiple option comments) |
| Edit | `rp/dpop.go` (DPoPNonceForEndpoint, StoreDPoPNonce, ShouldUseDPoP comments) |
| Edit | `metadata/cache.go` (CacheStore comment) |
| Edit | `metadata/client.go` (NewClient comment) |
| Edit | `metadata/example_test.go` (rename variable, add examples) |
| Edit | `jwks/cache.go` (CacheStore comment) |
| Edit | `jwks/remote_keyset.go` (NewRemoteKeySet comment) |
| Edit | `cache/store.go` (NewStore comment) |
| Edit | `examples/basic_discovery/main.go` (rename variable) |

Total: 6 new files, 14 edited files.
