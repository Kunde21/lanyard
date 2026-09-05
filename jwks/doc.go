// Package jwks provides remote JSON Web Key Set (JWKS) fetching and caching.
//
// The main entry point is [NewRemoteKeySet], which returns a [*RemoteKeySet]
// that fetches keys from a JWKS endpoint. Keys are cached in memory and
// refreshed using stale-while-refresh semantics: cached keys are returned
// immediately when fresh, and stale entries trigger a background refresh so
// callers never block on a cache miss after the initial fetch.
//
// # Key lookup
//
// Use [RemoteKeySet.Keys] to retrieve all current keys, or [RemoteKeySet.Key]
// to look up a specific key by its "kid" header. When a key ID is not found
// in the cached set, the RemoteKeySet performs an immediate refresh before
// reporting a [KeyNotFoundError].
//
// # Caching
//
// A default in-memory [CacheStore] is installed automatically. Replace it with
// [WithCache] if you need a custom implementation. The cache stores one entry
// per JWKS URL, keyed by URL.
//
// # When to use this package directly
//
// Most callers should use the metadata or rp packages, which construct a
// RemoteKeySet as part of provider discovery. Use this package directly when
// you have a JWKS URL and need key retrieval without OIDC discovery.
package jwks
