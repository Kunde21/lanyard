// Package cache provides a generic concurrency-safe in-memory cache store.
//
// The primary type is [Store], a generic map-based cache that satisfies the
// cache interfaces used by higher-level packages:
//
//   - *jwks.CacheEntry satisfies jwks.CacheStore for JWKS key caching
//   - *metadata.CacheEntry satisfies metadata.CacheStore for discovery caching
//
// The default in-memory caches in the metadata and jwks packages are both
// backed by cache.Store. Most callers do not need to interact with this package
// directly; it is exported for callers who want to share a single cache instance
// across multiple metadata.Client or *jwks.RemoteKeySet instances, or who
// need to implement custom cache eviction.
package cache
