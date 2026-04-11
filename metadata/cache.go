package metadata

import "time"

// CacheStore is the minimal cache interface used by the metadata package.
// Implementations must be safe for concurrent use.
type CacheStore interface {
	Get(key string) (value *CacheEntry, ok bool)
	Set(key string, value *CacheEntry)
	Delete(key string)
}

type cacheEntryKind string

const (
	cacheEntryKindProvider cacheEntryKind = "provider"
	cacheEntryKindAS       cacheEntryKind = "authorization_server"
)

// CacheEntry is an opaque cached discovery entry.
// Its fields are intentionally unexported.
type CacheEntry struct {
	kind       cacheEntryKind
	provider   Provider
	authorizer AuthorizationServer
	etag       string
	freshUntil time.Time
	fetchedAt  time.Time
}

func newProviderCacheEntry(provider Provider, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
	return &CacheEntry{
		kind:       cacheEntryKindProvider,
		provider:   provider,
		etag:       etag,
		freshUntil: freshUntil,
		fetchedAt:  fetchedAt,
	}
}

func newAuthorizationServerCacheEntry(server AuthorizationServer, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
	return &CacheEntry{
		kind:       cacheEntryKindAS,
		authorizer: server,
		etag:       etag,
		freshUntil: freshUntil,
		fetchedAt:  fetchedAt,
	}
}
