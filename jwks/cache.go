package jwks

import (
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// CacheStore is the minimal cache interface used by the jwks package.
// Implementations must be safe for concurrent use.
type CacheStore interface {
	Get(key string) (value *CacheEntry, ok bool)
	Set(key string, value *CacheEntry)
	Delete(key string)
}

// CacheEntry is an opaque cached JWKS entry.
// Its fields are intentionally unexported.
type CacheEntry struct {
	keys               []jose.JSONWebKey
	etag               string
	freshUntil         time.Time
	fetchedAt          time.Time
	lastRefreshAttempt time.Time
}

func newCacheEntry(keys []jose.JSONWebKey, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
	copied := append([]jose.JSONWebKey(nil), keys...)
	return &CacheEntry{
		keys:       copied,
		etag:       etag,
		freshUntil: freshUntil,
		fetchedAt:  fetchedAt,
	}
}

func (e *CacheEntry) keysCopy() []jose.JSONWebKey {
	return append([]jose.JSONWebKey(nil), e.keys...)
}
