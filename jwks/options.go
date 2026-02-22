package jwks

import (
	"log/slog"
	"net/http"
	"time"
)

// Option configures a RemoteKeySet.
type Option func(*RemoteKeySet)

// WithHTTPClient configures the HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(r *RemoteKeySet) {
		if client != nil {
			r.httpClient = client
		}
	}
}

// WithLogger configures the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(r *RemoteKeySet) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithCache configures the cache implementation.
func WithCache(store CacheStore) Option {
	return func(r *RemoteKeySet) {
		if store != nil {
			r.cache = store
		}
	}
}

// WithDefaultTTL configures the fallback TTL when cache headers are absent.
func WithDefaultTTL(ttl time.Duration) Option {
	return func(r *RemoteKeySet) {
		if ttl > 0 {
			r.defaultTTL = ttl
		}
	}
}

// WithExpiryDelta configures a small delta used to proactively refresh near-expiry keys.
func WithExpiryDelta(delta time.Duration) Option {
	return func(r *RemoteKeySet) {
		if delta >= 0 {
			r.expiryDelta = delta
		}
	}
}

// WithMinRefreshInterval configures minimum time between unknown-kid refreshes.
func WithMinRefreshInterval(interval time.Duration) Option {
	return func(r *RemoteKeySet) {
		if interval >= 0 {
			r.minRefreshInterval = interval
		}
	}
}
