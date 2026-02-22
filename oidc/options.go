package oidc

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/jwks"
)

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithDiscoveryCache sets the cache used for discovery metadata.
func WithDiscoveryCache(store CacheStore) Option {
	return func(c *Client) {
		if store != nil {
			c.discoveryCache = store
		}
	}
}

// WithJWKSCache sets the cache used for remote JWKS sets.
func WithJWKSCache(store jwks.CacheStore) Option {
	return func(c *Client) {
		if store != nil {
			c.jwksCache = store
		}
	}
}

// WithIssuerTrailingSlashTolerance enables tolerant issuer matching for one trailing slash mismatch.
func WithIssuerTrailingSlashTolerance(tolerate bool) Option {
	return func(c *Client) {
		c.issuerTrailingSlashTolerance = tolerate
	}
}

// WithDefaultDiscoveryTTL sets the fallback discovery TTL.
func WithDefaultDiscoveryTTL(ttl time.Duration) Option {
	return func(c *Client) {
		if ttl > 0 {
			c.defaultDiscoveryTTL = ttl
		}
	}
}
