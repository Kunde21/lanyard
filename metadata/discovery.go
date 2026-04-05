package metadata

import (
	"context"
	"fmt"
	"time"
)

const (
	providerCachePrefix = "oidc:provider:v1:"
	oauthASCachePrefix  = "oidc:authz-server:v1:"
)

type discoveryConfig struct {
	cachePrefix   string
	cacheKind     cacheEntryKind
	buildOpts     func(c *Client) discoveryRefreshOptions
	metadataEntry func(entry *CacheEntry) interface{}
}

var providerDiscoveryConfig = discoveryConfig{
	cachePrefix: providerCachePrefix,
	cacheKind:   cacheEntryKindProvider,
	buildOpts: func(c *Client) discoveryRefreshOptions {
		return discoveryRefreshOptions{
			wellKnown: OIDCWellKnownURL,
			fetch: func(ctx context.Context, discoveryURL, etag string) (discoveryFetchResult, error) {
				return c.fetchDiscoveryMetadata(ctx, discoveryURL, etag, new(Provider))
			},
			validate: func(expectedIssuer string, md interface{}) error {
				p, ok := md.(*Provider)
				if !ok {
					return fmt.Errorf("expected *Provider, got %T", md)
				}
				return c.validateProvider(expectedIssuer, *p)
			},
			newEntry: func(md interface{}, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
				return newProviderCacheEntry(*md.(*Provider), etag, freshUntil, fetchedAt)
			},
			metadataFromExisting: func(entry *CacheEntry) interface{} {
				p := entry.provider
				return &p
			},
			staleLogMessage: "provider refresh failed; serving stale cache",
			entryKind:       cacheEntryKindProvider,
		}
	},
	metadataEntry: func(entry *CacheEntry) interface{} {
		return entry.provider
	},
}

var asDiscoveryConfig = discoveryConfig{
	cachePrefix: oauthASCachePrefix,
	cacheKind:   cacheEntryKindAS,
	buildOpts: func(c *Client) discoveryRefreshOptions {
		return discoveryRefreshOptions{
			wellKnown: OAuthASWellKnownURL,
			fetch: func(ctx context.Context, discoveryURL, etag string) (discoveryFetchResult, error) {
				return c.fetchDiscoveryMetadata(ctx, discoveryURL, etag, new(AuthorizationServer))
			},
			validate: func(expectedIssuer string, md interface{}) error {
				s, ok := md.(*AuthorizationServer)
				if !ok {
					return fmt.Errorf("expected *AuthorizationServer, got %T", md)
				}
				return c.validateAuthorizationServer(expectedIssuer, *s)
			},
			newEntry: func(md interface{}, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
				return newAuthorizationServerCacheEntry(*md.(*AuthorizationServer), etag, freshUntil, fetchedAt)
			},
			metadataFromExisting: func(entry *CacheEntry) interface{} {
				s := entry.authorizer
				return &s
			},
			staleLogMessage: "authorization server refresh failed; serving stale cache",
			entryKind:       cacheEntryKindAS,
		}
	},
	metadataEntry: func(entry *CacheEntry) interface{} {
		return entry.authorizer
	},
}

func (c *Client) discover(ctx context.Context, issuer string, cfg discoveryConfig) (interface{}, error) {
	if _, err := validateIssuerURL(issuer); err != nil {
		return nil, err
	}

	cacheKey := cfg.cachePrefix + issuer
	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cfg.cacheKind {
		if c.conformanceFreshDiscovery {
			refreshed, err := c.refreshDiscovery(ctx, issuer, cacheKey, entry, cfg.buildOpts(c))
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
			}
			return cfg.metadataEntry(refreshed), nil
		}

		if time.Now().UTC().Before(entry.freshUntil) {
			return cfg.metadataEntry(entry), nil
		}

		cached := cfg.metadataEntry(entry)
		go c.refreshDiscovery(context.Background(), issuer, cacheKey, entry, cfg.buildOpts(c))
		return cached, nil
	}

	entry, err := c.refreshDiscovery(ctx, issuer, cacheKey, nil, cfg.buildOpts(c))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	return cfg.metadataEntry(entry), nil
}

// DiscoverProvider fetches, validates, and caches OIDC provider information.
func (c *Client) DiscoverProvider(ctx context.Context, issuer string) (Provider, error) {
	md, err := c.discover(ctx, issuer, providerDiscoveryConfig)
	if err != nil {
		return Provider{}, err
	}
	return md.(Provider), nil
}

// DiscoverAuthorizationServer fetches, validates, and caches OAuth AS information.
func (c *Client) DiscoverAuthorizationServer(ctx context.Context, issuer string) (AuthorizationServer, error) {
	md, err := c.discover(ctx, issuer, asDiscoveryConfig)
	if err != nil {
		return AuthorizationServer{}, err
	}
	return md.(AuthorizationServer), nil
}
