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

// DiscoverProvider fetches, validates, and caches OIDC provider information.
func (c *Client) DiscoverProvider(ctx context.Context, issuer string) (Provider, error) {
	if _, err := validateIssuerURL(issuer); err != nil {
		return Provider{}, err
	}

	cacheKey := providerCachePrefix + issuer
	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cacheEntryKindProvider {
		if c.conformanceFreshDiscovery {
			refreshed, err := c.refreshProvider(ctx, issuer, cacheKey, entry)
			if err != nil {
				return Provider{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
			}
			return refreshed.provider, nil
		}

		if time.Now().UTC().Before(entry.freshUntil) {
			return entry.provider, nil
		}

		cached := entry.provider
		go c.refreshProvider(context.Background(), issuer, cacheKey, entry)
		return cached, nil
	}

	entry, err := c.refreshProvider(ctx, issuer, cacheKey, nil)
	if err != nil {
		return Provider{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	return entry.provider, nil
}

// DiscoverAuthorizationServer fetches, validates, and caches OAuth AS information.
func (c *Client) DiscoverAuthorizationServer(ctx context.Context, issuer string) (AuthorizationServer, error) {
	if _, err := validateIssuerURL(issuer); err != nil {
		return AuthorizationServer{}, err
	}

	cacheKey := oauthASCachePrefix + issuer
	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cacheEntryKindAS {
		if c.conformanceFreshDiscovery {
			refreshed, err := c.refreshAuthorizationServer(ctx, issuer, cacheKey, entry)
			if err != nil {
				return AuthorizationServer{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
			}
			return refreshed.authorizer, nil
		}

		if time.Now().UTC().Before(entry.freshUntil) {
			return entry.authorizer, nil
		}

		cached := entry.authorizer
		go c.refreshAuthorizationServer(context.Background(), issuer, cacheKey, entry)
		return cached, nil
	}

	entry, err := c.refreshAuthorizationServer(ctx, issuer, cacheKey, nil)
	if err != nil {
		return AuthorizationServer{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	return entry.authorizer, nil
}

func (c *Client) refreshProvider(ctx context.Context, issuer, cacheKey string, existing *CacheEntry) (*CacheEntry, error) {
	return c.refreshDiscovery(ctx, issuer, cacheKey, existing, discoveryRefreshOptions{
		wellKnown: OIDCWellKnownURL,
		fetch: func(ctx context.Context, discoveryURL, etag string) (discoveryFetchResult, error) {
			result, err := c.fetchProvider(ctx, discoveryURL, etag)
			if err != nil {
				return discoveryFetchResult{}, err
			}
			return discoveryFetchResult{
				metadata:    result.provider,
				notModified: result.notModified,
				etag:        result.etag,
				freshUntil:  result.freshUntil,
				fetchedAt:   result.fetchedAt,
			}, nil
		},
		validate: func(expectedIssuer string, md interface{}) error {
			p, ok := md.(Provider)
			if !ok {
				return fmt.Errorf("expected provider, got %T", md)
			}
			return c.validateProvider(expectedIssuer, p)
		},
		newEntry: func(md interface{}, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
			return newProviderCacheEntry(md.(Provider), etag, freshUntil, fetchedAt)
		},
		metadataFromExisting: func(entry *CacheEntry) interface{} {
			return entry.provider
		},
		staleLogMessage: "provider refresh failed; serving stale cache",
		entryKind:       cacheEntryKindProvider,
	})
}

func (c *Client) refreshAuthorizationServer(ctx context.Context, issuer, cacheKey string, existing *CacheEntry) (*CacheEntry, error) {
	return c.refreshDiscovery(ctx, issuer, cacheKey, existing, discoveryRefreshOptions{
		wellKnown: OAuthASWellKnownURL,
		fetch: func(ctx context.Context, discoveryURL, etag string) (discoveryFetchResult, error) {
			result, err := c.fetchAuthorizationServer(ctx, discoveryURL, etag)
			if err != nil {
				return discoveryFetchResult{}, err
			}
			return discoveryFetchResult{
				metadata:    result.server,
				notModified: result.notModified,
				etag:        result.etag,
				freshUntil:  result.freshUntil,
				fetchedAt:   result.fetchedAt,
			}, nil
		},
		validate: func(expectedIssuer string, md interface{}) error {
			s, ok := md.(AuthorizationServer)
			if !ok {
				return fmt.Errorf("expected authorization server, got %T", md)
			}
			return c.validateAuthorizationServer(expectedIssuer, s)
		},
		newEntry: func(md interface{}, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
			return newAuthorizationServerCacheEntry(md.(AuthorizationServer), etag, freshUntil, fetchedAt)
		},
		metadataFromExisting: func(entry *CacheEntry) interface{} {
			return entry.authorizer
		},
		staleLogMessage: "authorization server refresh failed; serving stale cache",
		entryKind:       cacheEntryKindAS,
	})
}
