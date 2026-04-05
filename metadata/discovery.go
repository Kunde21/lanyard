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

func (c *Client) providerRefreshOpts() discoveryRefreshOptions {
	return discoveryRefreshOptions{
		wellKnown: OIDCWellKnownURL,
		fetchAndValidate: func(ctx context.Context, discoveryURL, etag, issuer string) (discoveryFetchResult, error) {
			p := new(Provider)
			result, err := c.fetchDiscoveryMetadata(ctx, discoveryURL, etag, p)
			if err != nil {
				return result, err
			}
			if result.notModified {
				return result, nil
			}
			if err := c.validateProvider(issuer, *p); err != nil {
				return discoveryFetchResult{}, err
			}
			return result, nil
		},
		newEntry: func(result discoveryFetchResult) *CacheEntry {
			return newProviderCacheEntry(*result.metadata.(*Provider), result.etag, result.freshUntil, result.fetchedAt)
		},
		refreshExisting: func(existing *CacheEntry, result discoveryFetchResult) *CacheEntry {
			etag := existing.etag
			if result.etag != "" {
				etag = result.etag
			}
			return newProviderCacheEntry(existing.provider, etag, result.freshUntil, result.fetchedAt)
		},
		staleLogMessage: "provider refresh failed; serving stale cache",
	}
}

func (c *Client) authorizationServerRefreshOpts() discoveryRefreshOptions {
	return discoveryRefreshOptions{
		wellKnown: OAuthASWellKnownURL,
		fetchAndValidate: func(ctx context.Context, discoveryURL, etag, issuer string) (discoveryFetchResult, error) {
			s := new(AuthorizationServer)
			result, err := c.fetchDiscoveryMetadata(ctx, discoveryURL, etag, s)
			if err != nil {
				return result, err
			}
			if result.notModified {
				return result, nil
			}
			if err := c.validateAuthorizationServer(issuer, *s); err != nil {
				return discoveryFetchResult{}, err
			}
			return result, nil
		},
		newEntry: func(result discoveryFetchResult) *CacheEntry {
			return newAuthorizationServerCacheEntry(*result.metadata.(*AuthorizationServer), result.etag, result.freshUntil, result.fetchedAt)
		},
		refreshExisting: func(existing *CacheEntry, result discoveryFetchResult) *CacheEntry {
			etag := existing.etag
			if result.etag != "" {
				etag = result.etag
			}
			return newAuthorizationServerCacheEntry(existing.authorizer, etag, result.freshUntil, result.fetchedAt)
		},
		staleLogMessage: "authorization server refresh failed; serving stale cache",
	}
}

// DiscoverProvider fetches, validates, and caches OIDC provider information.
func (c *Client) DiscoverProvider(ctx context.Context, issuer string) (Provider, error) {
	if _, err := validateIssuerURL(issuer); err != nil {
		return Provider{}, err
	}

	cacheKey := providerCachePrefix + issuer
	opts := c.providerRefreshOpts()

	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cacheEntryKindProvider {
		if c.conformanceFreshDiscovery {
			refreshed, err := c.refreshDiscovery(ctx, issuer, cacheKey, entry, opts)
			if err != nil {
				return Provider{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
			}
			return refreshed.provider, nil
		}

		if time.Now().UTC().Before(entry.freshUntil) {
			return entry.provider, nil
		}

		cached := entry.provider
		go c.refreshDiscovery(context.Background(), issuer, cacheKey, entry, opts)
		return cached, nil
	}

	entry, err := c.refreshDiscovery(ctx, issuer, cacheKey, nil, opts)
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
	opts := c.authorizationServerRefreshOpts()

	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cacheEntryKindAS {
		if c.conformanceFreshDiscovery {
			refreshed, err := c.refreshDiscovery(ctx, issuer, cacheKey, entry, opts)
			if err != nil {
				return AuthorizationServer{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
			}
			return refreshed.authorizer, nil
		}

		if time.Now().UTC().Before(entry.freshUntil) {
			return entry.authorizer, nil
		}

		cached := entry.authorizer
		go c.refreshDiscovery(context.Background(), issuer, cacheKey, entry, opts)
		return cached, nil
	}

	entry, err := c.refreshDiscovery(ctx, issuer, cacheKey, nil, opts)
	if err != nil {
		return AuthorizationServer{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	return entry.authorizer, nil
}
