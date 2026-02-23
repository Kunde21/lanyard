package oidc

import (
	"context"
	"fmt"
	"time"
)

const (
	providerCachePrefix = "oidc:provider-metadata:v1:"
	oauthASCachePrefix  = "oidc:authz-server-metadata:v1:"
)

// DiscoverProvider fetches, validates, and caches OIDC provider metadata.
func (c *Client) DiscoverProvider(ctx context.Context, issuer string) (ProviderMetadata, error) {
	if _, err := validateIssuerURL(issuer); err != nil {
		return ProviderMetadata{}, err
	}

	cacheKey := providerCachePrefix + issuer
	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cacheEntryKindProvider {
		if time.Now().UTC().Before(entry.freshUntil) {
			return entry.provider, nil
		}

		cached := entry.provider
		go c.refreshProvider(context.Background(), issuer, cacheKey, entry)
		return cached, nil
	}

	entry, err := c.refreshProvider(ctx, issuer, cacheKey, nil)
	if err != nil {
		return ProviderMetadata{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	return entry.provider, nil
}

// DiscoverAuthorizationServer fetches, validates, and caches OAuth AS metadata.
func (c *Client) DiscoverAuthorizationServer(ctx context.Context, issuer string) (AuthorizationServerMetadata, error) {
	if _, err := validateIssuerURL(issuer); err != nil {
		return AuthorizationServerMetadata{}, err
	}

	cacheKey := oauthASCachePrefix + issuer
	if entry, ok := c.discoveryCache.Get(cacheKey); ok && entry != nil && entry.kind == cacheEntryKindAS {
		if time.Now().UTC().Before(entry.freshUntil) {
			return entry.authorizer, nil
		}

		cached := entry.authorizer
		go c.refreshAuthorizationServer(context.Background(), issuer, cacheKey, entry)
		return cached, nil
	}

	entry, err := c.refreshAuthorizationServer(ctx, issuer, cacheKey, nil)
	if err != nil {
		return AuthorizationServerMetadata{}, fmt.Errorf("%w: %w", ErrDiscoveryFailed, err)
	}

	return entry.authorizer, nil
}

func (c *Client) refreshProvider(ctx context.Context, issuer, cacheKey string, existing *CacheEntry) (*CacheEntry, error) {
	return c.refreshDiscovery(ctx, issuer, cacheKey, existing, discoveryRefreshOptions{
		wellKnown: OIDCWellKnownURL,
		fetch: func(ctx context.Context, discoveryURL, etag string) (discoveryFetchResult, error) {
			result, err := c.fetchProviderMetadata(ctx, discoveryURL, etag)
			if err != nil {
				return discoveryFetchResult{}, err
			}
			return discoveryFetchResult{
				metadata:    result.metadata,
				notModified: result.notModified,
				etag:        result.etag,
				freshUntil:  result.freshUntil,
				fetchedAt:   result.fetchedAt,
			}, nil
		},
		validate: func(expectedIssuer string, metadata interface{}) error {
			md, ok := metadata.(ProviderMetadata)
			if !ok {
				return fmt.Errorf("expected provider metadata, got %T", metadata)
			}
			return c.validateProviderMetadata(expectedIssuer, md)
		},
		newEntry: func(metadata interface{}, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
			return newProviderCacheEntry(metadata.(ProviderMetadata), etag, freshUntil, fetchedAt)
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
			result, err := c.fetchAuthorizationServerMetadata(ctx, discoveryURL, etag)
			if err != nil {
				return discoveryFetchResult{}, err
			}
			return discoveryFetchResult{
				metadata:    result.metadata,
				notModified: result.notModified,
				etag:        result.etag,
				freshUntil:  result.freshUntil,
				fetchedAt:   result.fetchedAt,
			}, nil
		},
		validate: func(expectedIssuer string, metadata interface{}) error {
			md, ok := metadata.(AuthorizationServerMetadata)
			if !ok {
				return fmt.Errorf("expected authorization server metadata, got %T", metadata)
			}
			return c.validateAuthorizationServerMetadata(expectedIssuer, md)
		},
		newEntry: func(metadata interface{}, etag string, freshUntil, fetchedAt time.Time) *CacheEntry {
			return newAuthorizationServerCacheEntry(metadata.(AuthorizationServerMetadata), etag, freshUntil, fetchedAt)
		},
		metadataFromExisting: func(entry *CacheEntry) interface{} {
			return entry.authorizer
		},
		staleLogMessage: "authorization server refresh failed; serving stale cache",
		entryKind:       cacheEntryKindAS,
	})
}
