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
	value, err, _ := c.discoveryGroup.Do(cacheKey, func() (any, error) {
		discoveryURL, err := OIDCWellKnownURL(issuer)
		if err != nil {
			return nil, err
		}

		etag := ""
		if existing != nil {
			etag = existing.etag
		}

		result, err := c.fetchProviderMetadata(ctx, discoveryURL, etag)
		if err != nil {
			return nil, err
		}

		if result.notModified {
			if existing == nil {
				return nil, fmt.Errorf("received 304 without cached entry")
			}
			updated := newProviderCacheEntry(existing.provider, existing.etag, result.freshUntil, result.fetchedAt)
			if result.etag != "" {
				updated.etag = result.etag
			}
			c.discoveryCache.Set(cacheKey, updated)
			return updated, nil
		}

		if err := c.validateProviderMetadata(issuer, result.metadata); err != nil {
			return nil, err
		}

		entry := newProviderCacheEntry(result.metadata, result.etag, result.freshUntil, result.fetchedAt)
		c.discoveryCache.Set(cacheKey, entry)
		return entry, nil
	})
	if err != nil {
		if existing != nil {
			c.logger.DebugContext(ctx, "provider refresh failed; serving stale cache", "issuer", issuer, "err", err)
		}
		return nil, err
	}

	entry, ok := value.(*CacheEntry)
	if !ok {
		return nil, fmt.Errorf("unexpected provider cache entry type %T", value)
	}

	return entry, nil
}

func (c *Client) refreshAuthorizationServer(ctx context.Context, issuer, cacheKey string, existing *CacheEntry) (*CacheEntry, error) {
	value, err, _ := c.discoveryGroup.Do(cacheKey, func() (any, error) {
		discoveryURL, err := OAuthASWellKnownURL(issuer)
		if err != nil {
			return nil, err
		}

		etag := ""
		if existing != nil {
			etag = existing.etag
		}

		result, err := c.fetchAuthorizationServerMetadata(ctx, discoveryURL, etag)
		if err != nil {
			return nil, err
		}

		if result.notModified {
			if existing == nil {
				return nil, fmt.Errorf("received 304 without cached entry")
			}
			updated := newAuthorizationServerCacheEntry(existing.authorizer, existing.etag, result.freshUntil, result.fetchedAt)
			if result.etag != "" {
				updated.etag = result.etag
			}
			c.discoveryCache.Set(cacheKey, updated)
			return updated, nil
		}

		if err := c.validateAuthorizationServerMetadata(issuer, result.metadata); err != nil {
			return nil, err
		}

		entry := newAuthorizationServerCacheEntry(result.metadata, result.etag, result.freshUntil, result.fetchedAt)
		c.discoveryCache.Set(cacheKey, entry)
		return entry, nil
	})
	if err != nil {
		if existing != nil {
			c.logger.DebugContext(ctx, "authorization server refresh failed; serving stale cache", "issuer", issuer, "err", err)
		}
		return nil, err
	}

	entry, ok := value.(*CacheEntry)
	if !ok {
		return nil, fmt.Errorf("unexpected authorization server cache entry type %T", value)
	}

	return entry, nil
}
