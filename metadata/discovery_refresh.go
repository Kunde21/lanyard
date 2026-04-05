package metadata

import (
	"context"
	"fmt"
	"time"
)

type discoveryFetchResult struct {
	metadata    interface{}
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

type discoveryRefreshOptions struct {
	wellKnown        func(string) (string, error)
	fetchAndValidate func(ctx context.Context, discoveryURL, etag, issuer string) (discoveryFetchResult, error)
	newEntry         func(result discoveryFetchResult) *CacheEntry
	refreshExisting  func(existing *CacheEntry, result discoveryFetchResult) *CacheEntry
	staleLogMessage  string
}

func (c *Client) refreshDiscovery(ctx context.Context, issuer, cacheKey string, existing *CacheEntry, opts discoveryRefreshOptions) (*CacheEntry, error) {
	value, err, _ := c.discoveryGroup.Do(cacheKey, func() (any, error) {
		wellKnownURL, err := opts.wellKnown(issuer)
		if err != nil {
			return nil, err
		}

		etag := ""
		if existing != nil {
			etag = existing.etag
		}

		result, err := opts.fetchAndValidate(ctx, wellKnownURL, etag, issuer)
		if err != nil {
			return nil, err
		}

		if result.notModified {
			if existing == nil {
				return nil, fmt.Errorf("received 304 without cached entry")
			}
			updated := opts.refreshExisting(existing, result)
			c.discoveryCache.Set(cacheKey, updated)
			return updated, nil
		}

		entry := opts.newEntry(result)
		c.discoveryCache.Set(cacheKey, entry)
		return entry, nil
	})
	if err != nil {
		if existing != nil {
			c.logger.DebugContext(ctx, opts.staleLogMessage, "issuer", issuer, "err", err)
		}
		return nil, err
	}

	entry, ok := value.(*CacheEntry)
	if !ok {
		return nil, fmt.Errorf("unexpected cache entry type %T", value)
	}

	return entry, nil
}
