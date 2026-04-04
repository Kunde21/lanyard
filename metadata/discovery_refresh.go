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
	wellKnown            func(string) (string, error)
	fetch                func(context.Context, string, string) (discoveryFetchResult, error)
	validate             func(string, interface{}) error
	newEntry             func(interface{}, string, time.Time, time.Time) *CacheEntry
	metadataFromExisting func(*CacheEntry) interface{}
	staleLogMessage      string
	entryKind            cacheEntryKind
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

		result, err := opts.fetch(ctx, wellKnownURL, etag)
		if err != nil {
			return nil, err
		}

		if result.notModified {
			if existing == nil {
				return nil, fmt.Errorf("received 304 without cached entry")
			}
			metadata := opts.metadataFromExisting(existing)
			entryETag := existing.etag
			if result.etag != "" {
				entryETag = result.etag
			}
			updated := opts.newEntry(metadata, entryETag, result.freshUntil, result.fetchedAt)
			c.discoveryCache.Set(cacheKey, updated)
			return updated, nil
		}

		if err := opts.validate(issuer, result.metadata); err != nil {
			return nil, err
		}

		entry := opts.newEntry(result.metadata, result.etag, result.freshUntil, result.fetchedAt)
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
		return nil, fmt.Errorf("unexpected %s cache entry type %T", opts.entryKind, value)
	}

	return entry, nil
}
