package jwks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Kunde21/lanyard/cache"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"
)

const (
	defaultTTL           = time.Hour
	defaultExpiryDelta   = 30 * time.Second
	defaultMinRefreshGap = 5 * time.Second
	cacheKeyPrefix       = "jwks:keyset:v1:"
)

// RemoteKeySet fetches and caches a remote JWKS endpoint.
type RemoteKeySet struct {
	jwksURL            string
	httpClient         *http.Client
	logger             *slog.Logger
	cache              CacheStore
	group              singleflight.Group
	defaultTTL         time.Duration
	expiryDelta        time.Duration
	minRefreshInterval time.Duration
}

// NewRemoteKeySet creates a new remote key set client.
func NewRemoteKeySet(jwksURL string, opts ...Option) (*RemoteKeySet, error) {
	u, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("invalid jwks URL: %w", err)
	}
	if !u.IsAbs() || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("invalid jwks URL %q: must be absolute https URL", jwksURL)
	}

	r := &RemoteKeySet{
		jwksURL:            jwksURL,
		httpClient:         http.DefaultClient,
		logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:              cache.NewStore[*CacheEntry](),
		defaultTTL:         defaultTTL,
		expiryDelta:        defaultExpiryDelta,
		minRefreshInterval: defaultMinRefreshGap,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r, nil
}

func (r *RemoteKeySet) cacheKey() string {
	return cacheKeyPrefix + r.jwksURL
}

func (r *RemoteKeySet) cachedEntry() (*CacheEntry, bool) {
	entry, ok := r.cache.Get(r.cacheKey())
	if !ok || entry == nil {
		return nil, false
	}
	return entry, true
}

func (r *RemoteKeySet) markRefreshAttempt(entry *CacheEntry) bool {
	if entry == nil {
		return true
	}
	now := time.Now().UTC()
	if !entry.lastRefreshAttempt.IsZero() && now.Sub(entry.lastRefreshAttempt) < r.minRefreshInterval {
		return false
	}
	entry.lastRefreshAttempt = now
	r.cache.Set(r.cacheKey(), entry)
	return true
}

// Keys returns keys from cache, refreshing stale or missing values as needed.
func (r *RemoteKeySet) Keys(ctx context.Context) ([]jose.JSONWebKey, error) {
	key := r.cacheKey()
	entry, ok := r.cachedEntry()
	if ok {
		if time.Now().UTC().Add(r.expiryDelta).Before(entry.freshUntil) {
			return entry.keysCopy(), nil
		}

		keys := entry.keysCopy()
		go func(existing *CacheEntry) {
			_, err := r.refresh(context.Background(), key, existing)
			if err != nil {
				r.logger.DebugContext(ctx, "jwks background refresh failed", "jwks_url", r.jwksURL, "err", err)
			}
		}(entry)
		return keys, nil
	}

	entry, err := r.refresh(ctx, key, nil)
	if err != nil {
		return nil, err
	}

	return entry.keysCopy(), nil
}

// Key returns a specific key by kid.
func (r *RemoteKeySet) Key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	keys, err := r.Keys(ctx)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if key, ok := findKey(keys, kid); ok {
		return key, nil
	}

	entry, _ := r.cachedEntry()
	if !r.markRefreshAttempt(entry) {
		return jose.JSONWebKey{}, &KeyNotFoundError{JWKSURL: r.jwksURL, KID: kid}
	}

	refreshed, refreshErr := r.refresh(ctx, r.cacheKey(), entry)
	if refreshErr != nil {
		if entry != nil && len(entry.keys) > 0 {
			r.logger.DebugContext(ctx, "jwks refresh failed for unknown kid", "jwks_url", r.jwksURL, "kid", kid, "err", refreshErr)
			return jose.JSONWebKey{}, &KeyNotFoundError{JWKSURL: r.jwksURL, KID: kid}
		}
		return jose.JSONWebKey{}, refreshErr
	}

	if key, found := findKey(refreshed.keys, kid); found {
		return key, nil
	}

	return jose.JSONWebKey{}, &KeyNotFoundError{JWKSURL: r.jwksURL, KID: kid}
}

func findKey(keys []jose.JSONWebKey, kid string) (jose.JSONWebKey, bool) {
	for _, key := range keys {
		if key.KeyID == kid {
			return key, true
		}
	}

	return jose.JSONWebKey{}, false
}

func (r *RemoteKeySet) refresh(ctx context.Context, cacheKey string, existing *CacheEntry) (*CacheEntry, error) {
	value, err, _ := r.group.Do(cacheKey, func() (any, error) {
		etag := ""
		if existing != nil {
			etag = existing.etag
		}

		result, err := r.fetchJWKS(ctx, etag)
		if err != nil {
			return nil, err
		}

		if result.NotModified {
			if existing == nil {
				return nil, &FetchError{JWKSURL: r.jwksURL, Err: fmt.Errorf("received 304 without cached entry")}
			}
			updated := newCacheEntry(existing.keysCopy(), existing.etag, result.FreshUntil, result.FetchedAt)
			updated.lastRefreshAttempt = existing.lastRefreshAttempt
			if result.ETag != "" {
				updated.etag = result.ETag
			}
			r.cache.Set(cacheKey, updated)
			return updated, nil
		}

		entry := newCacheEntry(result.keys, result.ETag, result.FreshUntil, result.FetchedAt)
		if existing != nil {
			entry.lastRefreshAttempt = existing.lastRefreshAttempt
		}
		r.cache.Set(cacheKey, entry)
		return entry, nil
	})
	if err != nil {
		var fetchErr *FetchError
		if !errors.As(err, &fetchErr) {
			return nil, &FetchError{JWKSURL: r.jwksURL, Err: err}
		}
		return nil, err
	}

	entry, ok := value.(*CacheEntry)
	if !ok {
		return nil, &FetchError{JWKSURL: r.jwksURL, Err: fmt.Errorf("unexpected cache entry type %T", value)}
	}

	return entry, nil
}
