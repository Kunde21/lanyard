package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/httputil"
)

type providerFetchResult struct {
	provider    Provider
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

type authorizationServerFetchResult struct {
	server      AuthorizationServer
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

func (c *Client) fetchProvider(ctx context.Context, rawURL, priorETag string) (providerFetchResult, error) {
	var provider Provider
	result, err := c.fetchRawJSON(ctx, rawURL, priorETag, &provider)
	if err != nil {
		return providerFetchResult{}, err
	}

	return providerFetchResult{
		provider:    provider,
		notModified: result.notModified,
		etag:        result.etag,
		freshUntil:  result.freshUntil,
		fetchedAt:   result.fetchedAt,
	}, nil
}

func (c *Client) fetchAuthorizationServer(ctx context.Context, rawURL, priorETag string) (authorizationServerFetchResult, error) {
	var server AuthorizationServer
	result, err := c.fetchRawJSON(ctx, rawURL, priorETag, &server)
	if err != nil {
		return authorizationServerFetchResult{}, err
	}

	return authorizationServerFetchResult{
		server:      server,
		notModified: result.notModified,
		etag:        result.etag,
		freshUntil:  result.freshUntil,
		fetchedAt:   result.fetchedAt,
	}, nil
}

type rawFetchResult struct {
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

func (c *Client) fetchRawJSON(ctx context.Context, rawURL, priorETag string, out any) (rawFetchResult, error) {
	var result rawFetchResult

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return result, fmt.Errorf("failed to build discovery request: %w", err)
	}

	fetchResult, err := httputil.FetchJSON(req, c.httpClient, priorETag, c.defaultDiscoveryTTL, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		return decoder.Decode(out)
	})
	if err != nil {
		var decodeErr *httputil.DecodeError
		if errors.As(err, &decodeErr) {
			return result, fmt.Errorf("failed to decode discovery response: %w", decodeErr.Err)
		}
		return result, fmt.Errorf("failed to execute discovery request: %w", err)
	}

	result.etag = fetchResult.ETag
	result.freshUntil = fetchResult.FreshUntil
	result.fetchedAt = fetchResult.FetchedAt

	if fetchResult.NotModified {
		result.notModified = true
		return result, nil
	}

	if fetchResult.StatusCode != http.StatusOK {
		return result, &HTTPStatusError{URL: rawURL, StatusCode: fetchResult.StatusCode, BodyPreview: fetchResult.BodyPreview}
	}

	return result, nil
}
