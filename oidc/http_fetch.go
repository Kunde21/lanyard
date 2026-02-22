package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
)

const maxErrorBodyBytes = 4096

type providerFetchResult struct {
	metadata    ProviderMetadata
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

type authorizationServerFetchResult struct {
	metadata    AuthorizationServerMetadata
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

func (c *Client) fetchProviderMetadata(ctx context.Context, rawURL, priorETag string) (providerFetchResult, error) {
	var metadata ProviderMetadata
	result, err := c.fetchRawJSON(ctx, rawURL, priorETag, &metadata)
	if err != nil {
		return providerFetchResult{}, err
	}

	return providerFetchResult{
		metadata:    metadata,
		notModified: result.notModified,
		etag:        result.etag,
		freshUntil:  result.freshUntil,
		fetchedAt:   result.fetchedAt,
	}, nil
}

func (c *Client) fetchAuthorizationServerMetadata(ctx context.Context, rawURL, priorETag string) (authorizationServerFetchResult, error) {
	var metadata AuthorizationServerMetadata
	result, err := c.fetchRawJSON(ctx, rawURL, priorETag, &metadata)
	if err != nil {
		return authorizationServerFetchResult{}, err
	}

	return authorizationServerFetchResult{
		metadata:    metadata,
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

	req.Header.Set("Accept", "application/json")
	if priorETag != "" {
		req.Header.Set("If-None-Match", priorETag)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("failed to execute discovery request: %w", err)
	}
	defer resp.Body.Close()

	now := time.Now().UTC()
	freshUntil := calculateFreshUntil(req, resp.StatusCode, resp.Header, c.defaultDiscoveryTTL, now)
	result.etag = strings.TrimSpace(resp.Header.Get("ETag"))
	result.freshUntil = freshUntil
	result.fetchedAt = now

	if resp.StatusCode == http.StatusNotModified {
		result.notModified = true
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return result, &HTTPStatusError{URL: rawURL, StatusCode: resp.StatusCode, BodyPreview: strings.TrimSpace(string(preview))}
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(out); err != nil {
		return result, fmt.Errorf("failed to decode discovery response: %w", err)
	}

	return result, nil
}

func calculateFreshUntil(req *http.Request, statusCode int, headers http.Header, fallbackTTL time.Duration, now time.Time) time.Time {
	if req != nil {
		_, expiry, err := cacheobject.UsingRequestResponse(req, statusCode, headers, true)
		if err == nil && !expiry.IsZero() {
			return expiry.UTC()
		}
	}

	return now.Add(fallbackTTL)
}
