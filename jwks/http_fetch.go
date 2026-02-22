package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/pquerna/cachecontrol/cacheobject"
)

const maxErrorBodyBytes = 4096

type fetchResult struct {
	keys        []jose.JSONWebKey
	notModified bool
	etag        string
	freshUntil  time.Time
	fetchedAt   time.Time
}

func (r *RemoteKeySet) fetchJWKS(ctx context.Context, priorETag string) (fetchResult, error) {
	var result fetchResult

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksURL, nil)
	if err != nil {
		return result, fmt.Errorf("failed to build jwks request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if priorETag != "" {
		req.Header.Set("If-None-Match", priorETag)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return result, &FetchError{JWKSURL: r.jwksURL, Err: err}
	}
	defer resp.Body.Close()

	now := time.Now().UTC()
	result.etag = strings.TrimSpace(resp.Header.Get("ETag"))
	result.fetchedAt = now
	result.freshUntil = calculateFreshUntil(req, resp.StatusCode, resp.Header, r.defaultTTL, now)

	if resp.StatusCode == http.StatusNotModified {
		result.notModified = true
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return result, &FetchError{JWKSURL: r.jwksURL, Err: fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))}
	}

	var keySet jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return result, &FetchError{JWKSURL: r.jwksURL, Err: fmt.Errorf("failed to decode jwks: %w", err)}
	}

	result.keys = append([]jose.JSONWebKey(nil), keySet.Keys...)
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
