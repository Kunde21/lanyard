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

func (c *Client) fetchDiscoveryMetadata(ctx context.Context, rawURL, priorETag string, out interface{}) (discoveryFetchResult, error) {
	result, err := c.fetchRawJSON(ctx, rawURL, priorETag, out)
	if err != nil {
		return discoveryFetchResult{}, err
	}

	return discoveryFetchResult{
		metadata:    out,
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

func mapFetchResult(r httputil.FetchJSONResult) rawFetchResult {
	return rawFetchResult{
		notModified: r.NotModified,
		etag:        r.ETag,
		freshUntil:  r.FreshUntil,
		fetchedAt:   r.FetchedAt,
	}
}

func (c *Client) fetchRawJSON(ctx context.Context, rawURL, priorETag string, out any) (rawFetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return rawFetchResult{}, fmt.Errorf("failed to build discovery request: %w", err)
	}

	fr, err := httputil.FetchJSON(req, c.httpClient, priorETag, c.defaultDiscoveryTTL, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		return decoder.Decode(out)
	})
	if err != nil {
		var decodeErr *httputil.DecodeError
		if errors.As(err, &decodeErr) {
			return rawFetchResult{}, fmt.Errorf("failed to decode discovery response: %w", decodeErr.Err)
		}
		return rawFetchResult{}, fmt.Errorf("failed to execute discovery request: %w", err)
	}

	result := mapFetchResult(fr)

	if result.notModified {
		return result, nil
	}

	if fr.StatusCode != http.StatusOK {
		return result, &HTTPStatusError{URL: rawURL, StatusCode: fr.StatusCode, BodyPreview: fr.BodyPreview}
	}

	return result, nil
}
