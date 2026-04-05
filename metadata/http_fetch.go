package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Kunde21/lanyard/httputil"
)

func (c *Client) fetchDiscoveryMetadata(ctx context.Context, rawURL, priorETag string, out interface{}) (discoveryFetchResult, error) {
	result, err := c.fetchRawJSON(ctx, rawURL, priorETag, out)
	if err != nil {
		return discoveryFetchResult{}, err
	}

	return discoveryFetchResult{
		metadata:    out,
		notModified: result.NotModified,
		etag:        result.ETag,
		freshUntil:  result.FreshUntil,
		fetchedAt:   result.FetchedAt,
	}, nil
}

func (c *Client) fetchRawJSON(ctx context.Context, rawURL, priorETag string, out any) (httputil.FetchJSONResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return httputil.FetchJSONResult{}, fmt.Errorf("failed to build discovery request: %w", err)
	}

	fr, err := httputil.FetchJSON(req, c.httpClient, priorETag, c.defaultDiscoveryTTL, func(body io.Reader) error {
		decoder := json.NewDecoder(body)
		return decoder.Decode(out)
	})
	if err != nil {
		var decodeErr *httputil.DecodeError
		if errors.As(err, &decodeErr) {
			return httputil.FetchJSONResult{}, fmt.Errorf("failed to decode discovery response: %w", decodeErr.Err)
		}
		return httputil.FetchJSONResult{}, fmt.Errorf("failed to execute discovery request: %w", err)
	}

	if fr.NotModified {
		return fr, nil
	}

	if fr.StatusCode != http.StatusOK {
		return fr, &HTTPStatusError{URL: rawURL, StatusCode: fr.StatusCode, BodyPreview: fr.BodyPreview}
	}

	return fr, nil
}
