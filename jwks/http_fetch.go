package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/httputil"
	jose "github.com/go-jose/go-jose/v4"
)

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

	var keySet []jose.JSONWebKey
	fetchResult, err := httputil.FetchJSON(req, r.httpClient, priorETag, r.defaultTTL, func(body io.Reader) error {
		decoded, decodeErr := decodeJWKS(body)
		if decodeErr != nil {
			return decodeErr
		}
		keySet = decoded
		return nil
	})
	if err != nil {
		var decodeErr *httputil.DecodeError
		if errors.As(err, &decodeErr) {
			return result, &FetchError{JWKSURL: r.jwksURL, Err: fmt.Errorf("failed to decode jwks: %w", decodeErr.Err)}
		}
		return result, &FetchError{JWKSURL: r.jwksURL, Err: err}
	}

	result.etag = fetchResult.ETag
	result.freshUntil = fetchResult.FreshUntil
	result.fetchedAt = fetchResult.FetchedAt

	if fetchResult.NotModified {
		result.notModified = true
		return result, nil
	}

	if fetchResult.StatusCode != http.StatusOK {
		return result, &FetchError{JWKSURL: r.jwksURL, Err: fmt.Errorf("status %d: %s", fetchResult.StatusCode, fetchResult.BodyPreview)}
	}

	result.keys = append([]jose.JSONWebKey(nil), keySet...)
	return result, nil
}

func decodeJWKS(body io.Reader) ([]jose.JSONWebKey, error) {
	var envelope struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(body).Decode(&envelope); err != nil {
		return nil, err
	}

	keys := make([]jose.JSONWebKey, 0, len(envelope.Keys))
	for _, raw := range envelope.Keys {
		var key jose.JSONWebKey
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}
		keys = append(keys, key)
	}

	if len(envelope.Keys) > 0 && len(keys) == 0 {
		return nil, fmt.Errorf("failed to decode all jwk entries")
	}

	return keys, nil
}
