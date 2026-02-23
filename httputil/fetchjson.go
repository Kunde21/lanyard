package httputil

import (
	"io"
	"net/http"
	"strings"
	"time"
)

const maxJSONErrorBodyBytes = 4096

// FetchJSONResult captures the metadata that every JSON-based fetch flow needs.
type FetchJSONResult struct {
	NotModified bool
	StatusCode  int
	ETag        string
	FreshUntil  time.Time
	FetchedAt   time.Time
	BodyPreview string
}

// DecodeError signals that the decoder returned a failure while handling a 200
// response body. Callers can unwrap this type to add package-specific context.
type DecodeError struct {
	Err error
}

func (e *DecodeError) Error() string {
	return e.Err.Error()
}

func (e *DecodeError) Unwrap() error {
	return e.Err
}

// FetchJSON executes the provided request, applies JSON-specific headers,
// handles conditional success/previewing error bodies, and runs the decoder
// when a 200 response arrives.
func FetchJSON(req *http.Request, client *http.Client, priorETag string, fallbackTTL time.Duration, decoder func(io.Reader) error) (FetchJSONResult, error) {
	req.Header.Set("Accept", "application/json")
	if priorETag != "" {
		req.Header.Set("If-None-Match", priorETag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return FetchJSONResult{}, err
	}
	defer resp.Body.Close()

	now := time.Now().UTC()
	result := FetchJSONResult{
		StatusCode: resp.StatusCode,
		ETag:       strings.TrimSpace(resp.Header.Get("ETag")),
		FreshUntil: CalculateFreshUntil(req, resp.StatusCode, resp.Header, fallbackTTL, now),
		FetchedAt:  now,
	}

	if resp.StatusCode == http.StatusNotModified {
		result.NotModified = true
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, maxJSONErrorBodyBytes))
		result.BodyPreview = strings.TrimSpace(string(preview))
		return result, nil
	}

	if decoder != nil {
		if err := decoder(resp.Body); err != nil {
			return result, &DecodeError{Err: err}
		}
	}

	return result, nil
}
