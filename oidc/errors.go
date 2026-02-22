package oidc

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidIssuer indicates issuer validation failed.
	ErrInvalidIssuer = errors.New("invalid issuer")
	// ErrDiscoveryFailed indicates discovery request or parsing failed.
	ErrDiscoveryFailed = errors.New("discovery failed")
)

// ValidationError describes validation failure details.
type ValidationError struct {
	Issuer   string
	Field    string
	Expected string
	Actual   string
	Err      error
}

// Error implements error.
func (e *ValidationError) Error() string {
	if e == nil {
		return "validation failed"
	}

	msg := fmt.Sprintf("validation failed for field %q", e.Field)
	if e.Issuer != "" {
		msg = fmt.Sprintf("issuer %q: %s", e.Issuer, msg)
	}
	if e.Expected != "" || e.Actual != "" {
		msg = fmt.Sprintf("%s (expected %q, got %q)", msg, e.Expected, e.Actual)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}

	return msg
}

// Unwrap returns wrapped error.
func (e *ValidationError) Unwrap() error {
	return e.Err
}

// Is supports errors.Is against ErrInvalidIssuer.
func (e *ValidationError) Is(target error) bool {
	if target == ErrInvalidIssuer {
		return true
	}

	return errors.Is(e.Err, target)
}

// HTTPStatusError indicates an unexpected HTTP status code.
type HTTPStatusError struct {
	URL         string
	StatusCode  int
	BodyPreview string
}

// Error implements error.
func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "unexpected http status"
	}

	if e.BodyPreview == "" {
		return fmt.Sprintf("unexpected HTTP status %d for %q", e.StatusCode, e.URL)
	}

	return fmt.Sprintf("unexpected HTTP status %d for %q: %s", e.StatusCode, e.URL, e.BodyPreview)
}
