package jwks

import (
	"errors"
	"fmt"
)

var (
	// ErrKeyNotFound indicates the requested key was not found.
	ErrKeyNotFound = errors.New("jwks key not found")
	// ErrFetchFailed indicates JWKS fetch failure.
	ErrFetchFailed = errors.New("jwks fetch failed")
)

// KeyNotFoundError indicates a specific key ID could not be found.
type KeyNotFoundError struct {
	JWKSURL string
	KID     string
}

// Error implements error.
func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("jwks key %q not found for %q", e.KID, e.JWKSURL)
}

// Is supports errors.Is matching against ErrKeyNotFound.
func (e *KeyNotFoundError) Is(target error) bool {
	return target == ErrKeyNotFound
}

// FetchError indicates a fetch operation failed.
type FetchError struct {
	JWKSURL string
	Err     error
}

// Error implements error.
func (e *FetchError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("failed to fetch jwks from %q", e.JWKSURL)
	}

	return fmt.Sprintf("failed to fetch jwks from %q: %v", e.JWKSURL, e.Err)
}

// Unwrap returns the wrapped error.
func (e *FetchError) Unwrap() error {
	return e.Err
}

// Is supports errors.Is matching against ErrFetchFailed.
func (e *FetchError) Is(target error) bool {
	if target == ErrFetchFailed {
		return true
	}

	return errors.Is(e.Err, target)
}
