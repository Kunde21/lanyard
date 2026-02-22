package jwks

import (
	"errors"
	"testing"
)

func TestKeyNotFoundErrorIs(t *testing.T) {
	err := &KeyNotFoundError{JWKSURL: "https://example.com/jwks", KID: "missing"}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected errors.Is(err, ErrKeyNotFound) to be true")
	}
}

func TestFetchErrorIs(t *testing.T) {
	err := &FetchError{JWKSURL: "https://example.com/jwks", Err: errors.New("boom")}
	if !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("expected errors.Is(err, ErrFetchFailed) to be true")
	}
}
