package rp

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// RefreshTokenSource is a concurrency-safe holder for a refresh token that
// tracks rotation across refreshes (RFC 9700 section 2.2.2).
//
// Authorization servers SHOULD issue a new refresh token with every refresh
// response; once rotated, the previous token is invalid. RefreshTokenSource
// serializes refreshes and adopts the new token on each successful response,
// so concurrent callers cannot accidentally replay a token that has already
// been rotated out — replay is what authorization servers answer by revoking
// the entire token family.
//
// When the server rejects the token (invalid_grant), Refresh returns an error
// wrapping ErrRefreshTokenRejected. Per RFC 9700 the caller must then discard
// the refresh token, restart the authorization flow, and replace this source.
type RefreshTokenSource struct {
	rp      *RP
	mu      sync.Mutex
	current string
}

// NewRefreshTokenSource creates a rotating refresh token source around
// refreshToken obtained from a prior authorization. Returns an error wrapping
// ErrInvalidConfiguration when r is nil or refreshToken is empty.
func NewRefreshTokenSource(r *RP, refreshToken string) (*RefreshTokenSource, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: rp is required", ErrInvalidConfiguration)
	}
	if refreshToken = strings.TrimSpace(refreshToken); refreshToken == "" {
		return nil, fmt.Errorf("%w: refresh token is required", ErrInvalidConfiguration)
	}
	return &RefreshTokenSource{rp: r, current: refreshToken}, nil
}

// Refresh exchanges the currently held refresh token for a new token set via
// RP.RefreshToken. When the response carries a refresh token (rotation), the
// source switches to it; when it does not (RFC 6749 section 6 allows
// omission), the previous token remains in use. The returned Token always
// carries the now-current refresh token in Token.RefreshToken.
func (s *RefreshTokenSource) Refresh(ctx context.Context) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := s.rp.RefreshToken(ctx, s.current)
	if err != nil {
		return Token{}, err
	}
	if token.RefreshToken != "" {
		s.current = token.RefreshToken
	} else {
		token.RefreshToken = s.current
	}
	return token, nil
}

// CurrentRefreshToken returns the refresh token currently held by the source.
// Use it to persist the latest token across process restarts.
func (s *RefreshTokenSource) CurrentRefreshToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// Replace swaps the refresh token held by the source. Use it after a grant
// management merge or replace flow: those actions invalidate the grant's
// existing refresh tokens (draft-ietf-oauth-grant-management section 5.2),
// so the source must be pointed at the refresh token returned by that
// flow's token exchange.
func (s *RefreshTokenSource) Replace(refreshToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = strings.TrimSpace(refreshToken)
}
