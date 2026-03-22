package rp

import "context"

// Token represents a token endpoint response shared by the browser and client
// credentials entrypoints.
type Token struct {
	// AccessToken is the OAuth 2.0 bearer token for API calls.
	AccessToken string `json:"access_token"`
	// TokenType is usually "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the token lifetime reported by the token endpoint, in seconds.
	ExpiresIn int64 `json:"expires_in"`
	// IDToken is set for authorization code responses that include an ID token.
	IDToken string `json:"id_token,omitempty"`
	// RefreshToken is set when the provider issues a refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Scope is the granted scope string returned by the token endpoint.
	Scope string `json:"scope,omitempty"`
}

// TokenSource provides OAuth 2.0 access tokens.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

// Scopes configuration option for client credentials flow.
type Scopes []string

type tokenScopesKey struct{}

// WithTokenScopes returns a context with per-request scopes for client credentials token requests.
// These scopes override the default scopes configured when creating the ClientCredentials.
func WithTokenScopes(ctx context.Context, scopes ...string) context.Context {
	if ctx == nil {
		return nil
	}
	clonedScopes := make([]string, len(scopes))
	copy(clonedScopes, scopes)
	return context.WithValue(ctx, tokenScopesKey{}, clonedScopes)
}

func tokenScopesFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	scopes, _ := ctx.Value(tokenScopesKey{}).([]string)
	return scopes
}
