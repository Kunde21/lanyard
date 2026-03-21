package rp

import "context"

// Token represents an OAuth 2.0 access token.
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
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
