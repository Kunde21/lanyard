package rp

import (
	"context"
	"fmt"
)

// CallbackResult contains data produced from callback processing.
type CallbackResult struct {
	Subject  string
	UserInfo map[string]any
}

// HandleCallback validates callback state and performs token/userinfo processing.
func (r *RP) HandleCallback(ctx context.Context, code, state string) (*CallbackResult, error) {
	if state == "" {
		return nil, fmt.Errorf("%w: missing state", ErrInvalidState)
	}
	if code == "" {
		return nil, fmt.Errorf("%w", ErrMissingCode)
	}

	data, ok := r.stateStore.Load(state)
	if !ok {
		return nil, fmt.Errorf("%w: unknown or expired state", ErrInvalidState)
	}
	r.stateStore.Delete(state)

	provider, err := r.oidcClient.DiscoverProvider(ctx, r.issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery failed: %v", ErrTokenExchangeFailed, err)
	}
	if provider.TokenEndpoint == "" {
		return nil, fmt.Errorf("%w: provider missing token endpoint", ErrTokenExchangeFailed)
	}

	tokenResp, err := r.exchangeToken(ctx, provider.TokenEndpoint, code, data.CodeVerifier)
	if err != nil {
		return nil, err
	}
	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("%w: token response missing id_token", ErrIDTokenValidationFailed)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: token response missing access_token", ErrUserInfoValidationFailed)
	}

	claims, err := r.validateIDToken(ctx, tokenResp.IDToken, data.Nonce, provider.JWKSURI)
	if err != nil {
		return nil, err
	}
	if provider.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("%w: provider missing userinfo endpoint", ErrUserInfoValidationFailed)
	}
	userinfo, err := r.fetchUserInfo(ctx, provider.UserinfoEndpoint, tokenResp.AccessToken, claims.Subject)
	if err != nil {
		return nil, err
	}

	return &CallbackResult{Subject: claims.Subject, UserInfo: userinfo}, nil
}
