package rp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// CallbackResult contains the validated identity data returned from
// [RP.HandleCallback].
type CallbackResult struct {
	// Subject is the OpenID Connect subject from the validated ID token.
	Subject string
	// AccessToken is the OAuth 2.0 access token returned by the token endpoint.
	AccessToken string
	// UserInfo contains claims returned from the provider's UserInfo endpoint.
	UserInfo map[string]any
}

// HandleCallback validates callback state and performs token/userinfo processing.
func (r *RP) HandleCallback(ctx context.Context, w http.ResponseWriter, req *http.Request) (*CallbackResult, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: missing callback request", ErrInvalidState)
	}

	query := req.URL.Query()
	code := strings.TrimSpace(query.Get("code"))
	state := strings.TrimSpace(query.Get("state"))
	authzResponseIss := strings.TrimSpace(query.Get("iss"))

	if state == "" {
		return nil, fmt.Errorf("%w: missing state", ErrInvalidState)
	}
	if code == "" {
		return nil, fmt.Errorf("%w", ErrMissingCode)
	}

	data, ok, err := r.stateStore.ConsumeCorrelation(ctx, w, req, state)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to consume state: %v", ErrInvalidState, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: unknown or expired state", ErrInvalidState)
	}

	expectedIssuer := data.Issuer
	if expectedIssuer == "" {
		expectedIssuer = r.issuer
	}

	if r.isFAPIProfile() && authzResponseIss == "" {
		return nil, fmt.Errorf("%w: authorization response iss is required for FAPI", ErrInvalidState)
	}

	if authzResponseIss != "" && authzResponseIss != expectedIssuer {
		return nil, fmt.Errorf("%w: authorization response iss mismatch", ErrInvalidState)
	}

	issuer := expectedIssuer
	r.issuer = issuer

	provider, err := r.oidcClient.DiscoverProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery failed: %v", ErrTokenExchangeFailed, err)
	}
	if len(provider.TokenEndpointAuthMethodsSupported) > 0 {
		if err := r.applySupportedAuthMethods(provider.TokenEndpointAuthMethodsSupported); err != nil {
			return nil, fmt.Errorf("%w: auth method negotiation failed: %v", ErrTokenExchangeFailed, err)
		}
	}

	tokenEndpoint := r.tokenEndpoint(provider)
	if tokenEndpoint == "" {
		return nil, fmt.Errorf("%w: provider missing token endpoint", ErrTokenExchangeFailed)
	}

	tokenResp, err := r.exchangeToken(ctx, tokenEndpoint, code, data.CodeVerifier)
	if err != nil {
		return nil, err
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("%w: token response missing access_token", ErrUserInfoValidationFailed)
	}

	if !r.usesOpenIDScope() {
		return &CallbackResult{
			AccessToken: tokenResp.AccessToken,
		}, nil
	}

	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("%w: token response missing id_token", ErrIDTokenValidationFailed)
	}

	claims, err := r.validateIDToken(ctx, tokenResp.IDToken, data.Nonce, provider.JWKSURI, provider.IDTokenSigningAlgValuesSupported)
	if err != nil {
		return nil, err
	}

	userInfoEndpoint := r.userInfoEndpoint(provider)
	if userInfoEndpoint == "" {
		return nil, fmt.Errorf("%w: provider missing userinfo endpoint", ErrUserInfoValidationFailed)
	}

	transport := UserInfoTokenTransport(data.UserInfoTokenTransport)
	if transport == "" {
		transport = r.userInfoTokenTransport
	}

	userinfo, err := r.fetchUserInfo(ctx, userInfoEndpoint, tokenResp.AccessToken, claims.Subject, transport)
	if err != nil {
		return nil, err
	}

	return &CallbackResult{Subject: claims.Subject, AccessToken: tokenResp.AccessToken, UserInfo: userinfo}, nil
}

func (r *RP) isFAPIProfile() bool {
	return r.fapiProfile.isFAPI()
}

func (r *RP) usesOpenIDScope() bool {
	for _, scope := range r.scopes {
		if strings.EqualFold(strings.TrimSpace(scope), "openid") {
			return true
		}
	}
	return false
}
