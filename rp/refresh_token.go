package rp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RefreshToken exchanges a refresh token for a new token at the provider's token endpoint.
func (r *RP) RefreshToken(ctx context.Context, refreshToken string) (Token, error) {
	if refreshToken == "" {
		return Token{}, fmt.Errorf("%w: refresh token is required", ErrRefreshTokenFailed)
	}

	tokenEndpoint := r.tokenEndpoint(r.provider)
	if tokenEndpoint == "" {
		return Token{}, fmt.Errorf("%w: token endpoint is not configured", ErrRefreshTokenFailed)
	}

	method, allowFallback := r.authMethodState()

	tokenResp, status, preview, err := r.refreshTokenOnce(ctx, tokenEndpoint, refreshToken, method, "")
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrRefreshTokenFailed, err)
	}
	if status == http.StatusOK {
		if allowFallback {
			r.setAuthMethodState(method, false)
		}
		return tokenResp, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryResp, retryStatus, retryPreview, retryErr := r.refreshTokenOnce(ctx, tokenEndpoint, refreshToken, AuthMethodBasic, "")
		if retryErr != nil {
			return Token{}, fmt.Errorf("%w: %v", ErrRefreshTokenFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			r.setAuthMethodState(AuthMethodBasic, false)
			return retryResp, nil
		}

		return Token{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrRefreshTokenFailed, retryStatus, retryPreview)
	}

	return Token{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrRefreshTokenFailed, status, preview)
}

func (r *RP) refreshTokenOnce(ctx context.Context, tokenEndpoint, refreshToken string, method AuthMethod, dpopAccessToken string) (Token, int, string, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	useDPoP := r.shouldUseDPoP()

	switch method {
	case AuthMethodPrivateKeyJWT:
		audience := r.issuer
		if audience == "" {
			audience = tokenEndpoint
		}
		assertion, err := r.buildClientAssertion(audience)
		if err != nil {
			return Token{}, 0, "", fmt.Errorf("failed to build client assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		form.Set("client_id", r.clientID)
	case AuthMethodClientSecretJWT:
		audience := r.issuer
		if audience == "" {
			audience = tokenEndpoint
		}
		assertion, err := r.buildClientSecretAssertion(audience)
		if err != nil {
			return Token{}, 0, "", fmt.Errorf("failed to build client secret assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		form.Set("client_id", r.clientID)
	case AuthMethodTLSClientAuth, AuthMethodSelfSignedTLSClientAuth:
		form.Set("client_id", r.clientID)
	case AuthMethodNone:
		form.Set("client_id", r.clientID)
	case AuthMethodPost:
		form.Set("client_id", r.clientID)
		form.Set("client_secret", r.clientSecret)
	case AuthMethodBasic:
	}

	var tokenResp Token
	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return r.buildTokenRequest(ctx, tokenEndpoint, form, method)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return r.attachDPoPProof(req, dpopAccessToken, nonce)
		},
		handleResponse: func(body io.Reader) error {
			payload, err := io.ReadAll(body)
			if err != nil {
				return fmt.Errorf("failed to read token response: %w", err)
			}
			return parseTokenResponse(payload, &tokenResp)
		},
		storeNonce: func(resp *http.Response) {
			r.extractAndStoreDPoPNonce(resp, tokenEndpoint)
		},
		successStatus: http.StatusOK,
		httpClient:    r.httpClient,
		useDPoP:       useDPoP,
		cachedNonce:   r.cachedDPoPNonce(tokenEndpoint),
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return Token{}, 0, "", fmt.Errorf("failed to decode token response: %w", decodeErr.Err)
		}
		return Token{}, 0, "", fmt.Errorf("failed to execute token request: %w", err)
	}

	return tokenResp, status, preview, nil
}
