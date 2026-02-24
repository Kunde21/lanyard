package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (r *RP) exchangeToken(ctx context.Context, tokenEndpoint, code, verifier string) (TokenResponse, error) {
	method, allowFallback := r.authMethodState()

	tokenResp, status, preview, err := r.exchangeTokenOnce(ctx, tokenEndpoint, code, verifier, method)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	if status == http.StatusOK {
		if allowFallback {
			r.setAuthMethodState(method, false)
		}
		return tokenResp, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryResp, retryStatus, retryPreview, retryErr := r.exchangeTokenOnce(ctx, tokenEndpoint, code, verifier, AuthMethodBasic)
		if retryErr != nil {
			return TokenResponse{}, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			r.setAuthMethodState(AuthMethodBasic, false)
			return retryResp, nil
		}

		return TokenResponse{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrTokenExchangeFailed, retryStatus, retryPreview)
	}

	return TokenResponse{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrTokenExchangeFailed, status, preview)
}

func (r *RP) exchangeTokenOnce(ctx context.Context, tokenEndpoint, code, verifier string, method AuthMethod) (TokenResponse, int, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.redirectURI)
	form.Set("code_verifier", verifier)
	if method == AuthMethodPost {
		form.Set("client_id", r.clientID)
		form.Set("client_secret", r.clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, 0, "", fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if method == AuthMethodBasic {
		req.SetBasicAuth(r.clientID, r.clientSecret)
	}

	var tokenResp TokenResponse
	status, preview, err := doJSON(req, r.httpClient, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&tokenResp)
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return TokenResponse{}, 0, "", fmt.Errorf("failed to decode token response: %w", decodeErr.Err)
		}
		return TokenResponse{}, 0, "", fmt.Errorf("failed to execute token request: %w", err)
	}

	return tokenResp, status, preview, nil
}

func shouldFallbackToBasic(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusUnauthorized
}
