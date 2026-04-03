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

func (r *RP) buildTokenRequest(ctx context.Context, tokenEndpoint string, form url.Values, method AuthMethod) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	switch method {
	case AuthMethodBasic:
		req.SetBasicAuth(r.clientID, r.clientSecret)
	case AuthMethodTLSClientAuth:
		// mTLS is handled by httpClient Transport
	}

	return req, nil
}

func (r *RP) exchangeToken(ctx context.Context, tokenEndpoint, code, verifier string) (Token, error) {
	method, allowFallback := r.authMethodState()

	tokenResp, status, preview, err := r.exchangeTokenOnce(ctx, tokenEndpoint, code, verifier, method, "")
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	if status == http.StatusOK {
		if allowFallback {
			r.setAuthMethodState(method, false)
		}
		return tokenResp, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryResp, retryStatus, retryPreview, retryErr := r.exchangeTokenOnce(ctx, tokenEndpoint, code, verifier, AuthMethodBasic, "")
		if retryErr != nil {
			return Token{}, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			r.setAuthMethodState(AuthMethodBasic, false)
			return retryResp, nil
		}

		return Token{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrTokenExchangeFailed, retryStatus, retryPreview)
	}

	return Token{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrTokenExchangeFailed, status, preview)
}

func (r *RP) exchangeTokenOnce(ctx context.Context, tokenEndpoint, code, verifier string, method AuthMethod, dpopAccessToken string) (Token, int, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.redirectURI)
	form.Set("code_verifier", verifier)

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
	case AuthMethodTLSClientAuth:
		form.Set("client_id", r.clientID)
	case AuthMethodPost:
		form.Set("client_id", r.clientID)
		form.Set("client_secret", r.clientSecret)
	case AuthMethodBasic:
		// client_id not included in form when using Basic auth (only in Authorization header)
	}

	req, err := r.buildTokenRequest(ctx, tokenEndpoint, form, method)
	if err != nil {
		return Token{}, 0, "", err
	}

	if useDPoP {
		if err := r.attachDPoPProof(req, dpopAccessToken, ""); err != nil {
			return Token{}, 0, "", fmt.Errorf("failed to generate DPoP proof: %w", err)
		}
	}

	var tokenResp Token
	resp, status, preview, err := doJSONStatus(req, r.httpClient, http.StatusOK, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&tokenResp)
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return Token{}, 0, "", fmt.Errorf("failed to decode token response: %w", decodeErr.Err)
		}
		return Token{}, 0, "", fmt.Errorf("failed to execute token request: %w", err)
	}

	if useDPoP && isUseDPoPNonce(resp) {
		nonce, ok := extractDPoPNonce(resp)
		if ok {
			retryReq, err := r.buildTokenRequest(ctx, tokenEndpoint, form, method)
			if err != nil {
				return Token{}, 0, "", err
			}
			if err := r.attachDPoPProof(retryReq, dpopAccessToken, nonce); err != nil {
				return Token{}, 0, "", fmt.Errorf("failed to generate DPoP proof: %w", err)
			}

			resp, status, preview, err = doJSONStatus(retryReq, r.httpClient, http.StatusOK, func(body io.Reader) error {
				return json.NewDecoder(body).Decode(&tokenResp)
			})
			if err != nil {
				var decodeErr *jsonDecodeError
				if errors.As(err, &decodeErr) {
					return Token{}, 0, "", fmt.Errorf("failed to decode token response: %w", decodeErr.Err)
				}
				return Token{}, 0, "", fmt.Errorf("failed to execute token request: %w", err)
			}
		}
	}

	return tokenResp, status, preview, nil
}

func shouldFallbackToBasic(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusUnauthorized
}
