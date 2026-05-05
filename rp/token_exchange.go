package rp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (r *RP) buildTokenRequest(ctx context.Context, tokenEndpoint string, form url.Values, method AuthMethod) (*http.Request, error) {
	return buildTokenRequestEnvelope(ctx, tokenEndpoint, form, method, r.clientID, r.clientSecret)
}

func buildTokenRequestEnvelope(ctx context.Context, tokenEndpoint string, form url.Values, method AuthMethod, clientID, clientSecret string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	switch method {
	case AuthMethodBasic:
		req.SetBasicAuth(clientID, clientSecret)
	case AuthMethodTLSClientAuth, AuthMethodSelfSignedTLSClientAuth:
	}

	return req, nil
}

type tokenGrantResult struct {
	token   Token
	status  int
	preview string
}

type tokenGrantExecutor func(method AuthMethod) (tokenGrantResult, error)

type tokenRequestExecution struct {
	buildRequest func() (*http.Request, error)
	attachDPoP   func(req *http.Request, nonce string) error
	storeNonce   func(resp *http.Response)
	httpClient   *http.Client
	useDPoP      bool
	cachedNonce  string
}

func executeTokenGrant(config *clientConfig, run tokenGrantExecutor) (Token, error) {
	method, allowFallback := config.authMethodState()

	result, err := run(method)
	if err != nil {
		return Token{}, err
	}
	if result.status == http.StatusOK {
		if allowFallback {
			config.setAuthMethodState(method, false)
		}
		return result.token, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(result.status) {
		retryResult, retryErr := run(AuthMethodBasic)
		if retryErr != nil {
			return Token{}, retryErr
		}
		if retryResult.status == http.StatusOK {
			config.setAuthMethodState(AuthMethodBasic, false)
			return retryResult.token, nil
		}

		return Token{}, tokenEndpointStatusError(retryResult.status, retryResult.preview)
	}

	return Token{}, tokenEndpointStatusError(result.status, result.preview)
}

func tokenEndpointStatusError(status int, preview string) error {
	return fmt.Errorf("token endpoint returned status %d: %s", status, preview)
}

func executeTokenRequest(cfg tokenRequestExecution) (Token, int, string, error) {
	var tokenResp Token
	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: cfg.buildRequest,
		attachDPoP:   cfg.attachDPoP,
		handleResponse: func(body io.Reader) error {
			payload, err := io.ReadAll(body)
			if err != nil {
				return fmt.Errorf("failed to read token response: %w", err)
			}
			return parseTokenResponse(payload, &tokenResp)
		},
		storeNonce:    cfg.storeNonce,
		successStatus: http.StatusOK,
		httpClient:    cfg.httpClient,
		useDPoP:       cfg.useDPoP,
		cachedNonce:   cfg.cachedNonce,
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

func (r *RP) exchangeToken(ctx context.Context, tokenEndpoint, code, verifier string, resources []string) (Token, error) {
	tokenResp, err := executeTokenGrant(&r.clientConfig, func(method AuthMethod) (tokenGrantResult, error) {
		tokenResp, status, preview, err := r.exchangeTokenOnce(ctx, tokenEndpoint, code, verifier, method, "", resources)
		return tokenGrantResult{token: tokenResp, status: status, preview: preview}, err
	})
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	return tokenResp, nil
}

func (r *RP) exchangeTokenOnce(ctx context.Context, tokenEndpoint, code, verifier string, method AuthMethod, dpopAccessToken string, resources []string) (Token, int, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.redirectURI)
	form.Set("code_verifier", verifier)
	addResourceParameters(form, resources)

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
		// client_id not included in form when using Basic auth (only in Authorization header)
	}

	return executeTokenRequest(tokenRequestExecution{
		buildRequest: func() (*http.Request, error) {
			return r.buildTokenRequest(ctx, tokenEndpoint, form, method)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return r.attachDPoPProof(req, dpopAccessToken, nonce)
		},
		storeNonce: func(resp *http.Response) {
			r.extractAndStoreDPoPNonce(resp, tokenEndpoint)
		},
		httpClient:  r.httpClient,
		useDPoP:     useDPoP,
		cachedNonce: r.cachedDPoPNonce(tokenEndpoint),
	})
}

func shouldFallbackToBasic(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusUnauthorized
}
