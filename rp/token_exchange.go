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
		// RFC 6749 section 2.3.1: the client_id and client_secret are
		// application/x-www-form-urlencoded per Appendix B before being
		// concatenated and base64-encoded for the Basic authentication header.
		// Authorization servers that issue credentials containing reserved
		// characters (as the OIDF conformance suite's dynamic registration does)
		// rely on this encoding.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
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
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(preview), &body); err == nil && body.Error != "" {
		return &OAuthError{Code: body.Error, Description: body.Description, Status: status}
	}
	return fmt.Errorf("token endpoint returned status %d: %s", status, preview)
}

// OAuthError describes an OAuth 2.0 token endpoint error response (RFC 6749
// section 5.2). It is returned when the endpoint responds with a JSON error
// body, so callers can branch on the machine-readable Code (e.g.
// "invalid_grant") via errors.As.
type OAuthError struct {
	// Code is the OAuth error code, e.g. "invalid_grant" or "invalid_client".
	Code string
	// Description is the optional error_description from the response.
	Description string
	// Status is the HTTP status code of the response.
	Status int
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth error %s (HTTP %d): %s", e.Code, e.Status, e.Description)
	}
	return fmt.Sprintf("oauth error %s (HTTP %d)", e.Code, e.Status)
}

// oauthErrorInvalidGrant is the RFC 6749 error code for an expired, revoked,
// or otherwise rejected refresh token.
const oauthErrorInvalidGrant = "invalid_grant"

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
