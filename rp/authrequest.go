package rp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (r *RP) saveCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state, nonce, verifier string, parResp *parResponse) error {
	correlation := CallbackCorrelation{
		Nonce:                  nonce,
		CodeVerifier:           verifier,
		CreatedAt:              r.now(),
		Issuer:                 r.issuer,
		ClientID:               r.clientID,
		ClientSecret:           r.clientSecret,
		UserInfoTokenTransport: string(r.userInfoTokenTransport),
	}
	if parResp != nil {
		correlation.Expiry = r.now().Add(time.Duration(parResp.ExpiresIn) * time.Second)
		correlation.RequestURI = parResp.RequestURI
		correlation.UsedPAR = true
	}
	if err := r.stateStore.SaveCorrelation(ctx, w, req, state, correlation); err != nil {
		return fmt.Errorf("failed to save callback correlation state: %w", err)
	}
	return nil
}

func buildAuthorizationRedirect(endpoint string, params url.Values) (string, error) {
	authURL, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("%w: invalid authorization endpoint URL: %v", ErrInvalidConfiguration, err)
	}
	q := authURL.Query()
	for key, values := range params {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	authURL.RawQuery = q.Encode()
	return authURL.String(), nil
}

// AuthorizationURL builds an authorization request URL and stores callback state.
func (r *RP) AuthorizationURL(w http.ResponseWriter, req *http.Request, opts ...AuthorizationURLOption) (string, error) {
	metadata := r.provider
	authorizationEndpoint := r.authorizationEndpoint(metadata)
	if authorizationEndpoint == "" {
		return "", fmt.Errorf("%w: authorization endpoint missing", ErrInvalidConfiguration)
	}

	cfg := authorizationURLConfig{
		authorizationDetails: r.authorizationDetails,
		parameters:           make(url.Values),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if err := r.resolveAuthMethod(); err != nil {
		return "", err
	}

	state, err := randomToken(r.randReader, 32)
	if err != nil {
		return "", err
	}
	nonce, err := randomToken(r.randReader, 32)
	if err != nil {
		return "", err
	}
	verifier, err := generateCodeVerifier(r.randReader)
	if err != nil {
		return "", err
	}
	challenge, err := codeChallengeS256(verifier)
	if err != nil {
		return "", err
	}

	params := r.buildAuthorizationParameters(state, nonce, verifier, challenge, cfg.authorizationDetails, cfg.parameters)

	if r.shouldUsePAR() {
		parParams := params
		if r.requestMethod.isSigned() {
			signed, err := r.buildSignedRequestObject(state, nonce, challenge, cfg.authorizationDetails, cfg.parameters)
			if err != nil {
				return "", err
			}
			parParams = url.Values{}
			parParams.Set("request", signed)
			if r.resolvedAuthMethod == AuthMethodTLSClientAuth {
				parParams.Set("client_id", r.clientID)
			}
		}

		parResp, err := r.pushAuthorizationRequest(req.Context(), parParams)
		if err != nil {
			return "", err
		}

		if err := r.saveCorrelation(req.Context(), w, req, state, nonce, verifier, parResp); err != nil {
			return "", err
		}

		return buildAuthorizationRedirect(authorizationEndpoint, url.Values{"client_id": {r.clientID}, "request_uri": {parResp.RequestURI}})
	}

	redirectParams := params
	if r.requestMethod.isSigned() {
		signed, err := r.buildSignedRequestObject(state, nonce, challenge, cfg.authorizationDetails, cfg.parameters)
		if err != nil {
			return "", err
		}

		if r.requestURIHandler != nil {
			uri, err := r.requestURIHandler(signed)
			if err != nil {
				return "", fmt.Errorf("failed to store request object: %w", err)
			}
			redirectParams = url.Values{}
			for key, values := range params {
				redirectParams[key] = append([]string(nil), values...)
			}
			redirectParams.Del("request")
			redirectParams.Set("request_uri", uri)
		} else {
			redirectParams = url.Values{}
			for key, values := range params {
				redirectParams[key] = append([]string(nil), values...)
			}
			redirectParams.Set("request", signed)
		}
	}

	if err := r.saveCorrelation(req.Context(), w, req, state, nonce, verifier, nil); err != nil {
		return "", err
	}

	return buildAuthorizationRedirect(authorizationEndpoint, redirectParams)
}

func randomToken(reader io.Reader, size int) (string, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
