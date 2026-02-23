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
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.redirectURI)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: failed to build token request: %v", ErrTokenExchangeFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.clientID, r.clientSecret)

	var tokenResp TokenResponse
	status, preview, err := doJSON(req, r.httpClient, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&tokenResp)
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return TokenResponse{}, fmt.Errorf("%w: failed to decode token response: %v", ErrTokenExchangeFailed, decodeErr.Err)
		}
		return TokenResponse{}, fmt.Errorf("%w: failed to execute token request: %v", ErrTokenExchangeFailed, err)
	}

	if status != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrTokenExchangeFailed, status, preview)
	}

	return tokenResp, nil
}
