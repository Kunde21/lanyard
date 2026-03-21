package rp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// AuthorizationURL builds an authorization request URL and stores callback state.
func (r *RP) AuthorizationURL(ctx context.Context) (string, error) {
	metadata, err := r.oidcClient.DiscoverProvider(ctx, r.issuer)
	if err != nil {
		return "", fmt.Errorf("failed to discover provider: %w", err)
	}
	if metadata.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("%w: authorization endpoint missing", ErrInvalidConfiguration)
	}

	r.provider = metadata
	r.providerSet = true

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

	params := r.buildAuthorizationParameters(state, nonce, verifier, challenge)

	if r.shouldUsePAR() {
		parResp, err := r.pushAuthorizationRequest(ctx, params)
		if err != nil {
			return "", err
		}

		expiry := r.now().Add(time.Duration(parResp.ExpiresIn) * time.Second)
		r.stateStore.Save(state, StateData{
			Nonce:                  nonce,
			CodeVerifier:           verifier,
			CreatedAt:              r.now(),
			Expiry:                 expiry,
			Issuer:                 r.issuer,
			RequestURI:             parResp.RequestURI,
			UsedPAR:                true,
			UserInfoTokenTransport: r.userInfoTokenTransport,
		})

		authURL, err := url.Parse(metadata.AuthorizationEndpoint)
		if err != nil {
			return "", fmt.Errorf("%w: invalid authorization endpoint URL: %v", ErrInvalidConfiguration, err)
		}

		q := authURL.Query()
		q.Set("client_id", r.clientID)
		q.Set("request_uri", parResp.RequestURI)
		authURL.RawQuery = q.Encode()

		return authURL.String(), nil
	}

	r.stateStore.Save(state, StateData{
		Nonce:                  nonce,
		CodeVerifier:           verifier,
		CreatedAt:              r.now(),
		Issuer:                 r.issuer,
		UserInfoTokenTransport: r.userInfoTokenTransport,
	})

	authURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("%w: invalid authorization endpoint URL: %v", ErrInvalidConfiguration, err)
	}

	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", r.clientID)
	q.Set("redirect_uri", r.redirectURI)
	q.Set("scope", strings.Join(r.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	return authURL.String(), nil
}

func randomToken(reader io.Reader, size int) (string, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
