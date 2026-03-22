package rp

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type parResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (r *RP) shouldUsePAR() bool {
	if r.requirePAR {
		return true
	}
	return r.provider.PushedAuthorizationRequestEndpoint != "" && r.provider.RequirePushedAuthorizationRequests != nil && *r.provider.RequirePushedAuthorizationRequests
}

func (r *RP) buildAuthorizationParameters(state, nonce, verifier, challenge string) url.Values {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", r.clientID)
	params.Set("redirect_uri", r.redirectURI)
	params.Set("scope", strings.Join(r.scopes, " "))
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	return params
}

func (r *RP) pushAuthorizationRequest(ctx context.Context, params url.Values) (*parResponse, error) {
	if r.provider.PushedAuthorizationRequestEndpoint == "" {
		return nil, fmt.Errorf("%w: pushed authorization request endpoint not available", ErrInvalidConfiguration)
	}

	parReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.provider.PushedAuthorizationRequestEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build PAR request: %w", err)
	}
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.Header.Set("Accept", "application/json")

	if r.clientKeyProvider != nil && r.resolvedAuthMethod == AuthMethodPrivateKeyJWT {
		assertion, err := r.buildClientAssertion(r.provider.PushedAuthorizationRequestEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to build client assertion for PAR: %w", err)
		}
		parReq.Header.Set("Authorization", "Bearer "+assertion)
	}

	resp, err := r.httpClient.Do(parReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute PAR request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read PAR response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("PAR request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var parResp parResponse
	if err := json.Unmarshal(body, &parResp); err != nil {
		return nil, fmt.Errorf("failed to parse PAR response: %w", err)
	}

	if parResp.RequestURI == "" {
		return nil, fmt.Errorf("%w: PAR response missing request_uri", ErrInvalidConfiguration)
	}

	return &parResp, nil
}

func (r *RP) buildClientAssertion(audience string) (string, error) {
	if r.clientKeyProvider == nil {
		return "", fmt.Errorf("%w: client key provider not configured", ErrInvalidConfiguration)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": r.clientID,
		"sub": r.clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": generateJTI(r.randReader),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	var alg jose.SignatureAlgorithm
	switch r.clientKeyProvider.SigningAlgorithm() {
	case "PS256":
		alg = jose.PS256
	case "RS256":
		alg = jose.RS256
	case "ES256":
		alg = jose.ES256
	default:
		return "", fmt.Errorf("unsupported signing algorithm: %s", r.clientKeyProvider.SigningAlgorithm())
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: r.clientKeyProvider.PrivateKey()}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"typ": "JWT",
			"kid": r.clientKeyProvider.KeyID(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	sig, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return sig.CompactSerialize()
}

func generateJTI(reader io.Reader) string {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

var (
	_ crypto.PrivateKey = (*rsaPrivateKey)(nil)
	_ crypto.PrivateKey = (*ecPrivateKey)(nil)
)

func (r *rsaPrivateKey) Equal(x crypto.PrivateKey) bool {
	xr, ok := x.(*rsaPrivateKey)
	if !ok {
		return false
	}
	return r.D.Cmp(xr.D) == 0
}

func (e *ecPrivateKey) Equal(x crypto.PrivateKey) bool {
	xr, ok := x.(*ecPrivateKey)
	if !ok {
		return false
	}
	return e.D.Cmp(xr.D) == 0
}
