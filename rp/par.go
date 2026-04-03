package rp

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	return r.pushedAuthorizationRequestEndpoint(r.provider) != "" && r.provider.RequirePushedAuthorizationRequests != nil && *r.provider.RequirePushedAuthorizationRequests
}

func (r *RP) buildPARRequest(ctx context.Context, parEndpoint string, params url.Values) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build PAR request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (r *RP) buildAuthorizationParameters(state, nonce, verifier, challenge, authorizationDetails string) url.Values {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", r.clientID)
	params.Set("redirect_uri", r.redirectURI)
	params.Set("scope", strings.Join(r.scopes, " "))
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	if strings.TrimSpace(authorizationDetails) != "" {
		params.Set("authorization_details", authorizationDetails)
	}
	return params
}

func (r *RP) pushAuthorizationRequest(ctx context.Context, params url.Values) (*parResponse, error) {
	parEndpoint := r.pushedAuthorizationRequestEndpoint(r.provider)
	if parEndpoint == "" {
		return nil, fmt.Errorf("%w: pushed authorization request endpoint not available", ErrInvalidConfiguration)
	}

	if r.clientKeyProvider != nil && r.resolvedAuthMethod == AuthMethodPrivateKeyJWT {
		assertion, err := r.buildClientAssertion(r.issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to build client assertion for PAR: %w", err)
		}
		params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		params.Set("client_assertion", assertion)
	}

	parReq, err := r.buildPARRequest(ctx, parEndpoint, params)
	if err != nil {
		return nil, err
	}

	useDPoP := r.shouldUseDPoP()
	if useDPoP {
		cachedNonce := r.cachedDPoPNonce(parEndpoint)
		if err := r.attachDPoPProof(parReq, "", cachedNonce); err != nil {
			return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
		}
	}

	var parResp parResponse
	resp, status, preview, err := doJSONStatus(parReq, r.httpClient, http.StatusCreated, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&parResp)
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return nil, fmt.Errorf("failed to parse PAR response: %w", decodeErr.Err)
		}
		return nil, fmt.Errorf("failed to execute PAR request: %w", err)
	}

	if useDPoP && resp != nil {
		r.extractAndStoreDPoPNonce(resp, parEndpoint)
	}

	if useDPoP && isUseDPoPNonce(resp) {
		nonce, ok := extractDPoPNonce(resp)
		if ok {
			retryReq, err := r.buildPARRequest(ctx, parEndpoint, params)
			if err != nil {
				return nil, err
			}
			if err := r.attachDPoPProof(retryReq, "", nonce); err != nil {
				return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
			}

			resp, status, preview, err = doJSONStatus(retryReq, r.httpClient, http.StatusCreated, func(body io.Reader) error {
				return json.NewDecoder(body).Decode(&parResp)
			})
			if err != nil {
				var decodeErr *jsonDecodeError
				if errors.As(err, &decodeErr) {
					return nil, fmt.Errorf("failed to parse PAR response: %w", decodeErr.Err)
				}
				return nil, fmt.Errorf("failed to execute PAR request: %w", err)
			}
			if err == nil && resp != nil {
				r.extractAndStoreDPoPNonce(resp, parEndpoint)
			}
		}
	}

	if status != http.StatusCreated {
		return nil, fmt.Errorf("PAR request failed with status %d: %s", status, preview)
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
