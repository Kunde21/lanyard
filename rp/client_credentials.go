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

type ClientCredentials struct {
	clientConfig
}

func NewClientCredentials(ctx context.Context, issuer string, opts ...Option) (*ClientCredentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c := &ClientCredentials{
		clientConfig: defaultClientConfig(issuer),
	}

	for _, opt := range opts {
		opt.apply(c)
	}

	c.clientConfig.initDefaults()

	if err := c.validate(); err != nil {
		return nil, err
	}

	c.clientConfig.initMetadataClient()

	if err := c.clientConfig.resolveProviderFromDiscovery(ctx); err != nil {
		return nil, err
	}

	if err := c.clientConfig.resolveAuthMethodFromProvider(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *ClientCredentials) validate() error {
	if err := validateHTTPSAbsoluteURL("issuer", c.issuer); err != nil {
		return err
	}

	if c.clientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidConfiguration)
	}

	return nil
}

func (c *ClientCredentials) Token(ctx context.Context) (*Token, error) {
	method, allowFallback := c.authMethodState()

	token, status, preview, err := c.requestToken(ctx, method)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClientCredentialsFailed, err)
	}
	if status == http.StatusOK {
		if allowFallback {
			c.setAuthMethodState(method, false)
		}
		return token, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryToken, retryStatus, retryPreview, retryErr := c.requestToken(ctx, AuthMethodBasic)
		if retryErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrClientCredentialsFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			c.setAuthMethodState(AuthMethodBasic, false)
			return retryToken, nil
		}

		return nil, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrClientCredentialsFailed, retryStatus, retryPreview)
	}

	return nil, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrClientCredentialsFailed, status, preview)
}

func (c *ClientCredentials) requestToken(ctx context.Context, method AuthMethod) (*Token, int, string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	scopes := c.scopes
	if overrideScopes := tokenScopesFromContext(ctx); len(overrideScopes) > 0 {
		scopes = overrideScopes
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	if method != AuthMethodBasic {
		form.Set("client_id", c.clientID)
	}

	switch method {
	case AuthMethodPrivateKeyJWT:
		assertion, err := c.buildClientAssertion()
		if err != nil {
			return nil, 0, "", fmt.Errorf("failed to build client assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	case AuthMethodSelfSignedTLSClientAuth:
	case AuthMethodPost:
		form.Set("client_secret", c.clientSecret)
	case AuthMethodBasic:
	}

	useDPoP := c.clientConfig.shouldUseDPoP()

	var token Token
	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return c.buildTokenRequest(ctx, method, form)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return c.clientConfig.attachDPoPProof(req, nonce)
		},
		handleResponse: func(body io.Reader) error {
			payload, err := io.ReadAll(body)
			if err != nil {
				return fmt.Errorf("failed to read token response: %w", err)
			}
			return parseTokenResponse(payload, &token)
		},
		storeNonce: func(resp *http.Response) {
			c.clientConfig.extractAndStoreDPoPNonce(resp, c.provider.TokenEndpoint)
		},
		successStatus: http.StatusOK,
		httpClient:    c.httpClient,
		useDPoP:       useDPoP,
		cachedNonce:   c.clientConfig.cachedDPoPNonce(c.provider.TokenEndpoint),
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return nil, 0, "", fmt.Errorf("failed to decode token response: %w", decodeErr.Err)
		}
		return nil, 0, "", fmt.Errorf("failed to execute token request: %w", err)
	}

	if status != http.StatusOK {
		return nil, status, preview, nil
	}

	if token.AccessToken == "" {
		return nil, status, "", fmt.Errorf("token response missing access_token")
	}

	return &token, status, "", nil
}

func (c *ClientCredentials) buildTokenRequest(ctx context.Context, method AuthMethod, form url.Values) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	switch method {
	case AuthMethodBasic:
		req.SetBasicAuth(c.clientID, c.clientSecret)
	case AuthMethodTLSClientAuth, AuthMethodSelfSignedTLSClientAuth:
	}

	return req, nil
}

func (c *ClientCredentials) buildClientAssertion() (string, error) {
	now := c.now()
	jti := make([]byte, 16)
	if _, err := io.ReadFull(c.randReader, jti); err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}

	header := map[string]any{
		"typ": "JWT",
		"alg": c.clientKeyProvider.SigningAlgorithm(),
		"kid": c.clientKeyProvider.KeyID(),
	}
	claims := map[string]any{
		"iss": c.clientID,
		"sub": c.clientID,
		"aud": c.provider.TokenEndpoint,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	payload := headerB64 + "." + claimsB64

	signature, err := signClientAssertion(payload, c.clientKeyProvider.SigningAlgorithm(), c.clientKeyProvider.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("failed to sign assertion: %w", err)
	}

	return payload + "." + signature, nil
}

func signClientAssertion(input, alg string, privateKey crypto.PrivateKey) (string, error) {
	joseAlg := signatureAlgorithm(alg)
	if joseAlg == "" {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: joseAlg, Key: privateKey}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return sig.CompactSerialize()
}
