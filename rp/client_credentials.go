package rp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ClientCredentials performs OAuth 2.0 client credentials token requests.
type ClientCredentials struct {
	clientConfig
}

// NewClientCredentials creates a client credentials token source for issuer.
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

// Token requests an access token using the client credentials grant.
func (c *ClientCredentials) Token(ctx context.Context) (*Token, error) {
	token, err := executeTokenGrant(&c.clientConfig, func(method AuthMethod) (tokenGrantResult, error) {
		tokenResp, status, preview, err := c.requestToken(ctx, method)
		if tokenResp == nil {
			return tokenGrantResult{status: status, preview: preview}, err
		}
		return tokenGrantResult{token: *tokenResp, status: status, preview: preview}, err
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClientCredentialsFailed, err)
	}
	return &token, nil
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

	token, status, preview, err := executeTokenRequest(tokenRequestExecution{
		buildRequest: func() (*http.Request, error) {
			return c.buildTokenRequest(ctx, method, form)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return c.clientConfig.attachDPoPProof(req, nonce)
		},
		storeNonce: func(resp *http.Response) {
			c.clientConfig.extractAndStoreDPoPNonce(resp, c.provider.TokenEndpoint)
		},
		httpClient:  c.httpClient,
		useDPoP:     useDPoP,
		cachedNonce: c.clientConfig.cachedDPoPNonce(c.provider.TokenEndpoint),
	})
	if err != nil {
		return nil, 0, "", err
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
	return buildTokenRequestEnvelope(ctx, c.provider.TokenEndpoint, form, method, c.clientID, c.clientSecret)
}

func (c *ClientCredentials) buildClientAssertion() (string, error) {
	return buildPrivateKeyClientAssertion(c.clientID, c.provider.TokenEndpoint, c.clientKeyProvider, c.now(), c.randReader)
}
