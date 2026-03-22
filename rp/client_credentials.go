package rp

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/go-jose/go-jose/v4"
)

// ClientCredentials implements OAuth 2.0 Client Credentials grant flow (RFC 6749 §4.4).
type ClientCredentials struct {
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	authMethod   AuthMethod

	httpClient *http.Client
	logger     *slog.Logger
	oidcClient *oidc.Client

	provider    oidc.ProviderMetadata
	providerSet bool

	clientKeyProvider ClientKeyProvider

	resolvedAuthMethod  AuthMethod
	allowMethodFallback bool
	methodMu            sync.RWMutex

	now        func() time.Time
	randReader io.Reader
}

// NewClientCredentials creates a new Client Credentials client.
func NewClientCredentials(ctx context.Context, issuer, clientID, clientSecret string, opts ...ClientCredentialsOption) (*ClientCredentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c := &ClientCredentials{
		issuer:       strings.TrimSpace(issuer),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: clientSecret,
		httpClient:   http.DefaultClient,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:          func() time.Time { return time.Now().UTC() },
		randReader:   rand.Reader,
	}

	for _, opt := range opts {
		opt(c)
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	if c.oidcClient == nil {
		c.oidcClient = oidc.NewClient(
			oidc.WithHTTPClient(c.httpClient),
			oidc.WithLogger(c.logger),
		)
	}

	if !c.providerSet {
		provider, err := c.oidcClient.DiscoverProvider(ctx, c.issuer)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to discover provider: %v", ErrInvalidConfiguration, err)
		}
		c.provider = provider
		c.providerSet = true
	}

	if err := c.resolveAuthMethod(); err != nil {
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

func (c *ClientCredentials) resolveAuthMethod() error {
	supported := normalizeSupportedAuthMethods(c.provider.TokenEndpointAuthMethodsSupported)
	resolved := AuthMethodPost
	allowFallback := false

	if len(supported) > 0 {
		if c.authMethod != "" {
			if !methodSupported(c.authMethod, supported) {
				return &AuthMethodError{Method: c.authMethod, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
			resolved = c.authMethod
			allowFallback = false
		} else {
			switch {
			case methodSupported(AuthMethodPrivateKeyJWT, supported):
				resolved = AuthMethodPrivateKeyJWT
			case methodSupported(AuthMethodTLSClientAuth, supported):
				resolved = AuthMethodTLSClientAuth
			case methodSupported(AuthMethodPost, supported):
				resolved = AuthMethodPost
			case methodSupported(AuthMethodBasic, supported):
				resolved = AuthMethodBasic
			default:
				return &AuthMethodError{Method: AuthMethodPost, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
			allowFallback = false
		}
	} else if c.authMethod != "" {
		resolved = c.authMethod
		allowFallback = false
	} else {
		resolved = AuthMethodPost
		allowFallback = true
	}

	if err := c.validateResolvedAuthMethod(resolved); err != nil {
		return err
	}

	c.setAuthMethodState(resolved, allowFallback)

	return nil
}

func (c *ClientCredentials) validateResolvedAuthMethod(method AuthMethod) error {
	switch method {
	case AuthMethodBasic, AuthMethodPost:
		if strings.TrimSpace(c.clientSecret) == "" {
			return fmt.Errorf("%w: client_secret is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodPrivateKeyJWT:
		if c.clientKeyProvider == nil {
			return fmt.Errorf("%w: client_key_provider is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodTLSClientAuth:
		if c.clientKeyProvider == nil || c.clientKeyProvider.TLSCertificate() == nil {
			return fmt.Errorf("%w: tls certificate is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported token endpoint auth method %q", ErrInvalidConfiguration, method)
	}
}

func (c *ClientCredentials) authMethodState() (AuthMethod, bool) {
	c.methodMu.RLock()
	method := c.resolvedAuthMethod
	allowFallback := c.allowMethodFallback
	c.methodMu.RUnlock()

	return method, allowFallback
}

func (c *ClientCredentials) setAuthMethodState(method AuthMethod, allowFallback bool) {
	c.methodMu.Lock()
	c.resolvedAuthMethod = method
	c.allowMethodFallback = allowFallback
	c.methodMu.Unlock()
}

// Token requests an access token using the client credentials grant.
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
	case AuthMethodPost:
		form.Set("client_secret", c.clientSecret)
	case AuthMethodBasic:
		// client_id not included in form when using Basic auth
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.provider.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	switch method {
	case AuthMethodBasic:
		req.SetBasicAuth(c.clientID, c.clientSecret)
	case AuthMethodTLSClientAuth:
		// mTLS is handled by httpClient Transport
	}

	var token Token
	status, preview, err := doJSON(req, c.httpClient, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&token)
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
	var joseAlg jose.SignatureAlgorithm
	switch alg {
	case "PS256":
		joseAlg = jose.PS256
	case "PS384":
		joseAlg = jose.PS384
	case "PS512":
		joseAlg = jose.PS512
	case "RS256":
		joseAlg = jose.RS256
	case "RS384":
		joseAlg = jose.RS384
	case "RS512":
		joseAlg = jose.RS512
	case "ES256":
		joseAlg = jose.ES256
	case "ES384":
		joseAlg = jose.ES384
	case "ES512":
		joseAlg = jose.ES512
	default:
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
