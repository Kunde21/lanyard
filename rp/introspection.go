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

// ErrIntrospectionFailed indicates a token introspection request failed.
var ErrIntrospectionFailed = errors.New("token introspection failed")

const introspectionJWTMediaType = "application/token-introspection+jwt"

// TokenTypeHint identifies the kind of token being introspected.
type TokenTypeHint string

const (
	// TokenTypeHintAccessToken indicates an OAuth access token.
	TokenTypeHintAccessToken TokenTypeHint = "access_token"
	// TokenTypeHintRefreshToken indicates an OAuth refresh token.
	TokenTypeHintRefreshToken TokenTypeHint = "refresh_token"
)

// IntrospectionRequest configures one OAuth 2.0 token introspection request.
type IntrospectionRequest struct {
	// Token is the token value to introspect (required).
	Token string
	// TokenTypeHint optionally indicates the token type.
	TokenTypeHint TokenTypeHint
	// PreferJWTResponse requests RFC 9701 signed JWT response format.
	PreferJWTResponse bool
	// ExpectedJWTAudience overrides the expected audience for JWT response
	// verification. Defaults to client_id when empty.
	ExpectedJWTAudience string
}

// IntrospectionResponse is an OAuth 2.0 token introspection response (RFC 7662).
type IntrospectionResponse struct {
	Active    bool          `json:"active"`
	Scope     string        `json:"scope,omitempty"`
	ClientID  string        `json:"client_id,omitempty"`
	Username  string        `json:"username,omitempty"`
	TokenType string        `json:"token_type,omitempty"`
	Exp       int64         `json:"exp,omitempty"`
	Iat       int64         `json:"iat,omitempty"`
	Nbf       int64         `json:"nbf,omitempty"`
	Sub       string        `json:"sub,omitempty"`
	Aud       audienceClaim `json:"aud,omitempty"`
	Iss       string        `json:"iss,omitempty"`
	JTI       string        `json:"jti,omitempty"`

	raw    json.RawMessage
	rawJWT string
}

type introspectionResponseJSON IntrospectionResponse

func (r *IntrospectionResponse) UnmarshalJSON(data []byte) error {
	if r == nil {
		return fmt.Errorf("introspection response is nil")
	}
	type alias introspectionResponseJSON
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = IntrospectionResponse(decoded)
	r.raw = append(r.raw[:0], data...)
	return nil
}

// DecodeRaw unmarshals the preserved introspection payload into target.
func (r IntrospectionResponse) DecodeRaw(target any) error {
	if target == nil {
		return fmt.Errorf("target is nil")
	}
	if len(r.raw) == 0 {
		return fmt.Errorf("introspection raw payload is empty")
	}
	if err := json.Unmarshal(r.raw, target); err != nil {
		return fmt.Errorf("failed to decode introspection raw payload: %w", err)
	}
	return nil
}

// RawJWT returns the compact JWT response when RFC 9701 response mode was used.
func (r IntrospectionResponse) RawJWT() string {
	return r.rawJWT
}

// Introspector performs OAuth 2.0 token introspection requests (RFC 7662).
type Introspector struct {
	clientConfig
}

// NewIntrospector creates a client for OAuth 2.0 token introspection.
// Unlike [New], it does not require authorization-code-only options such as
// redirect URI or state store. Provider metadata is discovered automatically
// unless [WithProviderMetadata] supplies complete metadata.
func NewIntrospector(ctx context.Context, issuer string, opts ...Option) (*Introspector, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	i := &Introspector{clientConfig: defaultClientConfig(issuer)}
	for _, opt := range opts {
		if _, ok := opt.(AuthCodeOption); ok {
			return nil, fmt.Errorf("%w: auth-code option is not valid for token introspection", ErrInvalidConfiguration)
		}
		opt.applyConfig(&i.clientConfig)
	}

	i.clientConfig.initDefaults()
	if len(i.optionErrors) > 0 {
		return nil, i.optionErrors[0]
	}
	if err := i.validate(); err != nil {
		return nil, err
	}
	i.clientConfig.initMetadataClient()
	if err := i.clientConfig.resolveProviderFromDiscovery(ctx); err != nil {
		return nil, err
	}
	if err := i.resolveIntrospectionAuthMethod(); err != nil {
		return nil, err
	}
	if i.introspectionEndpoint(i.provider) == "" {
		return nil, fmt.Errorf("%w: introspection endpoint is not configured", ErrInvalidConfiguration)
	}
	return i, nil
}

func (i *Introspector) validate() error {
	if err := validateHTTPSAbsoluteURL("issuer", i.issuer); err != nil {
		return err
	}
	if i.clientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidConfiguration)
	}
	return nil
}

func (i *Introspector) resolveIntrospectionAuthMethod() error {
	supported := i.provider.IntrospectionEndpointAuthMethodsSupported
	if len(supported) == 0 {
		supported = i.provider.TokenEndpointAuthMethodsSupported
	}
	method, allowFallback, err := i.clientConfig.selectAuthMethodFromSupported(supported)
	if err != nil {
		return err
	}
	i.clientConfig.setAuthMethodState(method, allowFallback)
	return nil
}

// IntrospectToken introspects a token at the configured provider using RFC 7662.
func (i *Introspector) IntrospectToken(ctx context.Context, req IntrospectionRequest) (IntrospectionResponse, error) {
	return i.clientConfig.introspectToken(ctx, req)
}

// IntrospectToken introspects a token using the RP's configured provider and
// client authentication.
func (r *RP) IntrospectToken(ctx context.Context, req IntrospectionRequest) (IntrospectionResponse, error) {
	return r.clientConfig.introspectToken(ctx, req)
}

func (c *clientConfig) introspectToken(ctx context.Context, in IntrospectionRequest) (IntrospectionResponse, error) {
	if strings.TrimSpace(in.Token) == "" {
		return IntrospectionResponse{}, fmt.Errorf("%w: token is required", ErrIntrospectionFailed)
	}
	endpoint := c.introspectionEndpoint(c.provider)
	if endpoint == "" {
		return IntrospectionResponse{}, fmt.Errorf("%w: introspection endpoint is not configured", ErrIntrospectionFailed)
	}
	method, allowFallback := c.authMethodState()

	resp, status, preview, err := c.introspectTokenOnce(ctx, endpoint, in, method)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}
	if status == http.StatusOK {
		if allowFallback {
			c.setAuthMethodState(method, false)
		}
		return resp, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryResp, retryStatus, retryPreview, retryErr := c.introspectTokenOnce(ctx, endpoint, in, AuthMethodBasic)
		if retryErr != nil {
			return IntrospectionResponse{}, fmt.Errorf("%w: %v", ErrIntrospectionFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			c.setAuthMethodState(AuthMethodBasic, false)
			return retryResp, nil
		}
		return IntrospectionResponse{}, fmt.Errorf("%w: introspection endpoint returned status %d: %s", ErrIntrospectionFailed, retryStatus, retryPreview)
	}

	return IntrospectionResponse{}, fmt.Errorf("%w: introspection endpoint returned status %d: %s", ErrIntrospectionFailed, status, preview)
}

func (c *clientConfig) introspectTokenOnce(ctx context.Context, endpoint string, in IntrospectionRequest, method AuthMethod) (IntrospectionResponse, int, string, error) {
	var out IntrospectionResponse
	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return c.buildIntrospectionRequest(ctx, endpoint, in, method)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return c.attachDPoPProof(req, nonce)
		},
		handleResponse: func(body io.Reader) error {
			return json.NewDecoder(body).Decode(&out)
		},
		storeNonce: func(resp *http.Response) {
			c.extractAndStoreDPoPNonce(resp, endpoint)
		},
		successStatus: http.StatusOK,
		httpClient:    c.httpClient,
		useDPoP:       c.shouldUseDPoP(),
		cachedNonce:   c.cachedDPoPNonce(endpoint),
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return IntrospectionResponse{}, 0, "", fmt.Errorf("failed to decode introspection response: %w", decodeErr.Err)
		}
		return IntrospectionResponse{}, 0, "", fmt.Errorf("failed to execute introspection request: %w", err)
	}
	return out, status, preview, nil
}

func (c *clientConfig) buildIntrospectionRequest(ctx context.Context, endpoint string, in IntrospectionRequest, method AuthMethod) (*http.Request, error) {
	form := url.Values{}
	form.Set("token", strings.TrimSpace(in.Token))
	if strings.TrimSpace(string(in.TokenTypeHint)) != "" {
		form.Set("token_type_hint", strings.TrimSpace(string(in.TokenTypeHint)))
	}

	switch method {
	case AuthMethodPrivateKeyJWT:
		assertion, err := buildPrivateKeyClientAssertion(c.clientID, endpoint, c.clientKeyProvider, c.now(), c.randReader)
		if err != nil {
			return nil, fmt.Errorf("failed to build client assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		form.Set("client_id", c.clientID)
	case AuthMethodClientSecretJWT:
		assertion, err := buildClientSecretJWTAssertion(c.clientID, c.clientSecret, endpoint, c.now(), c.randReader)
		if err != nil {
			return nil, fmt.Errorf("failed to build client secret assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		form.Set("client_id", c.clientID)
	case AuthMethodTLSClientAuth, AuthMethodSelfSignedTLSClientAuth, AuthMethodNone:
		form.Set("client_id", c.clientID)
	case AuthMethodPost:
		form.Set("client_id", c.clientID)
		form.Set("client_secret", c.clientSecret)
	case AuthMethodBasic:
	}

	req, err := buildTokenRequestEnvelope(ctx, endpoint, form, method, c.clientID, c.clientSecret)
	if err != nil {
		return nil, err
	}
	if in.PreferJWTResponse {
		req.Header.Set("Accept", introspectionJWTMediaType)
	}
	return req, nil
}
