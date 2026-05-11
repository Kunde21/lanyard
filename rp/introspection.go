package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
