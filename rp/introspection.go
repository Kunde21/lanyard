package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
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

	// Cnf is the RFC 7800 confirmation claim of the introspected token,
	// carrying its proof-of-possession key binding (e.g. cnf.jkt for
	// DPoP-bound tokens, cnf.x5t#S256 for mTLS-bound tokens). Nil when the
	// response carries no cnf claim.
	//
	// Introspection is a pure passthrough: the binding is not enforced
	// automatically. Callers can cross-check it via
	// Confirmation.VerifyDPoPBinding / VerifyMTLSBinding — for a DPoP client,
	// against RP.DPoPKeyThumbprint().
	Cnf *Confirmation `json:"cnf,omitempty"`

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

func (c *clientConfig) introspectionAuthMethod() (AuthMethod, bool) {
	supported := c.provider.IntrospectionEndpointAuthMethodsSupported
	if len(supported) > 0 {
		method, allowFallback, err := c.selectAuthMethodFromSupported(supported)
		if err == nil {
			return method, allowFallback
		}
	}
	return c.authMethodState()
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

	method, allowFallback := c.introspectionAuthMethod()

	resp, status, preview, err := c.introspectTokenOnce(ctx, endpoint, in, method)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}
	if status == http.StatusOK {
		return resp, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryResp, retryStatus, retryPreview, retryErr := c.introspectTokenOnce(ctx, endpoint, in, AuthMethodBasic)
		if retryErr != nil {
			return IntrospectionResponse{}, fmt.Errorf("%w: %v", ErrIntrospectionFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			return retryResp, nil
		}
		return IntrospectionResponse{}, fmt.Errorf("%w: introspection endpoint returned status %d: %s", ErrIntrospectionFailed, retryStatus, retryPreview)
	}

	return IntrospectionResponse{}, fmt.Errorf("%w: introspection endpoint returned status %d: %s", ErrIntrospectionFailed, status, preview)
}

func (c *clientConfig) introspectTokenOnce(ctx context.Context, endpoint string, in IntrospectionRequest, method AuthMethod) (IntrospectionResponse, int, string, error) {
	var bodyBytes []byte

	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return c.buildIntrospectionRequest(ctx, endpoint, in, method)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return c.attachDPoPProof(req, nonce)
		},
		handleResponse: func(body io.Reader) error {
			data, readErr := io.ReadAll(body)
			if readErr != nil {
				return fmt.Errorf("failed to read introspection response: %w", readErr)
			}
			bodyBytes = data
			return nil
		},
		storeNonce: func(resp *http.Response) {
			c.extractAndStoreDPoPNonce(resp, endpoint)
		},
		successStatus: http.StatusOK,
		httpClient:    c.httpClient,
		useDPoP:       c.shouldUseDPoPForMethod(method),
		cachedNonce:   c.cachedDPoPNonce(endpoint),
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return IntrospectionResponse{}, 0, "", fmt.Errorf("failed to decode introspection response: %w", decodeErr.Err)
		}
		return IntrospectionResponse{}, 0, "", fmt.Errorf("failed to execute introspection request: %w", err)
	}

	if status != http.StatusOK {
		return IntrospectionResponse{}, status, preview, nil
	}

	if in.PreferJWTResponse || looksLikeJWT(bodyBytes) {
		decoded, jwtErr := c.validateIntrospectionJWT(ctx, strings.TrimSpace(string(bodyBytes)), in)
		if jwtErr != nil {
			return IntrospectionResponse{}, status, preview, jwtErr
		}
		return decoded, status, preview, nil
	}

	var out IntrospectionResponse
	if err := json.Unmarshal(bodyBytes, &out); err != nil {
		return IntrospectionResponse{}, 0, "", fmt.Errorf("failed to decode introspection response: %w", err)
	}
	return out, status, preview, nil
}

func looksLikeJWT(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), "eyJ")
}

func (c *clientConfig) shouldUseDPoPForMethod(method AuthMethod) bool {
	if c.senderConstrain != SenderConstraintNone {
		return c.senderConstrain == SenderConstraintDPoP && c.clientKeyProvider != nil && isDPoPSupported(method)
	}
	return c.clientKeyProvider != nil && isDPoPSupported(method)
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

var supportedIntrospectionJWTAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
}

// supportedIntrospectionJWEAlgs restricts key encryption to algorithms
// considered safe (RFC 8725). RSA1_5 is deliberately excluded.
var supportedIntrospectionJWEAlgs = []jose.KeyAlgorithm{
	jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
}

var supportedIntrospectionJWEEncs = []jose.ContentEncryption{
	jose.A128GCM, jose.A192GCM, jose.A256GCM,
	jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512,
}

type introspectionJWTClaims struct {
	Iss                string                `json:"iss"`
	Aud                audienceClaim         `json:"aud"`
	Iat                *int64                `json:"iat"`
	TokenIntrospection IntrospectionResponse `json:"token_introspection"`
}

// decryptIntrospectionJWE decrypts the outer JWE of a signed-then-encrypted
// nested introspection response (RFC 9701 section 5) and returns the inner
// signed JWT. Requires a key configured via [WithIntrospectionDecryptionKey].
func (c *clientConfig) decryptIntrospectionJWE(raw string) (string, error) {
	if c.introspectionDecryptionKey == nil {
		return "", fmt.Errorf("encrypted introspection JWT received but no decryption key is configured")
	}
	obj, err := jose.ParseEncrypted(raw, supportedIntrospectionJWEAlgs, supportedIntrospectionJWEEncs)
	if err != nil {
		return "", fmt.Errorf("failed to parse encrypted introspection JWT: %w", err)
	}
	if typ, _ := obj.Header.ExtraHeaders["typ"].(string); typ != "" && !strings.EqualFold(typ, "token-introspection+jwt") {
		return "", fmt.Errorf("encrypted introspection JWT typ mismatch: %q", typ)
	}
	plaintext, err := obj.Decrypt(c.introspectionDecryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt introspection JWT: %w", err)
	}
	return string(plaintext), nil
}

func (c *clientConfig) validateIntrospectionJWT(ctx context.Context, raw string, req IntrospectionRequest) (IntrospectionResponse, error) {
	if raw == "" {
		return IntrospectionResponse{}, fmt.Errorf("empty introspection JWT response")
	}

	parts := strings.Split(raw, ".")
	inner := raw
	switch len(parts) {
	case 3:
		// Plain signed JWT; validated below.
	case 5:
		// Signed-then-encrypted nested JWT (RFC 9701 section 5): decrypt the
		// outer JWE, then validate the inner signed JWT below.
		decrypted, err := c.decryptIntrospectionJWE(raw)
		if err != nil {
			return IntrospectionResponse{}, err
		}
		inner = decrypted
		if len(strings.Split(inner, ".")) != 3 {
			return IntrospectionResponse{}, fmt.Errorf("nested introspection JWT plaintext must be a signed JWT")
		}
	default:
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT must be a signed or nested JWT, got %d parts", len(parts))
	}

	parsed, err := josejwt.ParseSigned(inner, supportedIntrospectionJWTAlgs)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("failed to parse introspection JWT: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT missing JOSE headers")
	}

	header := parsed.Headers[0]
	if header.Algorithm == "none" {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT must not use 'none' algorithm")
	}

	typ, _ := header.ExtraHeaders["typ"].(string)
	if typ == "" {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT missing typ header")
	}
	if !strings.EqualFold(typ, "token-introspection+jwt") {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT typ mismatch: %q", typ)
	}

	if len(c.provider.IntrospectionSigningAlgValuesSupported) > 0 {
		if !slices.ContainsFunc(c.provider.IntrospectionSigningAlgValuesSupported, func(a string) bool {
			return strings.EqualFold(a, string(header.Algorithm))
		}) {
			return IntrospectionResponse{}, fmt.Errorf("introspection JWT algorithm %q not in provider's supported algorithms %v", header.Algorithm, c.provider.IntrospectionSigningAlgValuesSupported)
		}
	}

	jwksURI := c.provider.JWKSURI
	if jwksURI == "" {
		return IntrospectionResponse{}, fmt.Errorf("provider metadata missing jwks_uri for introspection JWT verification")
	}

	keySet, err := c.metadataClient.RemoteKeySetFromJWKSURI(jwksURI)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("failed to load JWKS for introspection JWT verification: %w", err)
	}

	var claims introspectionJWTClaims
	if header.KeyID != "" {
		key, err := keySet.Key(ctx, header.KeyID)
		if err != nil {
			return IntrospectionResponse{}, fmt.Errorf("failed to find introspection JWT signing key: %w", err)
		}
		if err := parsed.Claims(key.Key, &claims); err != nil {
			return IntrospectionResponse{}, fmt.Errorf("introspection JWT signature verification failed: %w", err)
		}
	} else {
		keys, err := keySet.Keys(ctx)
		if err != nil {
			return IntrospectionResponse{}, fmt.Errorf("failed to load introspection JWT signing keys: %w", err)
		}
		matched := 0
		for _, key := range keys {
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			var candidate introspectionJWTClaims
			if err := parsed.Claims(key.Key, &candidate); err != nil {
				continue
			}
			matched++
			claims = candidate
		}
		if matched != 1 {
			return IntrospectionResponse{}, fmt.Errorf("introspection JWT verification requires exactly one matching key, got %d", matched)
		}
	}

	if claims.Iss != c.provider.Issuer {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT iss mismatch: got %q, want %q", claims.Iss, c.provider.Issuer)
	}

	expectedAud := req.ExpectedJWTAudience
	if expectedAud == "" {
		expectedAud = c.clientID
	}
	audMatch := false
	for _, aud := range claims.Aud {
		if aud == expectedAud {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT audience mismatch")
	}

	if claims.Iat == nil {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT missing required iat claim")
	}
	iat := time.Unix(*claims.Iat, 0).UTC()
	now := c.now()
	clockSkew := 5 * time.Minute
	if iat.After(now.Add(clockSkew)) {
		return IntrospectionResponse{}, fmt.Errorf("introspection JWT iat in the future")
	}

	out := claims.TokenIntrospection
	out.rawJWT = raw
	return out, nil
}
