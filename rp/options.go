package rp

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"go.opentelemetry.io/otel/trace"
)

// WithClientID sets the OAuth client identifier.
func WithClientID(id string) Option {
	return optionFunc(func(c *clientConfig) {
		c.clientID = strings.TrimSpace(id)
	})
}

// WithClientSecret sets the OAuth client secret.
func WithClientSecret(secret string) Option {
	return optionFunc(func(c *clientConfig) {
		c.clientSecret = secret
	})
}

// WithRedirectURI sets the browser-flow redirect URI.
func WithRedirectURI(uri string) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.redirectURI = strings.TrimSpace(uri)
	})
}

// AuthorizationURLOption configures a single authorization URL request.
type AuthorizationURLOption func(*authorizationURLConfig)

type authorizationURLConfig struct {
	authorizationDetails string
	parameters           url.Values
	resources            []string
	grantManagement      *grantManagementRequest
	claims               string
	err                  error
}

// WithMetadataClient sets the metadata client used for discovery and JWKS setup.
func WithMetadataClient(client *metadata.Client) Option {
	return optionFunc(func(c *clientConfig) {
		if client != nil {
			c.metadataClient = client
		}
	})
}

// WithLogger sets the structured logger used by discovery and token requests.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *clientConfig) {
		if logger != nil {
			c.logger = logger
		}
	})
}

// WithHTTPClient sets the HTTP client used for discovery and token requests.
func WithHTTPClient(client *http.Client) Option {
	return optionFunc(func(c *clientConfig) {
		if client != nil {
			c.httpClient = client
		}
	})
}

// WithScopes sets default OAuth scopes.
func WithScopes(scopes ...string) Option {
	return scopesOption{scopes: append([]string(nil), scopes...)}
}

type scopesOption struct {
	scopes []string
}

func (o scopesOption) applyConfig(c *clientConfig) {
	if len(o.scopes) == 0 {
		return
	}
	c.scopes = append([]string(nil), o.scopes...)
	c.scopesExplicit = true
}

// WithClockSkew sets the allowed clock skew for token validation.
func WithClockSkew(skew time.Duration) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if skew >= 0 {
			r.clockSkew = skew
		}
	})
}

// WithProviderMetadata supplies provider metadata and can skip discovery when complete.
func WithProviderMetadata(provider metadata.Provider) Option {
	return providerMetadataOption{provider: provider}
}

type providerMetadataOption struct {
	provider metadata.Provider
}

func (o providerMetadataOption) applyConfig(c *clientConfig) {
	c.provider = mergeConfiguredProvider(c.provider, o.provider)
	c.providerSet = true
	c.configuredProvider = mergeConfiguredProvider(c.configuredProvider, o.provider)
	c.configuredProviderSet = true
}

// WithAuthMethod sets the token endpoint client authentication method.
func WithAuthMethod(method AuthMethod) Option {
	return optionFunc(func(c *clientConfig) {
		c.authMethod = method
	})
}

// WithStateStore sets the browser-flow state store.
func WithStateStore(store StateStore) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if store != nil {
			r.stateStore = store
		}
	})
}

// WithCorrelationStore sets the browser-flow callback correlation store.
func WithCorrelationStore(store CorrelationStore) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if store != nil {
			r.stateStore = store
		}
	})
}

// WithUserInfoTokenTransport sets how access tokens are sent to the UserInfo endpoint.
func WithUserInfoTokenTransport(transport UserInfoTokenTransport) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.userInfoTokenTransport = normalizeUserInfoTokenTransport(transport)
	})
}

// WithClientKeyProvider sets the private key provider for signed client authentication and DPoP.
func WithClientKeyProvider(provider ClientKeyProvider) Option {
	return optionFunc(func(c *clientConfig) {
		if provider != nil {
			c.clientKeyProvider = provider
		}
	})
}

// WithRequirePAR controls whether authorization requests must use PAR.
func WithRequirePAR(require bool) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.requirePAR = require
		r.requirePARExplicit = true
	})
}

// WithSenderConstrain selects DPoP, mTLS, or no sender constraining.
func WithSenderConstrain(mode SenderConstraint) Option {
	return optionFunc(func(c *clientConfig) {
		c.senderConstrain = normalizeSenderConstrain(string(mode))
	})
}

// WithValidateAuthorizationResponseIssuer controls callback issuer validation.
func WithValidateAuthorizationResponseIssuer(validate bool) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.validateAuthorizationResponseIssuer = validate
	})
}

// WithAllowUnsecuredIDTokens controls whether unsigned ID tokens are accepted.
func WithAllowUnsecuredIDTokens(allow bool) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.allowUnsecuredIDTokens = allow
	})
}

func withNow(now func() time.Time) Option {
	return optionFunc(func(c *clientConfig) {
		if now != nil {
			c.now = now
		}
	})
}

func withRandReader(reader io.Reader) Option {
	return optionFunc(func(c *clientConfig) {
		if reader != nil {
			c.randReader = reader
		}
	})
}

// WithDPoPNonceTTL sets how long DPoP nonces are cached per endpoint.
func WithDPoPNonceTTL(ttl time.Duration) Option {
	return optionFunc(func(c *clientConfig) {
		if ttl > 0 {
			c.dpopNonces = newDPoPNonceStore(ttl)
		}
	})
}

// WithAuthorizationDetails sets default Rich Authorization Request details.
func WithAuthorizationDetails(details []map[string]any) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		authorizationDetails, ok := marshalAuthorizationDetails(details)
		if !ok {
			return
		}
		r.authorizationDetails = authorizationDetails
	})
}

// SetAuthorizationDetails sets Rich Authorization Request details for one authorization URL.
func SetAuthorizationDetails(details []map[string]any) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		authorizationDetails, ok := marshalAuthorizationDetails(details)
		if !ok {
			return
		}
		cfg.authorizationDetails = authorizationDetails
	}
}

// SetResources sets OAuth 2.0 resource indicators for one authorization request.
func SetResources(resources ...string) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		normalized, err := normalizeResources(resources)
		if err != nil {
			cfg.err = err
			return
		}
		cfg.resources = normalized
	}
}

// SetClaims overrides the claims request parameter (OIDC Core section 5.5)
// for one authorization request. raw must be a JSON object; it is passed
// through verbatim as the claims parameter value.
func SetClaims(raw string) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		if strings.TrimSpace(raw) == "" {
			cfg.claims = ""
			return
		}
		if !isValidClaimsJSON(raw) {
			cfg.err = fmt.Errorf("%w: claims parameter must be a JSON object", ErrInvalidConfiguration)
			return
		}
		cfg.claims = raw
	}
}

// WithClaims sets the default claims request parameter (OIDC Core section
// 5.5) for authorization requests. raw must be a JSON object; override it per
// request with [SetClaims].
func WithClaims(raw string) Option {
	return claimsOption{raw: raw}
}

type claimsOption struct {
	raw string
}

func (o claimsOption) applyConfig(c *clientConfig) {
	if strings.TrimSpace(o.raw) == "" {
		return
	}
	if !isValidClaimsJSON(o.raw) {
		c.optionErrors = append(c.optionErrors, fmt.Errorf(
			"%w: claims parameter must be a JSON object", ErrInvalidConfiguration))
		return
	}
	c.claimsParameter = o.raw
}

func isValidClaimsJSON(raw string) bool {
	var parsed map[string]any
	return json.Unmarshal([]byte(raw), &parsed) == nil
}

// SetGrantManagementAction sets the grant management parameters
// (grant_management_action and grant_id) for one authorization request.
// grant_id must be empty for [GrantActionCreate] and non-empty for
// [GrantActionMerge], [GrantActionUpdate], and [GrantActionReplace].
func SetGrantManagementAction(action GrantManagementAction, grantID string) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		grant := &grantManagementRequest{action: action, grantID: strings.TrimSpace(grantID)}
		if err := grant.validate(); err != nil {
			cfg.err = err
			return
		}
		cfg.grantManagement = grant
	}
}

// SetGrantID references an existing grant for one authorization request via
// the grant_id parameter, without requesting a specific grant management
// action.
func SetGrantID(grantID string) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		grantID = strings.TrimSpace(grantID)
		if grantID == "" {
			cfg.err = fmt.Errorf("%w: grant_id must not be empty", ErrInvalidConfiguration)
			return
		}
		cfg.grantManagement = &grantManagementRequest{grantID: grantID}
	}
}

// WithResources sets default OAuth 2.0 resource indicators (RFC 8707).
func WithResources(resources ...string) Option {
	return resourcesOption{resources: append([]string(nil), resources...)}
}

type resourcesOption struct {
	resources []string
}

func (o resourcesOption) applyConfig(c *clientConfig) {
	normalized, err := normalizeResources(o.resources)
	if err != nil {
		c.optionErrors = append(c.optionErrors, err)
		return
	}
	c.resources = normalized
}

// WithInitialAccessToken sets the bearer token authorizing dynamic client
// registration requests (RFC 7591 section 3.3) at providers that require one.
func WithInitialAccessToken(token string) Option {
	return initialAccessTokenOption{token: strings.TrimSpace(token)}
}

type initialAccessTokenOption struct {
	token string
}

func (o initialAccessTokenOption) applyConfig(c *clientConfig) {
	c.initialAccessToken = o.token
}

// WithTracerProvider sets the OpenTelemetry tracer provider the RP creates
// its tracer from. When unset, the global provider is used (a no-op tracer
// unless the application installs one). Spans never contain tokens,
// credentials, or other secret values; see the package documentation.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return tracerProviderOption{provider: tp}
}

type tracerProviderOption struct {
	provider trace.TracerProvider
}

func (o tracerProviderOption) applyConfig(c *clientConfig) {
	if o.provider == nil {
		return
	}
	c.tracer = o.provider.Tracer(tracerName)
}

// WithIntrospectionDecryptionKey sets the private key used to decrypt encrypted
// RFC 9701 introspection responses (signed-then-encrypted nested JWTs). The
// corresponding public key must be registered with the authorization server
// (e.g. via the jwks or jwks_uri client metadata, together with
// introspection_encrypted_response_alg). Supports *rsa.PrivateKey and
// *ecdsa.PrivateKey.
func WithIntrospectionDecryptionKey(key crypto.PrivateKey) Option {
	return introspectionDecryptionKeyOption{key: key}
}

type introspectionDecryptionKeyOption struct {
	key crypto.PrivateKey
}

func (o introspectionDecryptionKeyOption) applyConfig(c *clientConfig) {
	if o.key == nil {
		c.optionErrors = append(c.optionErrors, fmt.Errorf(
			"%w: introspection decryption key must not be nil", ErrInvalidConfiguration))
		return
	}
	c.introspectionDecryptionKey = o.key
}

// SetAuthParam sets an extra authorization request parameter.
func SetAuthParam(key, value string) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		name := strings.TrimSpace(key)
		if name == "" {
			return
		}
		if cfg.parameters == nil {
			cfg.parameters = make(url.Values)
		}
		cfg.parameters.Set(name, value)
	}
}

func marshalAuthorizationDetails(details []map[string]any) (string, bool) {
	if len(details) == 0 {
		return "", false
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// WithResponseMode sets the authorization response mode.
func WithResponseMode(mode string) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if r != nil {
			r.responseMode = strings.TrimSpace(mode)
			r.responseModeExplicit = true
		}
	})
}

// WithResponseType sets the authorization response type.
func WithResponseType(responseType string) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if r != nil {
			r.responseType = strings.TrimSpace(responseType)
			r.responseTypeExplicit = true
		}
	})
}

// WithRequestMethod sets the authorization request object mode.
func WithRequestMethod(method string) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if r != nil {
			r.requestMethod = normalizeRequestMethod(method)
			r.requestMethodExplicit = true
		}
	})
}

// RequestURIHandler stores a signed request object and returns its request_uri.
type RequestURIHandler func(signedJWT string) (requestURI string, err error)

// WithRequestURIMode enables request_uri mode using handler.
func WithRequestURIMode(handler RequestURIHandler) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		if r != nil {
			r.requestURIHandler = handler
		}
	})
}

// Profile selects a behavior profile for relying-party defaults.
type Profile int

const (
	// OIDC selects OpenID Connect defaults.
	OIDC Profile = iota
	// OAuth2 selects OAuth 2.0-only defaults.
	OAuth2
	// FAPI1Adv selects FAPI 1.0 Advanced defaults.
	FAPI1Adv
	// FAPI2SecurityProfile selects FAPI 2.0 Security Profile defaults.
	FAPI2SecurityProfile
	// FAPI2MessageSigning selects FAPI 2.0 Message Signing defaults.
	FAPI2MessageSigning
	// PlainFAPI selects unsigned request defaults for FAPI-style testing.
	PlainFAPI
)

func profileFromPublic(p Profile) profileType {
	switch p {
	case OAuth2:
		return profileOAuth2
	case FAPI1Adv:
		return profileFAPI1Adv
	case FAPI2SecurityProfile:
		return profileFAPI2SecurityProfile
	case FAPI2MessageSigning:
		return profileFAPI2MessageSigning
	case PlainFAPI:
		return profilePlainFAPI
	default:
		return profileOIDC
	}
}

// WithProfile applies default behavior for the selected profile.
func WithProfile(profile Profile) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.profile = profileFromPublic(profile)
		r.profileExplicit = true
	})
}

// DiscoveryMode selects how provider metadata discovery is performed.
type DiscoveryMode int

const (
	// DiscoveryAuto chooses the discovery mode from configured scopes and metadata.
	DiscoveryAuto DiscoveryMode = iota
	// DiscoveryOIDC forces OpenID Connect provider discovery.
	DiscoveryOIDC
	// DiscoveryOAuth2 forces OAuth 2.0 authorization server discovery.
	DiscoveryOAuth2
	// DiscoveryDisabled disables metadata discovery.
	DiscoveryDisabled
)

func discoveryModeFromPublic(m DiscoveryMode) discoveryModeType {
	switch m {
	case DiscoveryOIDC:
		return discoveryModeOIDC
	case DiscoveryOAuth2:
		return discoveryModeOAuth2
	case DiscoveryDisabled:
		return discoveryModeDisabled
	default:
		return discoveryModeAuto
	}
}

// WithDiscoveryMode configures provider metadata discovery behavior.
func WithDiscoveryMode(mode DiscoveryMode) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.discoveryMode = discoveryModeFromPublic(mode)
		r.discoveryModeExplicit = true
	})
}
