package rp

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/metadata"
)

// Option configures an RP instance.
type Option func(*RP)

// AuthorizationURLOption configures a single authorization URL generation.
type AuthorizationURLOption func(*authorizationURLConfig)

type authorizationURLConfig struct {
	authorizationDetails string
	parameters           url.Values
}

// WithOIDCClient sets the OIDC discovery and JWKS client.
func WithOIDCClient(client *metadata.Client) Option {
	return func(r *RP) {
		if client != nil {
			r.metadataClient = client
		}
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(r *RP) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithHTTPClient sets the HTTP client used by RP network calls.
func WithHTTPClient(client *http.Client) Option {
	return func(r *RP) {
		if client != nil {
			r.httpClient = client
		}
	}
}

// WithScopes sets requested authorization scopes.
func WithScopes(scopes ...string) Option {
	return func(r *RP) {
		if len(scopes) == 0 {
			return
		}
		r.scopes = append([]string(nil), scopes...)
		r.scopesExplicit = true
	}
}

// WithClockSkew sets clock skew tolerance for token claim checks.
func WithClockSkew(skew time.Duration) Option {
	return func(r *RP) {
		if skew >= 0 {
			r.clockSkew = skew
		}
	}
}

// WithProviderMetadata supplies provider metadata. Values are stored as partial
// configuration and merged with discovered metadata; caller-supplied values
// take precedence over discovered values.
func WithProviderMetadata(provider metadata.Provider) Option {
	return func(r *RP) {
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, provider)
		r.configuredProviderSet = true
	}
}

// WithAuthorizationEndpoint sets the authorization endpoint URL.
// The value is stored as partial metadata and merged with discovered metadata.
func WithAuthorizationEndpoint(endpoint string) Option {
	return func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{AuthorizationEndpoint: endpoint},
		})
		r.configuredProviderSet = true
	}
}

// WithTokenEndpoint sets the token endpoint URL.
// The value is stored as partial metadata and merged with discovered metadata.
func WithTokenEndpoint(endpoint string) Option {
	return func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{TokenEndpoint: endpoint},
		})
		r.configuredProviderSet = true
	}
}

// WithUserInfoEndpoint sets the userinfo endpoint URL.
// The value is stored as partial metadata and merged with discovered metadata.
func WithUserInfoEndpoint(endpoint string) Option {
	return func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{UserinfoEndpoint: endpoint})
		r.configuredProviderSet = true
	}
}

// WithJWKSURI sets the JWKS URI.
// The value is stored as partial metadata and merged with discovered metadata.
func WithJWKSURI(uri string) Option {
	return func(r *RP) {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{JWKSURI: uri},
		})
		r.configuredProviderSet = true
	}
}

// WithPushedAuthorizationRequestEndpoint sets the PAR endpoint URL.
// The value is stored as partial metadata and merged with discovered metadata.
func WithPushedAuthorizationRequestEndpoint(endpoint string) Option {
	return func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			PushedAuthorizationRequestEndpoint: endpoint,
		})
		r.configuredProviderSet = true
	}
}

// WithMTLSEndpointAliases sets the mTLS endpoint aliases.
// The value is stored as partial metadata and merged with discovered metadata.
func WithMTLSEndpointAliases(aliases metadata.MTLSEndpointAliases) Option {
	return func(r *RP) {
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{MTLSEndpointAliases: aliases},
		})
		r.configuredProviderSet = true
	}
}

// WithProviderIssuer sets the provider issuer in the configured metadata.
func WithProviderIssuer(issuer string) Option {
	return func(r *RP) {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{Issuer: issuer},
		})
		r.configuredProviderSet = true
	}
}

// WithAuthMethod sets the token endpoint client authentication method.
func WithAuthMethod(method AuthMethod) Option {
	return func(r *RP) {
		r.authMethod = method
	}
}

// WithStateStore sets the state store used for callback correlation and caller values.
//
// Callers typically provide implementations from `rp/store/memory` or `rp/store/cookie`.
func WithStateStore(store StateStore) Option {
	return func(r *RP) {
		if store != nil {
			r.stateStore = store
		}
	}
}

// WithUserInfoTokenTransport sets how UserInfo requests send access tokens.
func WithUserInfoTokenTransport(transport UserInfoTokenTransport) Option {
	return func(r *RP) {
		r.userInfoTokenTransport = normalizeUserInfoTokenTransport(transport)
	}
}

// WithClientKeyProvider sets the key provider for private_key_jwt and mTLS authentication.
func WithClientKeyProvider(provider ClientKeyProvider) Option {
	return func(r *RP) {
		if provider != nil {
			r.clientKeyProvider = provider
		}
	}
}

// WithRequirePAR forces the use of Pushed Authorization Requests (PAR).
func WithRequirePAR(require bool) Option {
	return func(r *RP) {
		r.requirePAR = require
		r.requirePARExplicit = true
	}
}

// WithSenderConstrain sets the sender-constraining mode used for outbound requests.
// Supported values are "", "mtls", and "dpop".
func WithSenderConstrain(mode string) Option {
	return func(r *RP) {
		r.senderConstrain = normalizeSenderConstrain(mode)
		r.senderConstrainExplicit = true
	}
}

// WithFAPIProfile sets the FAPI profile for strict validation.
// Supported values are "plain_fapi", "fapi2", "fapi1", etc.
func WithFAPIProfile(profile string) Option {
	return func(r *RP) {
		r.fapiProfile = normalizeFAPIProfile(profile)
	}
}

// WithAllowUnsecuredIDTokens allows acceptance of ID tokens with alg=none.
// For FAPI profiles, this option is ignored - unsecured tokens are always rejected.
func WithAllowUnsecuredIDTokens(allow bool) Option {
	return func(r *RP) {
		r.allowUnsecuredIDTokens = allow
	}
}

func withNow(now func() time.Time) Option {
	return func(r *RP) {
		if now != nil {
			r.now = now
		}
	}
}

func withRandReader(reader io.Reader) Option {
	return func(r *RP) {
		if reader != nil {
			r.randReader = reader
		}
	}
}

// WithDPoPNonceTTL sets the TTL for cached DPoP nonces.
func WithDPoPNonceTTL(ttl time.Duration) Option {
	return func(r *RP) {
		if ttl > 0 {
			r.dpopNonces = newDPoPNonceStore(ttl)
		}
	}
}

// WithAuthorizationDetails sets the Rich Authorization Request (RAR) details.
// The details should be a slice of maps containing authorization detail types.
func WithAuthorizationDetails(details []map[string]any) Option {
	return func(r *RP) {
		authorizationDetails, ok := marshalAuthorizationDetails(details)
		if !ok {
			return
		}
		r.authorizationDetails = authorizationDetails
	}
}

// SetAuthorizationDetails sets Rich Authorization Request (RAR) details for a
// single authorization URL generation.
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

// SetAuthParam sets a single authorization request parameter for a
// specific authorization URL generation. The parameter is added to the browser
// redirect query or pushed authorization request body.
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

// WithResponseMode sets the OAuth 2.0 response_mode for authorization requests.
// Common values are "query" (default) and "form_post".
func WithResponseMode(mode string) Option {
	return func(r *RP) {
		if r != nil {
			r.responseMode = strings.TrimSpace(mode)
			r.responseModeExplicit = true
		}
	}
}

// WithResponseType sets the OAuth 2.0 response_type for authorization requests.
func WithResponseType(responseType string) Option {
	return func(r *RP) {
		if r != nil {
			r.responseType = strings.TrimSpace(responseType)
			r.responseTypeExplicit = true
		}
	}
}

// WithRequestMethod sets the FAPI request method. Use "signed_non_repudiation"
// to enable JAR (signed request objects) for message-signing profiles.
func WithRequestMethod(method string) Option {
	return func(r *RP) {
		if r != nil {
			r.requestMethod = normalizeRequestMethod(method)
			r.requestMethodExplicit = true
		}
	}
}

// Profile selects an RP behavior profile that applies sensible defaults.
type Profile int

const (
	// OIDC selects standard OpenID Connect defaults.
	OIDC Profile = iota
	// OAuth2 selects OAuth 2.0-only defaults (no forced openid scope).
	OAuth2
	// FAPI1Adv selects FAPI 1.0 Advanced profile defaults.
	FAPI1Adv
	// FAPI2SecurityProfile selects FAPI 2.0 Security Profile defaults.
	FAPI2SecurityProfile
	// FAPI2MessageSigning selects FAPI 2.0 Message Signing defaults.
	FAPI2MessageSigning
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
	default:
		return profileOIDC
	}
}

// WithProfile sets an RP behavior profile that applies sensible defaults
// for scopes, discovery mode, and security settings. Profile defaults only
// fill fields that the caller has not already set via explicit options.
func WithProfile(profile Profile) Option {
	return func(r *RP) {
		r.profile = profileFromPublic(profile)
		r.profileExplicit = true
	}
}

// DiscoveryMode controls whether and how provider metadata is discovered.
type DiscoveryMode int

const (
	// DiscoveryAuto selects discovery type from profile and current RP needs.
	DiscoveryAuto DiscoveryMode = iota
	// DiscoveryOIDC forces OIDC provider metadata discovery.
	DiscoveryOIDC
	// DiscoveryOAuth2 forces OAuth 2.0 authorization server metadata discovery.
	DiscoveryOAuth2
	// DiscoveryDisabled never discovers; fails if required metadata is missing.
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

// WithDiscoveryMode sets the discovery policy for provider metadata resolution.
func WithDiscoveryMode(mode DiscoveryMode) Option {
	return func(r *RP) {
		r.discoveryMode = discoveryModeFromPublic(mode)
		r.discoveryModeExplicit = true
	}
}
