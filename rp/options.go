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

func WithClientID(id string) Option {
	return optionFunc(func(c *clientConfig) {
		c.clientID = strings.TrimSpace(id)
	})
}

func WithClientSecret(secret string) Option {
	return optionFunc(func(c *clientConfig) {
		c.clientSecret = secret
	})
}

func WithRedirectURI(uri string) Option {
	return rpOptionFunc(func(r *RP) {
		r.redirectURI = strings.TrimSpace(uri)
	})
}

type AuthorizationURLOption func(*authorizationURLConfig)

type authorizationURLConfig struct {
	authorizationDetails string
	parameters           url.Values
}

func WithMetadataClient(client *metadata.Client) Option {
	return optionFunc(func(c *clientConfig) {
		if client != nil {
			c.metadataClient = client
		}
	})
}

func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *clientConfig) {
		if logger != nil {
			c.logger = logger
		}
	})
}

func WithHTTPClient(client *http.Client) Option {
	return optionFunc(func(c *clientConfig) {
		if client != nil {
			c.httpClient = client
		}
	})
}

func WithScopes(scopes ...string) Option {
	return scopesOption{scopes: append([]string(nil), scopes...)}
}

type scopesOption struct {
	scopes []string
}

func (o scopesOption) apply(t optionTarget) {
	if len(o.scopes) == 0 {
		return
	}
	t.config().scopes = append([]string(nil), o.scopes...)
	if r, ok := t.(*RP); ok {
		r.scopesExplicit = true
	}
}

func WithClockSkew(skew time.Duration) Option {
	return rpOptionFunc(func(r *RP) {
		if skew >= 0 {
			r.clockSkew = skew
		}
	})
}

func WithProviderMetadata(provider metadata.Provider) Option {
	return providerMetadataOption{provider: provider}
}

type providerMetadataOption struct {
	provider metadata.Provider
}

func (o providerMetadataOption) apply(t optionTarget) {
	merged := mergeConfiguredProvider(t.config().provider, o.provider)
	t.config().provider = merged
	t.config().providerSet = true
	if r, ok := t.(*RP); ok {
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, o.provider)
		r.configuredProviderSet = true
	}
}

func WithAuthorizationEndpoint(endpoint string) Option {
	return rpOptionFunc(func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{AuthorizationEndpoint: endpoint},
		})
		r.configuredProviderSet = true
	})
}

func WithTokenEndpoint(endpoint string) Option {
	return rpOptionFunc(func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{TokenEndpoint: endpoint},
		})
		r.configuredProviderSet = true
	})
}

func WithUserInfoEndpoint(endpoint string) Option {
	return rpOptionFunc(func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{UserinfoEndpoint: endpoint})
		r.configuredProviderSet = true
	})
}

func WithJWKSURI(uri string) Option {
	return rpOptionFunc(func(r *RP) {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{JWKSURI: uri},
		})
		r.configuredProviderSet = true
	})
}

func WithPushedAuthorizationRequestEndpoint(endpoint string) Option {
	return rpOptionFunc(func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			PushedAuthorizationRequestEndpoint: endpoint,
		})
		r.configuredProviderSet = true
	})
}

func WithMTLSEndpointAliases(aliases metadata.MTLSEndpointAliases) Option {
	return rpOptionFunc(func(r *RP) {
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{MTLSEndpointAliases: aliases},
		})
		r.configuredProviderSet = true
	})
}

func WithProviderIssuer(issuer string) Option {
	return rpOptionFunc(func(r *RP) {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			return
		}
		r.configuredProvider = mergeConfiguredProvider(r.configuredProvider, metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{Issuer: issuer},
		})
		r.configuredProviderSet = true
	})
}

func WithAuthMethod(method AuthMethod) Option {
	return optionFunc(func(c *clientConfig) {
		c.authMethod = method
	})
}

func WithStateStore(store StateStore) Option {
	return rpOptionFunc(func(r *RP) {
		if store != nil {
			r.stateStore = store
		}
	})
}

func WithUserInfoTokenTransport(transport UserInfoTokenTransport) Option {
	return rpOptionFunc(func(r *RP) {
		r.userInfoTokenTransport = normalizeUserInfoTokenTransport(transport)
	})
}

func WithClientKeyProvider(provider ClientKeyProvider) Option {
	return optionFunc(func(c *clientConfig) {
		if provider != nil {
			c.clientKeyProvider = provider
		}
	})
}

func WithRequirePAR(require bool) Option {
	return rpOptionFunc(func(r *RP) {
		r.requirePAR = require
		r.requirePARExplicit = true
	})
}

func WithSenderConstrain(mode SenderConstraint) Option {
	return optionFunc(func(c *clientConfig) {
		c.senderConstrain = normalizeSenderConstrain(string(mode))
	})
}

func WithValidateAuthorizationResponseIssuer(validate bool) Option {
	return rpOptionFunc(func(r *RP) {
		r.validateAuthorizationResponseIssuer = validate
	})
}

func WithAllowUnsecuredIDTokens(allow bool) Option {
	return rpOptionFunc(func(r *RP) {
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

func WithDPoPNonceTTL(ttl time.Duration) Option {
	return optionFunc(func(c *clientConfig) {
		if ttl > 0 {
			c.dpopNonces = newDPoPNonceStore(ttl)
		}
	})
}

func WithAuthorizationDetails(details []map[string]any) Option {
	return rpOptionFunc(func(r *RP) {
		authorizationDetails, ok := marshalAuthorizationDetails(details)
		if !ok {
			return
		}
		r.authorizationDetails = authorizationDetails
	})
}

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

func WithResponseMode(mode string) Option {
	return rpOptionFunc(func(r *RP) {
		if r != nil {
			r.responseMode = strings.TrimSpace(mode)
			r.responseModeExplicit = true
		}
	})
}

func WithResponseType(responseType string) Option {
	return rpOptionFunc(func(r *RP) {
		if r != nil {
			r.responseType = strings.TrimSpace(responseType)
			r.responseTypeExplicit = true
		}
	})
}

func WithRequestMethod(method string) Option {
	return rpOptionFunc(func(r *RP) {
		if r != nil {
			r.requestMethod = normalizeRequestMethod(method)
			r.requestMethodExplicit = true
		}
	})
}

type RequestURIHandler func(signedJWT string) (requestURI string, err error)

func WithRequestURIMode(handler RequestURIHandler) Option {
	return rpOptionFunc(func(r *RP) {
		if r != nil {
			r.requestURIHandler = handler
		}
	})
}

type Profile int

const (
	OIDC Profile = iota
	OAuth2
	FAPI1Adv
	FAPI2SecurityProfile
	FAPI2MessageSigning
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

func WithProfile(profile Profile) Option {
	return rpOptionFunc(func(r *RP) {
		r.profile = profileFromPublic(profile)
		r.profileExplicit = true
	})
}

type DiscoveryMode int

const (
	DiscoveryAuto DiscoveryMode = iota
	DiscoveryOIDC
	DiscoveryOAuth2
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

func WithDiscoveryMode(mode DiscoveryMode) Option {
	return rpOptionFunc(func(r *RP) {
		r.discoveryMode = discoveryModeFromPublic(mode)
		r.discoveryModeExplicit = true
	})
}
