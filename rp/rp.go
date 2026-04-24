package rp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp/store/memory"
	"github.com/Kunde21/lanyard/validateurl"
)

const defaultClockSkew = 5 * time.Minute

type requestMethodType int

const (
	requestMethodPlain requestMethodType = iota
	requestMethodSignedNonRepudiation
)

type profileType int

const (
	profileOIDC profileType = iota
	profileOAuth2
	profileFAPI1Adv
	profileFAPI2SecurityProfile
	profileFAPI2MessageSigning
	profilePlainFAPI
)

func (p profileType) isFAPI() bool {
	switch p {
	case profileFAPI1Adv, profileFAPI2SecurityProfile, profileFAPI2MessageSigning, profilePlainFAPI:
		return true
	default:
		return false
	}
}

type discoveryModeType int

const (
	discoveryModeAuto discoveryModeType = iota
	discoveryModeOIDC
	discoveryModeOAuth2
	discoveryModeDisabled
)

func normalizeRequestMethod(raw string) requestMethodType {
	if strings.EqualFold(strings.TrimSpace(raw), "signed_non_repudiation") {
		return requestMethodSignedNonRepudiation
	}
	return requestMethodPlain
}

func (r requestMethodType) isSigned() bool {
	return r == requestMethodSignedNonRepudiation
}

// RP is an OpenID Connect relying party for the Authorization Code flow.
type RP struct {
	clientConfig

	redirectURI string

	scopesExplicit bool

	stateStore StateStore

	configuredProvider    metadata.Provider
	configuredProviderSet bool

	userInfoTokenTransport UserInfoTokenTransport

	requirePAR              bool
	requirePARExplicit      bool
	senderConstrainExplicit bool
	allowUnsecuredIDTokens  bool

	responseMode                        string
	responseModeExplicit                bool
	responseType                        string
	responseTypeExplicit                bool
	requestMethod                       requestMethodType
	requestMethodExplicit               bool
	requestURIHandler                   RequestURIHandler
	validateAuthorizationResponseIssuer bool

	profile               profileType
	profileExplicit       bool
	discoveryMode         discoveryModeType
	discoveryModeExplicit bool

	clockSkew time.Duration

	authorizationDetails string
}

// New creates a browser-flow relying party that is ready to generate an
// authorization URL immediately after construction.
//
// If no state store is provided via [WithStateStore], New creates a default
// in-memory state store from rp/store/memory with a 10-minute TTL. If no
// metadata client is provided via [WithMetadataClient], New constructs a
// default [metadata.Client] with the configured HTTP client and logger.
//
// Provider metadata is discovered automatically unless [WithProviderMetadata]
// supplies complete metadata or [WithDiscoveryMode] is set to
// [DiscoveryDisabled].
func New(ctx context.Context, issuer string, opts ...Option) (*RP, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	r := newRP(issuer)

	for _, opt := range opts {
		opt.apply(r)
	}

	r.applyProfileDefaults()
	r.initDefaults()

	if err := r.validate(); err != nil {
		return nil, err
	}

	r.initMetadataClient()

	if err := r.resolveProvider(ctx); err != nil {
		return nil, err
	}

	if err := r.resolveAuthMethod(); err != nil {
		return nil, err
	}

	if err := r.validateProviderReadyForAuthorizationURL(); err != nil {
		return nil, err
	}

	r.finalizeSecurityDefaults()

	return r, nil
}

func (r *RP) authorizationResponseType() string {
	if strings.TrimSpace(r.responseType) != "" {
		return strings.TrimSpace(r.responseType)
	}
	return "code"
}

func mergeProviderMissing(dst, src metadata.Provider) metadata.Provider {
	merged := dst
	if merged.AuthorizationEndpoint == "" {
		merged.AuthorizationEndpoint = src.AuthorizationEndpoint
	}
	if merged.TokenEndpoint == "" {
		merged.TokenEndpoint = src.TokenEndpoint
	}
	if merged.JWKSURI == "" {
		merged.JWKSURI = src.JWKSURI
	}
	if merged.UserinfoEndpoint == "" {
		merged.UserinfoEndpoint = src.UserinfoEndpoint
	}
	if merged.PushedAuthorizationRequestEndpoint == "" {
		merged.PushedAuthorizationRequestEndpoint = src.PushedAuthorizationRequestEndpoint
	}
	if merged.Issuer == "" {
		merged.Issuer = src.Issuer
	}
	if len(merged.ResponseTypesSupported) == 0 {
		merged.ResponseTypesSupported = src.ResponseTypesSupported
	}
	if len(merged.IDTokenSigningAlgValuesSupported) == 0 {
		merged.IDTokenSigningAlgValuesSupported = src.IDTokenSigningAlgValuesSupported
	}
	if len(merged.SubjectTypesSupported) == 0 {
		merged.SubjectTypesSupported = src.SubjectTypesSupported
	}
	if len(merged.TokenEndpointAuthMethodsSupported) == 0 {
		merged.TokenEndpointAuthMethodsSupported = src.TokenEndpointAuthMethodsSupported
	}
	if len(merged.RequestObjectSigningAlgValuesSupported) == 0 {
		merged.RequestObjectSigningAlgValuesSupported = src.RequestObjectSigningAlgValuesSupported
	}
	if len(merged.AuthorizationSigningAlgValuesSupported) == 0 {
		merged.AuthorizationSigningAlgValuesSupported = src.AuthorizationSigningAlgValuesSupported
	}
	if merged.MTLSEndpointAliases.TokenEndpoint == "" {
		merged.MTLSEndpointAliases.TokenEndpoint = src.MTLSEndpointAliases.TokenEndpoint
	}
	if merged.MTLSEndpointAliases.UserinfoEndpoint == "" {
		merged.MTLSEndpointAliases.UserinfoEndpoint = src.MTLSEndpointAliases.UserinfoEndpoint
	}
	if merged.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint == "" {
		merged.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint = src.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint
	}
	if len(merged.CodeChallengeMethodsSupported) == 0 {
		merged.CodeChallengeMethodsSupported = src.CodeChallengeMethodsSupported
	}
	if len(merged.ResponseModesSupported) == 0 {
		merged.ResponseModesSupported = src.ResponseModesSupported
	}
	if len(merged.TokenEndpointAuthSigningAlgValuesSupported) == 0 {
		merged.TokenEndpointAuthSigningAlgValuesSupported = src.TokenEndpointAuthSigningAlgValuesSupported
	}
	if len(merged.IDTokenEncryptionAlgValuesSupported) == 0 {
		merged.IDTokenEncryptionAlgValuesSupported = src.IDTokenEncryptionAlgValuesSupported
	}
	if len(merged.IDTokenEncryptionEncValuesSupported) == 0 {
		merged.IDTokenEncryptionEncValuesSupported = src.IDTokenEncryptionEncValuesSupported
	}
	if merged.Raw == nil {
		merged.Raw = src.Raw
	}
	merged.AuthorizationServer.Raw = merged.Raw
	return merged
}

func mergeConfiguredProvider(dst, src metadata.Provider) metadata.Provider {
	merged := dst
	if strings.TrimSpace(src.AuthorizationEndpoint) != "" {
		merged.AuthorizationEndpoint = src.AuthorizationEndpoint
	}
	if strings.TrimSpace(src.TokenEndpoint) != "" {
		merged.TokenEndpoint = src.TokenEndpoint
	}
	if strings.TrimSpace(src.JWKSURI) != "" {
		merged.JWKSURI = src.JWKSURI
	}
	if strings.TrimSpace(src.UserinfoEndpoint) != "" {
		merged.UserinfoEndpoint = src.UserinfoEndpoint
	}
	if strings.TrimSpace(src.PushedAuthorizationRequestEndpoint) != "" {
		merged.PushedAuthorizationRequestEndpoint = src.PushedAuthorizationRequestEndpoint
	}
	if strings.TrimSpace(src.Issuer) != "" {
		merged.Issuer = src.Issuer
	}
	if len(src.ResponseTypesSupported) > 0 {
		merged.ResponseTypesSupported = append([]string(nil), src.ResponseTypesSupported...)
	}
	if len(src.IDTokenSigningAlgValuesSupported) > 0 {
		merged.IDTokenSigningAlgValuesSupported = append([]string(nil), src.IDTokenSigningAlgValuesSupported...)
	}
	if len(src.SubjectTypesSupported) > 0 {
		merged.SubjectTypesSupported = append([]string(nil), src.SubjectTypesSupported...)
	}
	if len(src.TokenEndpointAuthMethodsSupported) > 0 {
		merged.TokenEndpointAuthMethodsSupported = append([]string(nil), src.TokenEndpointAuthMethodsSupported...)
	}
	if len(src.RequestObjectSigningAlgValuesSupported) > 0 {
		merged.RequestObjectSigningAlgValuesSupported = append([]string(nil), src.RequestObjectSigningAlgValuesSupported...)
	}
	if len(src.AuthorizationSigningAlgValuesSupported) > 0 {
		merged.AuthorizationSigningAlgValuesSupported = append([]string(nil), src.AuthorizationSigningAlgValuesSupported...)
	}
	if strings.TrimSpace(src.MTLSEndpointAliases.TokenEndpoint) != "" {
		merged.MTLSEndpointAliases.TokenEndpoint = src.MTLSEndpointAliases.TokenEndpoint
	}
	if strings.TrimSpace(src.MTLSEndpointAliases.UserinfoEndpoint) != "" {
		merged.MTLSEndpointAliases.UserinfoEndpoint = src.MTLSEndpointAliases.UserinfoEndpoint
	}
	if strings.TrimSpace(src.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint) != "" {
		merged.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint = src.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint
	}
	if len(src.CodeChallengeMethodsSupported) > 0 {
		merged.CodeChallengeMethodsSupported = append([]string(nil), src.CodeChallengeMethodsSupported...)
	}
	if len(src.ResponseModesSupported) > 0 {
		merged.ResponseModesSupported = append([]string(nil), src.ResponseModesSupported...)
	}
	if len(src.TokenEndpointAuthSigningAlgValuesSupported) > 0 {
		merged.TokenEndpointAuthSigningAlgValuesSupported = append([]string(nil), src.TokenEndpointAuthSigningAlgValuesSupported...)
	}
	if len(src.IDTokenEncryptionAlgValuesSupported) > 0 {
		merged.IDTokenEncryptionAlgValuesSupported = append([]string(nil), src.IDTokenEncryptionAlgValuesSupported...)
	}
	if len(src.IDTokenEncryptionEncValuesSupported) > 0 {
		merged.IDTokenEncryptionEncValuesSupported = append([]string(nil), src.IDTokenEncryptionEncValuesSupported...)
	}
	if src.Raw != nil {
		merged.Raw = src.Raw
	}
	merged.AuthorizationServer.Raw = merged.Raw
	return merged
}

func providerHasAuthorizationEndpoint(p metadata.Provider) bool {
	return strings.TrimSpace(p.AuthorizationEndpoint) != ""
}

func providerHasTokenEndpoint(p metadata.Provider) bool {
	return strings.TrimSpace(p.TokenEndpoint) != ""
}

func providerHasJWKSURI(p metadata.Provider) bool {
	return strings.TrimSpace(p.JWKSURI) != ""
}

func providerIsComplete(p metadata.Provider) bool {
	return providerHasAuthorizationEndpoint(p) &&
		providerHasTokenEndpoint(p) &&
		providerHasJWKSURI(p)
}

func newRP(issuer string) *RP {
	return &RP{
		clientConfig: clientConfig{
			issuer:     strings.TrimSpace(issuer),
			scopes:     []string{"openid"},
			httpClient: http.DefaultClient,
			logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			now:        func() time.Time { return time.Now().UTC() },
			randReader: rand.Reader,
		},
		userInfoTokenTransport: UserInfoTokenTransportHeader,
		clockSkew:              defaultClockSkew,
	}
}

func (r *RP) initDefaults() {
	r.clientConfig.initDefaults()
	if r.stateStore == nil {
		r.stateStore = memory.New(10 * time.Minute)
	}
}

func (r *RP) initMetadataClient() {
	if r.metadataClient == nil {
		r.metadataClient = metadata.NewClient(
			metadata.WithHTTPClient(r.httpClient),
			metadata.WithLogger(r.logger),
		)
	}
}

func (r *RP) resolveProvider(ctx context.Context) error {
	if r.configuredProviderSet && providerIsComplete(r.configuredProvider) {
		r.provider = r.configuredProvider
		r.providerSet = true
		return nil
	}

	mode := r.effectiveDiscoveryMode()

	if mode == discoveryModeDisabled {
		if r.configuredProviderSet {
			r.provider = r.configuredProvider
			r.providerSet = true
			return nil
		}
		return fmt.Errorf("%w: discovery is disabled and no provider metadata was configured", ErrInvalidConfiguration)
	}

	discovered, err := r.discoverProviderMetadataForMode(ctx, r.issuer, mode)
	if err != nil {
		return fmt.Errorf("%w: failed to discover provider: %v", ErrInvalidConfiguration, err)
	}

	if r.configuredProviderSet {
		r.provider = mergeProviderMissing(r.configuredProvider, discovered)
	} else {
		r.provider = discovered
	}
	r.providerSet = true
	return nil
}

func (r *RP) effectiveDiscoveryMode() discoveryModeType {
	if r.discoveryModeExplicit {
		return r.discoveryMode
	}

	switch r.profile {
	case profileOAuth2:
		return discoveryModeOAuth2
	default:
		if r.usesOpenIDScope() {
			return discoveryModeOIDC
		}
		return discoveryModeAuto
	}
}

func (r *RP) discoverProviderMetadataForMode(ctx context.Context, issuer string, mode discoveryModeType) (metadata.Provider, error) {
	switch mode {
	case discoveryModeOIDC:
		return DiscoverProvider(ctx, issuer,
			WithDiscoveryMetadataClient(r.metadataClient),
		)
	case discoveryModeOAuth2:
		as, err := r.metadataClient.DiscoverAuthorizationServer(ctx, issuer)
		if err != nil {
			return metadata.Provider{}, err
		}
		return metadata.Provider{AuthorizationServer: as}, nil
	default:
		return r.discoverProviderMetadata(ctx, issuer)
	}
}

func (r *RP) applyProfileDefaults() {
	if !r.profileExplicit {
		return
	}

	switch r.profile {
	case profileOAuth2:
		if !r.scopesExplicit {
			r.scopes = removeScope(r.scopes, "openid")
			if len(r.scopes) == 0 {
				r.scopes = []string{}
			}
		}
	case profileFAPI1Adv:
		if !r.scopesExplicit {
			r.scopes = []string{"openid"}
		}
		if !r.requestMethodExplicit {
			r.requestMethod = requestMethodSignedNonRepudiation
		}
	case profileFAPI2SecurityProfile:
		if !r.scopesExplicit {
			r.scopes = []string{"openid"}
		}
		if !r.requestMethodExplicit {
			r.requestMethod = requestMethodSignedNonRepudiation
		}
	case profileFAPI2MessageSigning:
		if !r.scopesExplicit {
			r.scopes = []string{"openid"}
		}
		if !r.requestMethodExplicit {
			r.requestMethod = requestMethodSignedNonRepudiation
		}
	}
}

func removeScope(scopes []string, target string) []string {
	filtered := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !strings.EqualFold(strings.TrimSpace(s), target) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func (r *RP) finalizeSecurityDefaults() {
	if !r.profile.isFAPI() && !r.allowUnsecuredIDTokens {
		r.allowUnsecuredIDTokens = true
	}
}

func (r *RP) validateProviderReadyForAuthorizationURL() error {
	if r.authorizationEndpoint(r.provider) == "" {
		return fmt.Errorf("%w: authorization endpoint missing", ErrInvalidConfiguration)
	}
	if r.requirePAR && r.pushedAuthorizationRequestEndpoint(r.provider) == "" {
		return fmt.Errorf("%w: pushed authorization request endpoint missing", ErrInvalidConfiguration)
	}

	return nil
}

func (r *RP) validate() error {
	if err := validateHTTPSAbsoluteURL("issuer", r.issuer); err != nil {
		return err
	}

	if r.clientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidConfiguration)
	}

	if err := validateHTTPSAbsoluteURL("redirect_uri", r.redirectURI); err != nil {
		return err
	}

	if len(r.scopes) == 0 {
		return fmt.Errorf("%w: at least one scope is required", ErrInvalidConfiguration)
	}

	return nil
}

func (r *RP) discoverProviderMetadata(ctx context.Context, issuer string) (metadata.Provider, error) {
	if r.usesOpenIDScope() {
		return DiscoverProvider(ctx, issuer,
			WithDiscoveryMetadataClient(r.metadataClient),
		)
	}

	return oauthOnlyProviderMetadata(issuer), nil
}

func oauthOnlyProviderMetadata(issuer string) metadata.Provider {
	base := strings.TrimRight(strings.TrimSpace(issuer), "/")

	return metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 issuer,
			AuthorizationEndpoint:  base + "/authorize",
			TokenEndpoint:          base + "/token",
			ResponseTypesSupported: []string{"code"},
			MTLSEndpointAliases: metadata.MTLSEndpointAliases{
				TokenEndpoint:    base + "/mtls/token",
				UserinfoEndpoint: base + "/mtls/userinfo",
			},
		},
		PushedAuthorizationRequestEndpoint: base + "/par",
	}
}

func validateHTTPSAbsoluteURL(field, raw string) error {
	if _, err := validateurl.ParseHTTPSAbsoluteNoQueryFragment(raw); err != nil {
		if errors.Is(err, validateurl.ErrInvalidFormat) {
			return fmt.Errorf("%w: invalid %s %q: %v", ErrInvalidConfiguration, field, raw, err)
		}
		if errors.Is(err, validateurl.ErrQueryOrFragment) {
			return fmt.Errorf("%w: %s must not include query or fragment", ErrInvalidConfiguration, field)
		}
		return fmt.Errorf("%w: %s must be an absolute https URL", ErrInvalidConfiguration, field)
	}

	return nil
}
