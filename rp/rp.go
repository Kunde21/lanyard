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
	"sync"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp/store/memory"
	"github.com/Kunde21/lanyard/validateurl"
)

const defaultClockSkew = 5 * time.Minute

// RP is an OpenID Connect relying party for the Authorization Code flow.
type fapiProfileType int

const (
	fapiProfileNone fapiProfileType = iota
	fapiProfilePlainFAPI
	fapiProfileFAPI2
	fapiProfileFAPI1
)

func normalizeFAPIProfile(raw string) fapiProfileType {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(lower, "plain_fapi") {
		return fapiProfilePlainFAPI
	}
	if strings.Contains(lower, "fapi2") {
		return fapiProfileFAPI2
	}
	if strings.Contains(lower, "fapi1") {
		return fapiProfileFAPI1
	}
	return fapiProfileNone
}

func (f fapiProfileType) isFAPI() bool {
	return f != fapiProfileNone
}

type requestMethodType int

const (
	requestMethodPlain requestMethodType = iota
	requestMethodSignedNonRepudiation
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

type RP struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	authMethod   AuthMethod

	httpClient     *http.Client
	logger         *slog.Logger
	metadataClient *metadata.Client
	stateStore     StateStore

	provider    metadata.Provider
	providerSet bool

	userInfoTokenTransport UserInfoTokenTransport

	clientKeyProvider ClientKeyProvider

	requirePAR             bool
	senderConstrain        senderConstrainType
	fapiProfile            fapiProfileType
	allowUnsecuredIDTokens bool

	resolvedAuthMethod  AuthMethod
	allowMethodFallback bool
	methodMu            sync.RWMutex

	now        func() time.Time
	randReader io.Reader
	clockSkew  time.Duration
	dpopNonces *dpopNonceStore

	authorizationDetails string
	responseMode         string
	responseType         string
	requestMethod        requestMethodType
}

// New creates a browser-flow relying party that is ready to generate an
// authorization URL immediately after construction.
func New(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, opts ...Option) (*RP, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	r := newRP(issuer, clientID, clientSecret, redirectURI)

	for _, opt := range opts {
		opt(r)
	}

	r.initDefaults()

	if err := r.validate(); err != nil {
		return nil, err
	}

	r.initMetadataClient()

	if err := r.initProvider(ctx); err != nil {
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

func newRP(issuer, clientID, clientSecret, redirectURI string) *RP {
	return &RP{
		issuer:                 strings.TrimSpace(issuer),
		clientID:               strings.TrimSpace(clientID),
		clientSecret:           clientSecret,
		redirectURI:            strings.TrimSpace(redirectURI),
		scopes:                 []string{"openid"},
		httpClient:             http.DefaultClient,
		logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		userInfoTokenTransport: UserInfoTokenTransportHeader,
		now:                    func() time.Time { return time.Now().UTC() },
		randReader:             rand.Reader,
		clockSkew:              defaultClockSkew,
	}
}

func (r *RP) initDefaults() {
	if r.dpopNonces == nil {
		r.dpopNonces = newDPoPNonceStore(5 * time.Minute)
	}
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

func (r *RP) initProvider(ctx context.Context) error {
	if !r.providerSet {
		provider, err := r.discoverProviderMetadata(ctx, r.issuer)
		if err != nil {
			return fmt.Errorf("%w: failed to discover provider: %v", ErrInvalidConfiguration, err)
		}
		r.provider = provider
		r.providerSet = true
	}
	return nil
}

func (r *RP) finalizeSecurityDefaults() {
	if !r.fapiProfile.isFAPI() && !r.allowUnsecuredIDTokens {
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
			WithDiscoveryOIDCClient(r.metadataClient),
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
