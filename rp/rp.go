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

	"github.com/Kunde21/lanyard/oidc"
	"github.com/Kunde21/lanyard/rp/store/memory"
	"github.com/Kunde21/lanyard/validateurl"
)

const defaultClockSkew = 5 * time.Minute

// RP is an OpenID Connect relying party for the Authorization Code flow.
type RP struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	authMethod   AuthMethod

	httpClient *http.Client
	logger     *slog.Logger
	oidcClient *oidc.Client

	stateStore StateStore

	provider    oidc.ProviderMetadata
	providerSet bool

	userInfoTokenTransport UserInfoTokenTransport

	clientKeyProvider ClientKeyProvider

	requirePAR      bool
	senderConstrain senderConstrainType

	resolvedAuthMethod  AuthMethod
	allowMethodFallback bool
	methodMu            sync.RWMutex

	now        func() time.Time
	randReader io.Reader
	clockSkew  time.Duration
}

// New creates a browser-flow relying party that is ready to generate an
// authorization URL immediately after construction.
func New(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, opts ...Option) (*RP, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	r := &RP{
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

	for _, opt := range opts {
		opt(r)
	}

	if err := r.validate(); err != nil {
		return nil, err
	}

	if r.oidcClient == nil {
		r.oidcClient = oidc.NewClient(
			oidc.WithHTTPClient(r.httpClient),
			oidc.WithLogger(r.logger),
		)
	}

	if !r.providerSet {
		provider, err := DiscoverProvider(ctx, r.issuer,
			WithDiscoveryOIDCClient(r.oidcClient),
		)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to discover provider: %v", ErrInvalidConfiguration, err)
		}
		r.provider = provider
		r.providerSet = true
	}

	if err := r.resolveAuthMethod(); err != nil {
		return nil, err
	}

	if err := r.validateProviderReadyForAuthorizationURL(); err != nil {
		return nil, err
	}

	if r.stateStore == nil {
		r.stateStore = memory.New(10 * time.Minute)
	}

	return r, nil
}

func (r *RP) validateProviderReadyForAuthorizationURL() error {
	if r.provider.AuthorizationEndpoint == "" {
		return fmt.Errorf("%w: authorization endpoint missing", ErrInvalidConfiguration)
	}
	if r.requirePAR && r.provider.PushedAuthorizationRequestEndpoint == "" {
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
