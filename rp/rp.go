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

	requirePAR bool

	resolvedAuthMethod  AuthMethod
	allowMethodFallback bool
	methodMu            sync.RWMutex

	now        func() time.Time
	randReader io.Reader
	clockSkew  time.Duration
}

// New creates a new relying party.
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
		provider, err := r.oidcClient.DiscoverProvider(ctx, r.issuer)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to discover provider: %v", ErrInvalidConfiguration, err)
		}
		r.provider = provider
		r.providerSet = true
	}

	if err := r.resolveAuthMethod(); err != nil {
		return nil, err
	}

	if r.stateStore == nil {
		r.stateStore = NewMemoryStateStore(10 * time.Minute)
	}

	return r, nil
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

func (r *RP) Discover(ctx context.Context) error {
	provider, err := r.oidcClient.DiscoverProvider(ctx, r.issuer)
	if err != nil {
		return fmt.Errorf("failed to discover provider: %w", err)
	}
	r.provider = provider
	r.providerSet = true
	return nil
}

func (r *RP) DiscoverWithJWKS(ctx context.Context) error {
	if err := r.Discover(ctx); err != nil {
		return err
	}
	if r.provider.JWKSURI == "" {
		return nil
	}
	keySet, err := r.oidcClient.RemoteKeySetFromJWKSURI(r.provider.JWKSURI)
	if err != nil {
		return err
	}
	_, err = keySet.Keys(ctx)
	return err
}

func (r *RP) DiscoverFromWebFinger(ctx context.Context, resource string) error {
	provider, err := r.oidcClient.DiscoverProviderFromResource(ctx, resource)
	if err != nil {
		return fmt.Errorf("failed to discover provider from webfinger: %w", err)
	}

	r.issuer = provider.Issuer
	r.provider = provider
	r.providerSet = true

	if err := r.applySupportedAuthMethods(provider.TokenEndpointAuthMethodsSupported); err != nil {
		return fmt.Errorf("failed to resolve token endpoint auth method after webfinger discovery: %w", err)
	}

	return nil
}
