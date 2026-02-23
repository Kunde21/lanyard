package rp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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

	httpClient *http.Client
	logger     *slog.Logger
	oidcClient *oidc.Client

	stateStore StateStore

	now        func() time.Time
	randReader io.Reader
	clockSkew  time.Duration
}

// New creates a new relying party.
func New(issuer, clientID, clientSecret, redirectURI string, opts ...Option) (*RP, error) {
	r := &RP{
		issuer:       strings.TrimSpace(issuer),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: clientSecret,
		redirectURI:  strings.TrimSpace(redirectURI),
		scopes:       []string{"openid"},
		httpClient:   http.DefaultClient,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:          func() time.Time { return time.Now().UTC() },
		randReader:   rand.Reader,
		clockSkew:    defaultClockSkew,
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
