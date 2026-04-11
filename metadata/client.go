package metadata

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/cache"
	"github.com/Kunde21/lanyard/jwks"
	"golang.org/x/sync/singleflight"
)

const defaultDiscoveryTTL = time.Hour

// Client fetches and validates OIDC and OAuth authorization server metadata.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger

	discoveryCache CacheStore
	jwksCache      jwks.CacheStore

	issuerTrailingSlashTolerance bool
	defaultDiscoveryTTL          time.Duration
	conformanceFreshDiscovery    bool

	discoveryGroup singleflight.Group
}

// NewClient constructs a discovery client with default in-memory caches for
// both discovery metadata and JWKS results. Use [WithDiscoveryCache] or
// [WithJWKSCache] to replace the default caches.
func NewClient(opts ...Option) *Client {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &Client{
		httpClient:                   http.DefaultClient,
		logger:                       logger,
		discoveryCache:               cache.NewStore[*CacheEntry](),
		jwksCache:                    cache.NewStore[*jwks.CacheEntry](),
		defaultDiscoveryTTL:          defaultDiscoveryTTL,
		issuerTrailingSlashTolerance: false,
		conformanceFreshDiscovery:    false,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}
