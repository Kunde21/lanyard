package rp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Kunde21/lanyard/metadata"
)

// ProviderDiscoveryOption configures [DiscoverProvider].
type ProviderDiscoveryOption interface {
	applyProviderDiscovery(*providerDiscoveryConfig)
}

type providerDiscoveryOptionFunc func(*providerDiscoveryConfig)

func (f providerDiscoveryOptionFunc) applyProviderDiscovery(cfg *providerDiscoveryConfig) {
	f(cfg)
}

type providerDiscoveryConfig struct {
	httpClient        *http.Client
	logger            *slog.Logger
	metadataClient    *metadata.Client
	webFingerResource string
	preloadJWKS       bool
}

// DiscoverProvider discovers provider metadata for issuer validation and setup
// flows that do not need to construct an [RP] yet.
//
// By default it discovers metadata from the supplied issuer. Callers can use
// [WithDiscoveryWebFingerResource] to resolve the issuer through WebFinger
// instead, and [WithDiscoveryPreloadJWKS] to eagerly validate JWKS reachability.
func DiscoverProvider(ctx context.Context, issuer string, opts ...ProviderDiscoveryOption) (metadata.Provider, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	cfg := providerDiscoveryConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt.applyProviderDiscovery(&cfg)
		}
	}

	client := cfg.metadataClient
	if client == nil {
		opts := make([]metadata.Option, 0, 2)
		if cfg.httpClient != nil {
			opts = append(opts, metadata.WithHTTPClient(cfg.httpClient))
		}
		if cfg.logger != nil {
			opts = append(opts, metadata.WithLogger(cfg.logger))
		}
		client = metadata.NewClient(opts...)
	}

	var (
		provider metadata.Provider
		err      error
	)
	if cfg.webFingerResource != "" {
		provider, err = client.DiscoverProviderFromResource(ctx, cfg.webFingerResource)
	} else {
		provider, err = client.DiscoverProvider(ctx, issuer)
	}
	if err != nil {
		return metadata.Provider{}, err
	}

	if cfg.preloadJWKS && provider.JWKSURI != "" {
		keySet, err := client.RemoteKeySetFromJWKSURI(provider.JWKSURI)
		if err != nil {
			return metadata.Provider{}, fmt.Errorf("failed to prepare jwks key set: %w", err)
		}
		if _, err := keySet.Keys(ctx); err != nil {
			return metadata.Provider{}, fmt.Errorf("failed to preload jwks keys: %w", err)
		}
	}

	return provider, nil
}

// WithDiscoveryHTTPClient sets the HTTP client used by [DiscoverProvider] when
// it constructs its own metadata client.
func WithDiscoveryHTTPClient(client *http.Client) ProviderDiscoveryOption {
	return providerDiscoveryOptionFunc(func(cfg *providerDiscoveryConfig) {
		if client != nil {
			cfg.httpClient = client
		}
	})
}

// WithDiscoveryLogger sets the structured logger used by [DiscoverProvider]
// when it constructs its own metadata client.
func WithDiscoveryLogger(logger *slog.Logger) ProviderDiscoveryOption {
	return providerDiscoveryOptionFunc(func(cfg *providerDiscoveryConfig) {
		if logger != nil {
			cfg.logger = logger
		}
	})
}

// WithDiscoveryMetadataClient sets the metadata client used by [DiscoverProvider].
//
// When provided, this client takes precedence over discovery-specific HTTP and
// logger options.
func WithDiscoveryMetadataClient(client *metadata.Client) ProviderDiscoveryOption {
	return providerDiscoveryOptionFunc(func(cfg *providerDiscoveryConfig) {
		if client != nil {
			cfg.metadataClient = client
		}
	})
}

// WithDiscoveryWebFingerResource makes [DiscoverProvider] resolve issuer
// metadata from a WebFinger resource instead of directly from the issuer.
func WithDiscoveryWebFingerResource(resource string) ProviderDiscoveryOption {
	return providerDiscoveryOptionFunc(func(cfg *providerDiscoveryConfig) {
		cfg.webFingerResource = resource
	})
}

// WithDiscoveryPreloadJWKS makes [DiscoverProvider] eagerly fetch JWKS keys
// after metadata discovery.
func WithDiscoveryPreloadJWKS(preload bool) ProviderDiscoveryOption {
	return providerDiscoveryOptionFunc(func(cfg *providerDiscoveryConfig) {
		cfg.preloadJWKS = preload
	})
}
