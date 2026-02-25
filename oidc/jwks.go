package oidc

import (
	"context"
	"fmt"

	"github.com/Kunde21/lanyard/jwks"
)

// RemoteKeySet builds a remote key set from discovered provider metadata.
func (c *Client) RemoteKeySet(ctx context.Context, issuer string) (*jwks.RemoteKeySet, error) {
	provider, err := c.DiscoverProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if provider.JWKSURI == "" {
		return nil, fmt.Errorf("%w: provider metadata missing jwks_uri", ErrDiscoveryFailed)
	}

	return c.RemoteKeySetFromJWKSURI(provider.JWKSURI)
}

// RemoteKeySetFromJWKSURI builds a remote key set from a known JWKS URL.
func (c *Client) RemoteKeySetFromJWKSURI(jwksURI string) (*jwks.RemoteKeySet, error) {
	remote, err := jwks.NewRemoteKeySet(
		jwksURI,
		jwks.WithHTTPClient(c.httpClient),
		jwks.WithLogger(c.logger),
		jwks.WithCache(c.jwksCache),
	)
	if err != nil {
		return nil, err
	}

	return remote, nil
}
