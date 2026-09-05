package metadata

import (
	"context"
	"fmt"
	"net/url"

	"github.com/Kunde21/lanyard/jwks"
	"go.opentelemetry.io/otel/attribute"
)

// RemoteKeySet builds a remote key set from discovered provider information.
func (c *Client) RemoteKeySet(ctx context.Context, issuer string) (*jwks.RemoteKeySet, error) {
	provider, err := c.DiscoverProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if provider.JWKSURI == "" {
		return nil, fmt.Errorf("%w: provider missing jwks_uri", ErrDiscoveryFailed)
	}

	return c.RemoteKeySetFromJWKSURI(provider.JWKSURI)
}

// RemoteKeySetFromJWKSURI builds a remote key set from a known JWKS URL.
// The key set fetches lazily; this span records the construction only.
func (c *Client) RemoteKeySetFromJWKSURI(jwksURI string) (*jwks.RemoteKeySet, error) {
	_, span := c.spanStart(context.Background(), "metadata.jwks",
		attribute.String("lanyard.jwks.uri", urlWithoutQuery(jwksURI)),
		attribute.Bool("lanyard.jwks.lazy", true),
	)
	defer span.End()

	remote, err := jwks.NewRemoteKeySet(
		jwksURI,
		jwks.WithHTTPClient(c.httpClient),
		jwks.WithLogger(c.logger),
		jwks.WithCache(c.jwksCache),
	)
	if err != nil {
		spanError(span, err)
		return nil, err
	}

	return remote, nil
}

// urlWithoutQuery strips the query component: URLs are recorded without
// query strings by construction.
func urlWithoutQuery(raw string) string {
	if parsed, err := url.Parse(raw); err == nil {
		stripped := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}
		return stripped.String()
	}
	return ""
}
