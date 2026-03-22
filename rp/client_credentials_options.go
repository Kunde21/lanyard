package rp

import (
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/Kunde21/lanyard/oidc"
)

// ClientCredentialsOption configures a ClientCredentials instance.
type ClientCredentialsOption func(*ClientCredentials)

// WithClientCredentialsHTTPClient sets the HTTP client used by ClientCredentials.
func WithClientCredentialsHTTPClient(client *http.Client) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if client == nil {
			return
		}
		c.httpClient = client
	}
}

// WithClientCredentialsLogger sets the structured logger.
func WithClientCredentialsLogger(logger *slog.Logger) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if logger == nil {
			return
		}
		c.logger = logger
	}
}

// WithClientCredentialsOIDCClient sets the OIDC discovery and JWKS client.
func WithClientCredentialsOIDCClient(client *oidc.Client) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if client == nil {
			return
		}
		c.oidcClient = client
	}
}

// WithClientCredentialsScopes sets the default scopes for token requests.
func WithClientCredentialsScopes(scopes ...string) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if len(scopes) == 0 {
			return
		}
		c.scopes = slices.Clone(scopes)
	}
}

// WithClientCredentialsAuthMethod sets the token endpoint client authentication method.
func WithClientCredentialsAuthMethod(method AuthMethod) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		c.authMethod = method
	}
}

// WithClientCredentialsProviderMetadata supplies provider metadata up front so
// [NewClientCredentials] can skip discovery and use the provided token
// endpoint immediately.
func WithClientCredentialsProviderMetadata(provider oidc.ProviderMetadata) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		c.provider = provider
		c.providerSet = true
	}
}

// WithClientCredentialsKeyProvider sets the key provider for private_key_jwt and mTLS authentication.
func WithClientCredentialsKeyProvider(provider ClientKeyProvider) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if provider == nil {
			return
		}
		c.clientKeyProvider = provider
	}
}

func withClientCredentialsNow(now func() time.Time) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if now == nil {
			return
		}
		c.now = now
	}
}

func withClientCredentialsRandReader(reader io.Reader) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if reader == nil {
			return
		}
		c.randReader = reader
	}
}
