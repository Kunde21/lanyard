package rp

import (
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/Kunde21/lanyard/metadata"
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

// WithClientCredentialsMetadataClient sets the metadata discovery and JWKS client.
func WithClientCredentialsMetadataClient(client *metadata.Client) ClientCredentialsOption {
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
func WithClientCredentialsProviderMetadata(provider metadata.Provider) ClientCredentialsOption {
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

// WithClientCredentialsSenderConstrain sets the sender-constraining mode for DPoP or mTLS.
// Use the typed [SenderConstraint] constants: [SenderConstraintDPoP] or
// [SenderConstraintMTLS].
func WithClientCredentialsSenderConstrain(mode SenderConstraint) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		c.senderConstrain = normalizeSenderConstrain(string(mode))
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

// WithClientCredentialsDPoPNonceTTL sets the TTL for cached DPoP nonces in
// the client credentials flow.
func WithClientCredentialsDPoPNonceTTL(ttl time.Duration) ClientCredentialsOption {
	return func(c *ClientCredentials) {
		if ttl > 0 {
			c.dpopNonces = newDPoPNonceStore(ttl)
		}
	}
}
