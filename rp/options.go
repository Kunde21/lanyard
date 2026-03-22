package rp

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/oidc"
)

// Option configures an RP instance.
type Option func(*RP)

// WithOIDCClient sets the OIDC discovery and JWKS client.
func WithOIDCClient(client *oidc.Client) Option {
	return func(r *RP) {
		if client != nil {
			r.oidcClient = client
		}
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(r *RP) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithHTTPClient sets the HTTP client used by RP network calls.
func WithHTTPClient(client *http.Client) Option {
	return func(r *RP) {
		if client != nil {
			r.httpClient = client
		}
	}
}

// WithScopes sets requested authorization scopes.
func WithScopes(scopes ...string) Option {
	return func(r *RP) {
		if len(scopes) == 0 {
			return
		}
		r.scopes = append([]string(nil), scopes...)
	}
}

// WithClockSkew sets clock skew tolerance for token claim checks.
func WithClockSkew(skew time.Duration) Option {
	return func(r *RP) {
		if skew >= 0 {
			r.clockSkew = skew
		}
	}
}

// WithProviderMetadata supplies provider metadata up front so [New] can skip
// discovery and use the provided endpoints immediately.
func WithProviderMetadata(provider oidc.ProviderMetadata) Option {
	return func(r *RP) {
		r.provider = provider
		r.providerSet = true
	}
}

// WithAuthMethod sets the token endpoint client authentication method.
func WithAuthMethod(method AuthMethod) Option {
	return func(r *RP) {
		r.authMethod = method
	}
}

// WithStateStore sets the state store used for callback correlation and caller values.
//
// Callers typically provide implementations from `rp/store/memory` or `rp/store/cookie`.
func WithStateStore(store StateStore) Option {
	return func(r *RP) {
		if store != nil {
			r.stateStore = store
		}
	}
}

// WithUserInfoTokenTransport sets how UserInfo requests send access tokens.
func WithUserInfoTokenTransport(transport UserInfoTokenTransport) Option {
	return func(r *RP) {
		r.userInfoTokenTransport = normalizeUserInfoTokenTransport(transport)
	}
}

// WithClientKeyProvider sets the key provider for private_key_jwt and mTLS authentication.
func WithClientKeyProvider(provider ClientKeyProvider) Option {
	return func(r *RP) {
		if provider != nil {
			r.clientKeyProvider = provider
		}
	}
}

// WithRequirePAR forces the use of Pushed Authorization Requests (PAR).
func WithRequirePAR(require bool) Option {
	return func(r *RP) {
		r.requirePAR = require
	}
}

func withNow(now func() time.Time) Option {
	return func(r *RP) {
		if now != nil {
			r.now = now
		}
	}
}

func withRandReader(reader io.Reader) Option {
	return func(r *RP) {
		if reader != nil {
			r.randReader = reader
		}
	}
}
