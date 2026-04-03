package rp

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Kunde21/lanyard/oidc"
)

// Option configures an RP instance.
type Option func(*RP)

// AuthorizationURLOption configures a single authorization URL generation.
type AuthorizationURLOption func(*authorizationURLConfig)

type authorizationURLConfig struct {
	authorizationDetails string
}

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

// WithSenderConstrain sets the sender-constraining mode used for outbound requests.
// Supported values are "", "mtls", and "dpop".
func WithSenderConstrain(mode string) Option {
	return func(r *RP) {
		r.senderConstrain = normalizeSenderConstrain(mode)
	}
}

// WithFAPIProfile sets the FAPI profile for strict validation.
// Supported values are "plain_fapi", "fapi2", "fapi1", etc.
func WithFAPIProfile(profile string) Option {
	return func(r *RP) {
		r.fapiProfile = normalizeFAPIProfile(profile)
	}
}

// WithAllowUnsecuredIDTokens allows acceptance of ID tokens with alg=none.
// For FAPI profiles, this option is ignored - unsecured tokens are always rejected.
func WithAllowUnsecuredIDTokens(allow bool) Option {
	return func(r *RP) {
		r.allowUnsecuredIDTokens = allow
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

// WithDPoPNonceTTL sets the TTL for cached DPoP nonces.
func WithDPoPNonceTTL(ttl time.Duration) Option {
	return func(r *RP) {
		if ttl > 0 {
			r.dpopNonces = newDPoPNonceStore(ttl)
		}
	}
}

// WithAuthorizationDetails sets the Rich Authorization Request (RAR) details.
// The details should be a slice of maps containing authorization detail types.
func WithAuthorizationDetails(details []map[string]any) Option {
	return func(r *RP) {
		authorizationDetails, ok := marshalAuthorizationDetails(details)
		if !ok {
			return
		}
		r.authorizationDetails = authorizationDetails
	}
}

// SetAuthorizationDetails sets Rich Authorization Request (RAR) details for a
// single authorization URL generation.
func SetAuthorizationDetails(details []map[string]any) AuthorizationURLOption {
	return func(cfg *authorizationURLConfig) {
		if cfg == nil {
			return
		}
		authorizationDetails, ok := marshalAuthorizationDetails(details)
		if !ok {
			return
		}
		cfg.authorizationDetails = authorizationDetails
	}
}

func marshalAuthorizationDetails(details []map[string]any) (string, bool) {
	if len(details) == 0 {
		return "", false
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "", false
	}
	return string(b), true
}
