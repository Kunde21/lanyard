package rp

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Kunde21/lanyard/metadata"
)

type clientConfig struct {
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	authMethod   AuthMethod

	httpClient     *http.Client
	logger         *slog.Logger
	metadataClient *metadata.Client

	provider    metadata.Provider
	providerSet bool

	clientKeyProvider ClientKeyProvider

	resolvedAuthMethod  AuthMethod
	allowMethodFallback bool
	methodMu            sync.RWMutex

	senderConstrain SenderConstraint

	now        func() time.Time
	randReader io.Reader

	dpopNonces *dpopNonceStore
}

func (c *clientConfig) config() *clientConfig { return c }

func (c *clientConfig) initDefaults() {
	if c.dpopNonces == nil {
		c.dpopNonces = newDPoPNonceStore(5 * time.Minute)
	}
}

func (c *clientConfig) initMetadataClient() {
	if c.metadataClient == nil {
		c.metadataClient = metadata.NewClient(
			metadata.WithHTTPClient(c.httpClient),
			metadata.WithLogger(c.logger),
		)
	}
}

func (c *clientConfig) resolveProviderFromDiscovery(ctx context.Context) error {
	if !c.providerSet {
		provider, err := DiscoverProvider(ctx, c.issuer,
			WithDiscoveryMetadataClient(c.metadataClient),
		)
		if err != nil {
			return fmt.Errorf("%w: failed to discover provider: %v", ErrInvalidConfiguration, err)
		}
		c.provider = provider
		c.providerSet = true
	}
	return nil
}

func (c *clientConfig) resolveAuthMethodFromProvider() error {
	supported := normalizeSupportedAuthMethods(c.provider.TokenEndpointAuthMethodsSupported)
	resolved := AuthMethodPost
	allowFallback := false

	if len(supported) > 0 {
		if c.authMethod != "" {
			if !methodSupported(c.authMethod, supported) {
				return &AuthMethodError{Method: c.authMethod, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
			resolved = c.authMethod
		} else {
			switch {
			case methodSupported(AuthMethodPrivateKeyJWT, supported):
				resolved = AuthMethodPrivateKeyJWT
			case methodExactMatch(AuthMethodTLSClientAuth, supported):
				resolved = AuthMethodTLSClientAuth
			case methodExactMatch(AuthMethodSelfSignedTLSClientAuth, supported):
				resolved = AuthMethodSelfSignedTLSClientAuth
			case methodSupported(AuthMethodTLSClientAuth, supported):
				resolved = AuthMethodTLSClientAuth
			case methodSupported(AuthMethodPost, supported):
				resolved = AuthMethodPost
			case methodSupported(AuthMethodBasic, supported):
				resolved = AuthMethodBasic
			default:
				return &AuthMethodError{Method: AuthMethodPost, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
		}
	} else if c.authMethod != "" {
		resolved = c.authMethod
	} else {
		resolved = AuthMethodPost
		allowFallback = true
	}

	if err := c.validateResolvedAuthMethod(resolved); err != nil {
		return err
	}

	c.setAuthMethodState(resolved, allowFallback)

	return nil
}

func (c *clientConfig) validateResolvedAuthMethod(method AuthMethod) error {
	switch method {
	case AuthMethodBasic, AuthMethodPost:
		if strings.TrimSpace(c.clientSecret) == "" {
			return fmt.Errorf("%w: client_secret is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodPrivateKeyJWT:
		if c.clientKeyProvider == nil {
			return fmt.Errorf("%w: client_key_provider is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodTLSClientAuth:
		if c.clientKeyProvider == nil || c.clientKeyProvider.TLSCertificate() == nil {
			return fmt.Errorf("%w: tls certificate is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodSelfSignedTLSClientAuth:
		if c.clientKeyProvider == nil || c.clientKeyProvider.TLSCertificate() == nil {
			return fmt.Errorf("%w: tls certificate is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodNone:
		return nil
	case AuthMethodClientSecretJWT:
		if strings.TrimSpace(c.clientSecret) == "" {
			return fmt.Errorf("%w: client_secret is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported token endpoint auth method %q", ErrInvalidConfiguration, method)
	}
}

func (c *clientConfig) authMethodState() (AuthMethod, bool) {
	c.methodMu.RLock()
	method := c.resolvedAuthMethod
	allowFallback := c.allowMethodFallback
	c.methodMu.RUnlock()

	return method, allowFallback
}

func (c *clientConfig) setAuthMethodState(method AuthMethod, allowFallback bool) {
	c.methodMu.Lock()
	c.resolvedAuthMethod = method
	c.allowMethodFallback = allowFallback
	c.methodMu.Unlock()
}

func (c *clientConfig) shouldUseDPoP() bool {
	if c.senderConstrain != SenderConstraintNone {
		return c.senderConstrain == SenderConstraintDPoP && c.clientKeyProvider != nil && isDPoPSupported(c.resolvedAuthMethod)
	}
	return c.clientKeyProvider != nil && isDPoPSupported(c.resolvedAuthMethod)
}

func (c *clientConfig) attachDPoPProof(req *http.Request, nonce string) error {
	proof, err := buildDPoPProof(c.clientKeyProvider, c.randReader, c.now, req.Method, req.URL.String(), "", nonce)
	if err != nil {
		return err
	}
	req.Header.Set("DPoP", proof)
	return nil
}

func (c *clientConfig) cachedDPoPNonce(rawURL string) string {
	if c.dpopNonces == nil {
		return ""
	}
	nonce, _ := c.dpopNonces.get(normalizeDPoPHTU(rawURL))
	return nonce
}

func (c *clientConfig) storeDPoPNonce(rawURL, nonce string) {
	if c.dpopNonces == nil || nonce == "" {
		return
	}
	c.dpopNonces.put(normalizeDPoPHTU(rawURL), nonce)
}

func (c *clientConfig) extractAndStoreDPoPNonce(resp *http.Response, rawURL string) {
	nonce, ok := extractDPoPNonce(resp)
	if ok {
		c.storeDPoPNonce(rawURL, nonce)
	}
}

func defaultClientConfig(issuer string) clientConfig {
	return clientConfig{
		issuer:     strings.TrimSpace(issuer),
		httpClient: http.DefaultClient,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:        func() time.Time { return time.Now().UTC() },
		randReader: rand.Reader,
	}
}

// Option configures an [RP] or [ClientCredentials] instance.
type Option interface {
	apply(optionTarget)
}

type optionTarget interface {
	config() *clientConfig
}

type optionFunc func(*clientConfig)

func (f optionFunc) apply(t optionTarget) { f(t.config()) }

type rpOptionFunc func(*RP)

func (f rpOptionFunc) apply(t optionTarget) {
	if r, ok := t.(*RP); ok {
		f(r)
	}
}
