package rp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracerName identifies the lanyard rp package in OpenTelemetry.
const tracerName = "github.com/Kunde21/lanyard/rp"

type clientConfig struct {
	issuer          string
	clientID        string
	clientSecret    string
	scopes          []string
	scopesExplicit  bool
	authMethod      AuthMethod
	resources       []string
	claimsParameter string
	tracer          trace.Tracer

	introspectionDecryptionKey crypto.PrivateKey
	initialAccessToken         string

	optionErrors []error

	httpClient     *http.Client
	logger         *slog.Logger
	metadataClient *metadata.Client

	provider              metadata.Provider
	providerSet           bool
	configuredProvider    metadata.Provider
	configuredProviderSet bool

	clientKeyProvider ClientKeyProvider

	resolvedAuthMethod  AuthMethod
	allowMethodFallback bool
	methodMu            sync.RWMutex

	senderConstrain SenderConstraint

	now        func() time.Time
	randReader io.Reader

	dpopNonces *dpopNonceStore
}

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
	method, allowFallback, err := c.selectAuthMethodFromSupported(c.provider.TokenEndpointAuthMethodsSupported)
	if err != nil {
		return err
	}
	c.setAuthMethodState(method, allowFallback)
	return nil
}

func (c *clientConfig) selectAuthMethodFromSupported(supported []string) (AuthMethod, bool, error) {
	supported = normalizeSupportedAuthMethods(supported)
	resolved := AuthMethodPost
	allowFallback := false

	if len(supported) > 0 {
		if c.authMethod != "" {
			if !methodSupported(c.authMethod, supported) {
				return "", false, &AuthMethodError{Method: c.authMethod, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
			resolved = c.authMethod
		} else {
			// Credential-aware preference: only select methods whose
			// credentials the consumer actually supplied (RC review F9).
			hasKey := c.clientKeyProvider != nil
			hasSecret := strings.TrimSpace(c.clientSecret) != ""
			switch {
			case hasKey && methodSupported(AuthMethodPrivateKeyJWT, supported):
				resolved = AuthMethodPrivateKeyJWT
			case hasKey && methodExactMatch(AuthMethodTLSClientAuth, supported):
				resolved = AuthMethodTLSClientAuth
			case hasKey && methodExactMatch(AuthMethodSelfSignedTLSClientAuth, supported):
				resolved = AuthMethodSelfSignedTLSClientAuth
			case hasKey && methodSupported(AuthMethodTLSClientAuth, supported):
				resolved = AuthMethodTLSClientAuth
			case hasSecret && methodSupported(AuthMethodClientSecretJWT, supported):
				resolved = AuthMethodClientSecretJWT
			case hasSecret && methodSupported(AuthMethodPost, supported):
				resolved = AuthMethodPost
			case hasSecret && methodSupported(AuthMethodBasic, supported):
				resolved = AuthMethodBasic
			case hasKey && methodSupported(AuthMethodPost, supported):
				resolved = AuthMethodPost
			case methodSupported(AuthMethodNone, supported):
				resolved = AuthMethodNone
			default:
				return "", false, &AuthMethodError{Method: AuthMethodPost, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
		}
	} else if c.authMethod != "" {
		resolved = c.authMethod
	} else {
		resolved = AuthMethodPost
		allowFallback = true
	}

	if err := c.validateResolvedAuthMethod(resolved); err != nil {
		return "", false, err
	}

	return resolved, allowFallback, nil
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
	method, _ := c.authMethodState()
	if c.senderConstrain != SenderConstraintNone {
		return c.senderConstrain == SenderConstraintDPoP && c.clientKeyProvider != nil && isDPoPSupported(method)
	}
	return c.clientKeyProvider != nil && isDPoPSupported(method)
}

// validateExplicitDPoP rejects an explicitly required DPoP constraint
// without a signing key: proofs cannot be produced (fourth RC review R4).
// wireMTLSClientCertificate presents the client key provider's TLS
// certificate on the RP's own HTTPS connections when mTLS client
// authentication (or mTLS sender constraining) is configured. A configured
// certificate alone is not a mutual-TLS connection: without this wiring,
// construction succeeds while every token-endpoint call fails against a
// real mTLS endpoint (FAPI policy audit A3).
//
// Transports already presenting a client certificate are left untouched.
// Custom non-*http.Transport round trippers cannot be modified; consumers
// using them must wire the certificate themselves.
func (c *clientConfig) wireMTLSClientCertificate() {
	if c.clientKeyProvider == nil {
		return
	}
	cert := c.clientKeyProvider.TLSCertificate()
	if cert == nil || c.httpClient == nil {
		return
	}
	method, _ := c.authMethodState()
	if method == "" {
		// Constructors that do not perform token-endpoint auth negotiation
		// (grant management) keep the explicitly configured method.
		method = c.authMethod
	}
	mtls := method == AuthMethodTLSClientAuth || method == AuthMethodSelfSignedTLSClientAuth ||
		c.senderConstrain == SenderConstraintMTLS
	if !mtls {
		return
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || transport == nil {
		if c.httpClient.Transport == nil {
			transport = http.DefaultTransport.(*http.Transport).Clone()
		} else {
			return // custom round tripper: consumer's responsibility
		}
	} else {
		if transport.TLSClientConfig != nil && transport.TLSClientConfig.GetClientCertificate != nil {
			return
		}
		transport = transport.Clone()
	}

	clientCert := *cert
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &clientCert, nil
	}
	transport.TLSClientConfig = tlsConfig

	client := *c.httpClient
	client.Transport = transport
	c.httpClient = &client
}

func (c *clientConfig) validateExplicitDPoP() error {
	if c.senderConstrain == SenderConstraintDPoP && c.clientKeyProvider == nil {
		return fmt.Errorf("%w: DPoP sender constraining requires a client key provider", ErrInvalidConfiguration)
	}
	// mTLS sender constraining is only real with a presented certificate
	// (fourth RC review R3).
	if c.senderConstrain == SenderConstraintMTLS && (c.clientKeyProvider == nil || c.clientKeyProvider.TLSCertificate() == nil) {
		return fmt.Errorf("%w: mTLS sender constraining requires a client key provider with a TLS certificate", ErrInvalidConfiguration)
	}
	return nil
}

func (c *clientConfig) attachDPoPProof(req *http.Request, nonce string) error {
	proof, err := buildDPoPProof(c.clientKeyProvider, c.randReader, c.now, req.Method, req.URL.String(), "", nonce)
	if err != nil {
		return err
	}
	req.Header.Set("DPoP", proof)
	return nil
}

// attachDPoPProofForAccessToken attaches a DPoP proof bound to an access
// token (ath claim) for resource requests such as the Grant Management API.
func (c *clientConfig) attachDPoPProofForAccessToken(req *http.Request, accessToken, nonce string) error {
	proof, err := buildDPoPProof(c.clientKeyProvider, c.randReader, c.now, req.Method, req.URL.String(), accessToken, nonce)
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
		tracer:     otel.GetTracerProvider().Tracer(tracerName),
		now:        func() time.Time { return time.Now().UTC() },
		randReader: rand.Reader,
	}
}

// Option configures shared RP and client credentials settings.
type Option interface {
	applyConfig(*clientConfig)
}

// AuthCodeOption configures authorization-code RP behavior.
type AuthCodeOption interface {
	Option
	applyAuthCode(*RP)
}

type optionFunc func(*clientConfig)

func (f optionFunc) applyConfig(c *clientConfig) { f(c) }

type authCodeOptionFunc func(*RP)

func (f authCodeOptionFunc) applyConfig(*clientConfig) {}
func (f authCodeOptionFunc) applyAuthCode(r *RP)       { f(r) }
