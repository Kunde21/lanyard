package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/Kunde21/lanyard/rp"
	"github.com/Kunde21/lanyard/rp/store/cookie"
	"github.com/Kunde21/lanyard/rp/store/memory"
)

var (
	sharedStateStore    = newSharedStateStore()
	sharedMemoryStore   = memory.New(10 * time.Minute)
	conformanceRuntimes = newRuntimeRegistry()
)

var defaultScopes = []string{"openid", "profile", "email", "phone", "address"}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type resolvedRPRequest struct {
	issuer               string
	clientID             string
	clientSecret         string
	redirectURI          string
	scopes               []string
	stateStore           rp.StateStore
	userInfoTransport    rp.UserInfoTokenTransport
	authMethod           rp.AuthMethod
	hasAuthMethod        bool
	keyProvider          rp.ClientKeyProvider
	requirePAR           bool
	senderConstrain      string
	fapiProfile          string
	authorizationDetails []map[string]any
	responseMode         string
	requestMethod        string
}

func newSharedStateStore() rp.StateStore {
	authKey := []byte(envOrDefault("RP_STATE_COOKIE_AUTH_KEY", "0123456789abcdef0123456789abcdef"))
	encryptionKey := []byte(envOrDefault("RP_STATE_COOKIE_ENC_KEY", "abcdef0123456789abcdef0123456789"))

	store, err := cookie.New(
		authKey,
		encryptionKey,
		cookie.WithTTL(10*time.Minute),
		cookie.WithSecure(!envTrue("RP_STATE_COOKIE_INSECURE")),
	)
	if err != nil {
		log.Fatalf("failed to create cookie-backed RP state store: %v", err)
	}

	return store
}

func resolveRPRequest(r *http.Request, clientID, clientSecret, redirectURI string, transport rp.UserInfoTokenTransport) (resolvedRPRequest, error) {
	explicitIssuer := strings.TrimSpace(r.URL.Query().Get("issuer"))
	issuer := issuerFromRequest(r)
	pathAlias := callbackAliasFromPath(r.URL.Path)
	resolved := resolvedRPRequest{
		issuer:            issuer,
		clientID:          clientID,
		clientSecret:      clientSecret,
		redirectURI:       redirectURI,
		scopes:            parseScopesEnv("RP_SCOPES", defaultScopes),
		stateStore:        sharedStateStore,
		userInfoTransport: transport,
	}

	alias, err := issuerAlias(issuer)
	if err == nil {
		runtimeCfg, ok := conformanceRuntimes.Lookup(alias)
		if ok {
			return applyRuntimeConfig(resolved, runtimeCfg)
		}
		if explicitIssuer != "" {
			return resolvedRPRequest{}, fmt.Errorf("no registered conformance runtime for issuer alias %q", alias)
		}
	}

	if pathAlias != "" {
		runtimeCfg, ok := conformanceRuntimes.Lookup(pathAlias)
		if !ok {
			return resolvedRPRequest{}, fmt.Errorf("no registered conformance runtime for callback alias %q", pathAlias)
		}
		return applyRuntimeConfig(resolved, runtimeCfg)
	}

	return resolved, nil
}

func applyRuntimeConfig(resolved resolvedRPRequest, runtimeCfg rpRuntimeConfig) (resolvedRPRequest, error) {
	if strings.TrimSpace(runtimeCfg.Issuer) != "" {
		resolved.issuer = runtimeCfg.Issuer
	}
	resolved.clientID = runtimeCfg.ClientID
	resolved.clientSecret = runtimeCfg.ClientSecret
	resolved.redirectURI = runtimeCfg.RedirectURI
	resolved.scopes = append([]string(nil), runtimeCfg.Scopes...)
	resolved.stateStore = stateStoreForRuntime(runtimeCfg)
	if runtimeCfg.UserInfoTokenTransport != "" {
		resolved.userInfoTransport = runtimeCfg.UserInfoTokenTransport
	}
	if method, ok := authMethodForRuntime(runtimeCfg); ok {
		resolved.authMethod = method
		resolved.hasAuthMethod = true
	}
	resolved.requirePAR = runtimeRequiresPAR(runtimeCfg)
	resolved.senderConstrain = runtimeCfg.SenderConstrain
	resolved.fapiProfile = runtimeCfg.FAPIProfile
	resolved.authorizationDetails = authorizationDetailsForRuntime(runtimeCfg)
	resolved.responseMode = runtimeCfg.ResponseMode
	resolved.requestMethod = runtimeCfg.FAPIRequestMethod

	keyProvider, err := loadClientKeyProvider(runtimeCfg.ClientAuthType, runtimeCfg.SenderConstrain)
	if err != nil {
		return resolvedRPRequest{}, err
	}
	resolved.keyProvider = keyProvider

	return resolved, nil
}

func stateStoreForRuntime(cfg rpRuntimeConfig) rp.StateStore {
	if isFAPI2Profile(cfg) {
		return newNamespacedStateStore(sharedMemoryStore, cfg.Namespace)
	}
	return wrapWithIssuerShorthand(newNamespacedStateStore(sharedStateStore, cfg.Namespace))
}

func isFAPI2Profile(cfg rpRuntimeConfig) bool {
	profile := strings.ToLower(strings.TrimSpace(cfg.FAPIProfile))
	return strings.HasPrefix(profile, "plain_fapi") ||
		strings.Contains(profile, "fapi2") ||
		cfg.ClientAuthType == "private_key_jwt" ||
		cfg.ClientAuthType == "mtls"
}

func runtimeRequiresPAR(cfg rpRuntimeConfig) bool {
	if cfg.RequirePAR {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(cfg.AuthorizationRequestType)) {
	case "par", "pushed_authorization_request":
		return true
	}

	switch strings.ToLower(strings.TrimSpace(cfg.RequestType)) {
	case "par", "pushed_authorization_request":
		return true
	}

	return false
}

func authorizationDetailsForRuntime(cfg rpRuntimeConfig) []map[string]any {
	if !strings.EqualFold(strings.TrimSpace(cfg.AuthorizationRequestType), "rar") {
		return nil
	}
	return []map[string]any{
		{"type": "account_information"},
	}
}

func callbackAliasFromPath(path string) string {
	const prefix = "/callback/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return strings.Trim(strings.TrimPrefix(path, prefix), "/")
}

func authMethodForRuntime(cfg rpRuntimeConfig) (rp.AuthMethod, bool) {
	switch strings.ToLower(strings.TrimSpace(cfg.ClientAuthType)) {
	case "private_key_jwt":
		return rp.AuthMethodPrivateKeyJWT, true
	case "mtls":
		return rp.AuthMethodTLSClientAuth, true
	default:
		return "", false
	}
}

func newRPHTTPClient(keyProvider rp.ClientKeyProvider) *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RP_INSECURE_TLS")), "true") {
		tlsConfig.InsecureSkipVerify = true
	}
	if keyProvider != nil && keyProvider.TLSCertificate() != nil {
		clientCert := *keyProvider.TLSCertificate()
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	baseTransport := &http.Transport{TLSClientConfig: tlsConfig}
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requestDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			slog.Info("rp http request dump failed", "method", req.Method, "url", req.URL.String(), "err", err)
		} else {
			slog.Info("rp http request dump", "dump", string(requestDump))
		}

		resp, err := baseTransport.RoundTrip(req)
		if err != nil {
			slog.Info("rp http round trip failed", "method", req.Method, "url", req.URL.String(), "err", err)
			return nil, err
		}

		responseDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			slog.Info("rp http response dump failed", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "err", err)
		} else {
			slog.Info("rp http response dump", "dump", string(responseDump))
		}

		return resp, nil
	})
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}
}

func buildRPFromResolvedRequest(r *http.Request, resolved resolvedRPRequest) (*rp.RP, error) {
	httpClient := newRPHTTPClient(resolved.keyProvider)
	oidcOpts := []oidc.Option{oidc.WithHTTPClient(httpClient)}
	if envTrue("RP_CONFORMANCE_FRESH_DISCOVERY") {
		oidcOpts = append(oidcOpts, oidc.WithConformanceFreshDiscovery(true))
	}
	oidcClient := oidc.NewClient(oidcOpts...)

	opts := []rp.Option{
		rp.WithHTTPClient(httpClient),
		rp.WithOIDCClient(oidcClient),
		rp.WithStateStore(resolved.stateStore),
		rp.WithUserInfoTokenTransport(resolved.userInfoTransport),
		rp.WithScopes(resolved.scopes...),
		rp.WithRequirePAR(resolved.requirePAR),
	}
	if resolved.hasAuthMethod {
		opts = append(opts, rp.WithAuthMethod(resolved.authMethod))
	}
	if strings.TrimSpace(resolved.senderConstrain) != "" {
		opts = append(opts, rp.WithSenderConstrain(resolved.senderConstrain))
	}
	if strings.TrimSpace(resolved.fapiProfile) != "" {
		opts = append(opts, rp.WithFAPIProfile(resolved.fapiProfile))
	}
	if resolved.keyProvider != nil {
		opts = append(opts, rp.WithClientKeyProvider(resolved.keyProvider))
	}
	if provider, ok := providerMetadataForResolvedRequest(resolved); ok {
		opts = append(opts, rp.WithProviderMetadata(provider))
	}
	if len(resolved.authorizationDetails) > 0 {
		opts = append(opts, rp.WithAuthorizationDetails(resolved.authorizationDetails))
	}
	if strings.TrimSpace(resolved.responseMode) != "" {
		opts = append(opts, rp.WithResponseMode(resolved.responseMode))
	}
	if strings.TrimSpace(resolved.requestMethod) != "" {
		opts = append(opts, rp.WithRequestMethod(resolved.requestMethod))
	}

	return rp.New(r.Context(), resolved.issuer, resolved.clientID, resolved.clientSecret, resolved.redirectURI, opts...)
}

func providerMetadataForResolvedRequest(resolved resolvedRPRequest) (oidc.ProviderMetadata, bool) {
	if scopesContainOpenID(resolved.scopes) {
		return oidc.ProviderMetadata{}, false
	}
	if _, err := issuerAlias(resolved.issuer); err != nil {
		return oidc.ProviderMetadata{}, false
	}

	base := strings.TrimRight(strings.TrimSpace(resolved.issuer), "/")
	mtlsBase, err := conformanceMTLSBaseURL(resolved.issuer)
	if err != nil {
		return oidc.ProviderMetadata{}, false
	}

	return oidc.ProviderMetadata{
		AuthorizationServerMetadata: oidc.AuthorizationServerMetadata{
			Issuer:                 resolved.issuer,
			AuthorizationEndpoint:  base + "/authorize",
			TokenEndpoint:          base + "/token",
			ResponseTypesSupported: []string{"code"},
			MTLSEndpointAliases: oidc.MTLSEndpointAliases{
				TokenEndpoint:                      mtlsBase + "/token",
				UserinfoEndpoint:                   mtlsBase + "/userinfo",
				PushedAuthorizationRequestEndpoint: mtlsBase + "/par",
			},
		},
		PushedAuthorizationRequestEndpoint: base + "/par",
	}, true
}

func scopesContainOpenID(scopes []string) bool {
	for _, scope := range scopes {
		if strings.EqualFold(strings.TrimSpace(scope), "openid") {
			return true
		}
	}
	return false
}

func conformanceMTLSBaseURL(issuer string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil {
		return "", err
	}
	parsed.Host = parsed.Hostname() + ":8444"
	trimmedPath := strings.TrimRight(parsed.Path, "/")
	parsed.Path = strings.Replace(trimmedPath, "/test/a/", "/test-mtls/a/", 1)
	parsed.RawPath = ""
	return parsed.String(), nil
}
