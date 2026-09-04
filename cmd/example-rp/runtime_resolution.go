package main

import (
	"context"
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

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
	"github.com/Kunde21/lanyard/rp/store/cookie"
	"github.com/Kunde21/lanyard/rp/store/memory"
)

var (
	sharedStateStore    = newSharedStateStore()
	sharedMemoryStore   = memory.New(10 * time.Minute)
	sharedRequestStore  = newRequestObjectStore(5 * time.Minute)
	conformanceRuntimes = newRuntimeRegistry()
)

var defaultScopes = []string{"openid", "profile", "email", "phone", "address"}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type resolvedRPRequest struct {
	issuer                              string
	clientID                            string
	clientSecret                        string
	redirectURI                         string
	scopes                              []string
	stateStore                          rp.StateStore
	userInfoTransport                   rp.UserInfoTokenTransport
	authMethod                          rp.AuthMethod
	hasAuthMethod                       bool
	keyProvider                         rp.ClientKeyProvider
	requirePAR                          bool
	senderConstrain                     string
	fapiProfile                         string
	authorizationDetails                []map[string]any
	responseMode                        string
	responseType                        string
	requestMethod                       string
	profile                             string
	discoveryMode                       string
	validateAuthorizationResponseIssuer bool
	useRequestURI                       bool
	provider                            *metadata.Provider
	startupAction                       startupAction
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
	moduleName := strings.TrimSpace(r.URL.Query().Get("module_name"))
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
			return applyRuntimeConfig(resolved, runtimeCfg, moduleName)
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
		return applyRuntimeConfig(resolved, runtimeCfg, moduleName)
	}

	return resolved, nil
}

func resolveRPRequestFromRuntimeConfig(cfg rpRuntimeConfig) (resolvedRPRequest, error) {
	resolved := resolvedRPRequest{
		issuer:            cfg.Issuer,
		clientID:          cfg.ClientID,
		clientSecret:      cfg.ClientSecret,
		redirectURI:       cfg.RedirectURI,
		scopes:            append([]string(nil), cfg.Scopes...),
		stateStore:        stateStoreForRuntime(cfg),
		userInfoTransport: rp.UserInfoTokenTransportHeader,
	}
	if cfg.UserInfoTokenTransport != "" {
		resolved.userInfoTransport = cfg.UserInfoTokenTransport
	}
	if method, ok := authMethodForRuntime(cfg); ok {
		resolved.authMethod = method
		resolved.hasAuthMethod = true
	}
	resolved.requirePAR = runtimeRequiresPAR(cfg)
	resolved.senderConstrain = cfg.SenderConstrain
	resolved.fapiProfile = cfg.FAPIProfile
	resolved.validateAuthorizationResponseIssuer = cfg.ValidateAuthorizationResponseIssuer
	resolved.authorizationDetails = authorizationDetailsForRuntime(cfg)
	resolved.responseMode = cfg.ResponseMode
	resolved.responseType = cfg.ResponseType
	resolved.requestMethod = requestMethodForRuntime(cfg)
	resolved.profile = cfg.Profile
	resolved.discoveryMode = cfg.DiscoveryMode
	resolved.useRequestURI = shouldUseRequestURI(cfg)
	resolved.startupAction = cfg.startupAction()

	keyProvider, err := loadRequestObjectKeyProvider(cfg.ClientAuthType, cfg.SenderConstrain, cfg.RequestType)
	if err != nil {
		return resolvedRPRequest{}, err
	}
	resolved.keyProvider = keyProvider

	if shouldRegisterDynamically(cfg) {
		clientID, clientSecret, provider, err := ensureDynamicClientRegistration(context.Background(), cfg, cfg.ModuleName)
		if err != nil {
			return resolvedRPRequest{}, err
		}
		resolved.clientID = clientID
		resolved.clientSecret = clientSecret
		resolved.provider = provider
	}

	return resolved, nil
}

func applyRuntimeConfig(resolved resolvedRPRequest, runtimeCfg rpRuntimeConfig, moduleName string) (resolvedRPRequest, error) {
	resolved, err := applyRuntimeConfigFields(resolved, runtimeCfg, moduleName)
	if err != nil {
		return resolvedRPRequest{}, err
	}
	if !shouldRegisterDynamically(runtimeCfg) {
		return resolved, nil
	}

	clientID, clientSecret, provider, err := ensureDynamicClientRegistration(context.Background(), runtimeCfg, moduleName)
	if err != nil {
		return resolvedRPRequest{}, err
	}
	resolved.clientID = clientID
	resolved.clientSecret = clientSecret
	resolved.provider = provider
	return resolved, nil
}

func applyRuntimeConfigFields(resolved resolvedRPRequest, runtimeCfg rpRuntimeConfig, moduleName string) (resolvedRPRequest, error) {
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
	resolved.validateAuthorizationResponseIssuer = runtimeCfg.ValidateAuthorizationResponseIssuer
	resolved.authorizationDetails = authorizationDetailsForRuntime(runtimeCfg)
	resolved.responseMode = runtimeCfg.ResponseMode
	resolved.responseType = runtimeCfg.ResponseType
	resolved.requestMethod = requestMethodForRuntime(runtimeCfg)
	resolved.profile = runtimeCfg.Profile
	resolved.discoveryMode = runtimeCfg.DiscoveryMode
	resolved.useRequestURI = shouldUseRequestURI(runtimeCfg)
	resolved.startupAction = runtimeCfg.startupAction()
	if shouldUseSecondClient(runtimeCfg, moduleName) {
		resolved.clientID = "local-dev-client-2"
		resolved.clientSecret = "local-dev-secret-2-32-bytes-min!!"
	}

	keyProvider, err := loadRequestObjectKeyProvider(runtimeCfg.ClientAuthType, runtimeCfg.SenderConstrain, runtimeCfg.RequestType)
	if err != nil {
		return resolvedRPRequest{}, err
	}
	resolved.keyProvider = keyProvider

	return resolved, nil
}

func stateStoreForRuntime(cfg rpRuntimeConfig) rp.StateStore {
	if shouldUseMemoryStateStore(cfg) {
		return newNamespacedStateStore(sharedMemoryStore, cfg.Namespace)
	}
	return wrapWithIssuerShorthand(newNamespacedStateStore(sharedStateStore, cfg.Namespace))
}

func shouldUseMemoryStateStore(cfg rpRuntimeConfig) bool {
	profile := strings.ToLower(strings.TrimSpace(cfg.FAPIProfile))
	return strings.HasPrefix(profile, "plain_fapi") ||
		strings.Contains(profile, "fapi2")
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
	case "request_uri":
		if strings.TrimSpace(cfg.FAPIProfile) != "" {
			return true
		}
	}

	return false
}

func shouldUseRequestURI(cfg rpRuntimeConfig) bool {
	if strings.ToLower(strings.TrimSpace(cfg.RequestType)) != "request_uri" {
		return false
	}
	if runtimeRequiresPAR(cfg) {
		return false
	}
	return true
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
	case "tls_client_auth", "mtls":
		return rp.AuthMethodTLSClientAuth, true
	case "self_signed_tls_client_auth":
		return rp.AuthMethodSelfSignedTLSClientAuth, true
	case "none":
		return rp.AuthMethodNone, true
	case "client_secret_jwt":
		return rp.AuthMethodClientSecretJWT, true
	default:
		return "", false
	}
}

func requestMethodForRuntime(cfg rpRuntimeConfig) string {
	if strings.TrimSpace(cfg.FAPIRequestMethod) != "" {
		return cfg.FAPIRequestMethod
	}
	switch strings.ToLower(strings.TrimSpace(cfg.RequestType)) {
	case "request_object", "request_uri":
		return "signed_non_repudiation"
	}
	return ""
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
	metadataOpts := []metadata.Option{metadata.WithHTTPClient(httpClient)}
	if envTrue("RP_CONFORMANCE_FRESH_DISCOVERY") {
		metadataOpts = append(metadataOpts, metadata.WithConformanceFreshDiscovery(true))
	}
	metadataClient := metadata.NewClient(metadataOpts...)

	opts := []rp.Option{
		rp.WithHTTPClient(httpClient),
		rp.WithMetadataClient(metadataClient),
		rp.WithStateStore(resolved.stateStore),
		rp.WithUserInfoTokenTransport(resolved.userInfoTransport),
		rp.WithScopes(resolved.scopes...),
		rp.WithRequirePAR(resolved.requirePAR),
	}
	if resolved.hasAuthMethod {
		opts = append(opts, rp.WithAuthMethod(resolved.authMethod))
	}
	if strings.TrimSpace(resolved.senderConstrain) != "" {
		opts = append(opts, rp.WithSenderConstrain(rp.SenderConstraint(resolved.senderConstrain)))
	}
	if resolved.validateAuthorizationResponseIssuer {
		opts = append(opts, rp.WithValidateAuthorizationResponseIssuer(true))
	}
	if resolved.keyProvider != nil {
		opts = append(opts, rp.WithClientKeyProvider(resolved.keyProvider))
	}
	if resolved.provider != nil {
		opts = append(opts, rp.WithProviderMetadata(*resolved.provider))
	} else if provider, ok := providerMetadataForResolvedRequest(resolved); ok {
		opts = append(opts, rp.WithProviderMetadata(provider))
	}
	if len(resolved.authorizationDetails) > 0 {
		opts = append(opts, rp.WithAuthorizationDetails(resolved.authorizationDetails))
	}
	if strings.TrimSpace(resolved.responseMode) != "" {
		opts = append(opts, rp.WithResponseMode(resolved.responseMode))
	}
	if strings.TrimSpace(resolved.responseType) != "" {
		opts = append(opts, rp.WithResponseType(resolved.responseType))
	}
	if strings.TrimSpace(resolved.requestMethod) != "" {
		opts = append(opts, rp.WithRequestMethod(resolved.requestMethod))
	}
	if strings.TrimSpace(resolved.fapiProfile) != "" {
		opts = append(opts, rp.WithProfile(rp.PlainFAPI))
	}
	if shouldAllowUnsecuredIDTokens(resolved) {
		opts = append(opts, rp.WithAllowUnsecuredIDTokens(true))
	}
	if resolved.useRequestURI {
		opts = append(opts, rp.WithRequestURIMode(func(signedJWT string) (string, error) {
			id, err := sharedRequestStore.Store(signedJWT)
			if err != nil {
				return "", err
			}
			return "https://rp.localhost/request/" + id, nil
		}))
	}

	return rp.New(r.Context(), resolved.issuer,
		append([]rp.Option{
			rp.WithClientID(resolved.clientID),
			rp.WithClientSecret(resolved.clientSecret),
			rp.WithRedirectURI(resolved.redirectURI),
		}, opts...)...,
	)
}

func shouldUseSecondClient(cfg rpRuntimeConfig, moduleName string) bool {
	if strings.TrimSpace(cfg.Namespace) == "" {
		return false
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(moduleName)), "encrypted-idtoken")
}

func shouldAllowUnsecuredIDTokens(resolved resolvedRPRequest) bool {
	if strings.TrimSpace(resolved.fapiProfile) != "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(resolved.profile)) {
	case "fapi1_adv", "fapi1-advanced", "fapi2_security_profile", "fapi2-sp", "fapi2_message_signing", "fapi2-ms":
		return false
	default:
		return true
	}
}

func providerMetadataForResolvedRequest(resolved resolvedRPRequest) (metadata.Provider, bool) {
	if scopesContainOpenID(resolved.scopes) && resolved.clientID != "local-dev-client-2" {
		return metadata.Provider{}, false
	}
	if _, err := issuerAlias(resolved.issuer); err != nil {
		return metadata.Provider{}, false
	}

	base := strings.TrimRight(strings.TrimSpace(resolved.issuer), "/")
	mtlsBase, err := conformanceMTLSBaseURL(resolved.issuer)
	if err != nil {
		return metadata.Provider{}, false
	}

	return metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            resolved.issuer,
			AuthorizationEndpoint:             base + "/authorize",
			TokenEndpoint:                     base + "/token",
			JWKSURI:                           base + "/jwks",
			ResponseTypesSupported:            []string{"code"},
			ResponseModesSupported:            []string{"jwt"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			TokenEndpointAuthMethodsSupported: []string{"tls_client_auth", "private_key_jwt"},
			TokenEndpointAuthSigningAlgValuesSupported: []string{"PS256", "ES256", "EdDSA"},
			MTLSEndpointAliases: metadata.MTLSEndpointAliases{
				TokenEndpoint:                      mtlsBase + "/token",
				UserinfoEndpoint:                   mtlsBase + "/userinfo",
				PushedAuthorizationRequestEndpoint: mtlsBase + "/par",
			},
		},
		UserinfoEndpoint:                       base + "/userinfo",
		SubjectTypesSupported:                  []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:       []string{"PS256", "RS256"},
		PushedAuthorizationRequestEndpoint:     base + "/par",
		RequestObjectSigningAlgValuesSupported: []string{"PS256", "ES256", "EdDSA"},
		AuthorizationSigningAlgValuesSupported: []string{"PS256"},
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

func rpDiscoveryModeForResolvedRequest(resolved resolvedRPRequest) (rp.DiscoveryMode, bool) {
	switch strings.ToLower(strings.TrimSpace(resolved.discoveryMode)) {
	case "oidc":
		return rp.DiscoveryOIDC, true
	case "oauth2":
		return rp.DiscoveryOAuth2, true
	case "disabled":
		return rp.DiscoveryDisabled, true
	case "auto":
		return rp.DiscoveryAuto, true
	default:
		return rp.DiscoveryAuto, false
	}
}
