package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
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

type resolvedRPRequest struct {
	issuer            string
	clientID          string
	clientSecret      string
	redirectURI       string
	scopes            []string
	stateStore        rp.StateStore
	userInfoTransport rp.UserInfoTokenTransport
	authMethod        rp.AuthMethod
	hasAuthMethod     bool
	keyProvider       rp.ClientKeyProvider
	requirePAR        bool
	senderConstrain   string
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
		tlsConfig.Certificates = []tls.Certificate{*keyProvider.TLSCertificate()}
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
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
	if resolved.keyProvider != nil {
		opts = append(opts, rp.WithClientKeyProvider(resolved.keyProvider))
	}

	return rp.New(r.Context(), resolved.issuer, resolved.clientID, resolved.clientSecret, resolved.redirectURI, opts...)
}
