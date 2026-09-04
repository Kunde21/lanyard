package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

// dynamicRegistrationEntry caches the credentials issued for one dynamically
// registered client together with the provider metadata discovered in the
// same module window, scoped to the conformance module that requested them.
// The suite creates a fresh client record from each registration POST, and
// some modules (rp-registration-dynamic) FINISH on the registration POST —
// any further discovery against the mock then fails, so the provider
// discovered alongside the registration is cached and reused for the rest of
// the module's flow.
type dynamicRegistrationEntry struct {
	clientID     string
	clientSecret string
	moduleName   string
	provider     *metadata.Provider
}

var dynamicRegistrations = struct {
	sync.Mutex
	entries map[string]dynamicRegistrationEntry
}{entries: map[string]dynamicRegistrationEntry{}}

// resetDynamicRegistrations clears the cache; used by tests.
func resetDynamicRegistrations() {
	dynamicRegistrations.Lock()
	defer dynamicRegistrations.Unlock()
	dynamicRegistrations.entries = map[string]dynamicRegistrationEntry{}
}

// ensureDynamicClientRegistration returns client credentials and the provider
// metadata for a dynamic conformance runtime. Per module window (identified
// by module_name) it discovers the provider once, registers a fresh client
// via RFC 7591, and caches both; callbacks and repeated requests (which do
// not carry module_name) reuse the cached entry.
func ensureDynamicClientRegistration(ctx context.Context, cfg rpRuntimeConfig, moduleName string) (string, string, *metadata.Provider, error) {
	alias := strings.TrimSpace(cfg.Alias)
	if alias == "" {
		return "", "", nil, fmt.Errorf("dynamic client registration requires a runtime alias")
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		return "", "", nil, fmt.Errorf("dynamic client registration requires a runtime issuer")
	}

	dynamicRegistrations.Lock()
	defer dynamicRegistrations.Unlock()

	if cached, ok := dynamicRegistrations.entries[alias]; ok {
		if moduleName == "" || moduleName == cached.moduleName {
			return cached.clientID, cached.clientSecret, cached.provider, nil
		}
	}

	// The request-object signing algorithm must match what the example RP
	// actually signs with (the conformance key set's algorithm), or the
	// suite's ValidateRequestObjectSignature rejects the request object.
	requestObjectAlg := ""
	if requestTypeNeedsAsymmetricSigningKey(cfg.RequestType) {
		keys, keysErr := loadConformanceKeySet()
		if keysErr != nil {
			return "", "", nil, fmt.Errorf("dynamic registration key set failed: %w", keysErr)
		}
		requestObjectAlg = keys.rsaAlg
	}

	// Single discovery for the whole window: feeds both the Registrar and the
	// RP built afterwards, so no second discovery can hit a mock that already
	// FINISHED on the registration POST.
	provider, err := newMetadataClient(nil).DiscoverProvider(ctx, cfg.Issuer)
	if err != nil {
		return "", "", nil, fmt.Errorf("dynamic registration discovery failed: %w", err)
	}

	registrar, err := rp.NewRegistrar(ctx, cfg.Issuer,
		rp.WithProviderMetadata(provider),
		rp.WithHTTPClient(newRPHTTPClient(nil)),
	)
	if err != nil {
		return "", "", nil, fmt.Errorf("dynamic registration setup failed: %w", err)
	}
	reg, err := registrar.Register(ctx, rp.ClientMetadata{
		RedirectURIs:            []string{cfg.RedirectURI},
		TokenEndpointAuthMethod: rp.AuthMethodBasic,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Lanyard example RP",
		Contacts:                []string{"dev@example.org"},
		RequestURIs:             []string{"https://rp.localhost/request/"},
		JWKSURI:                 "https://rp.localhost/conformance/jwks/" + alias,
		RequestObjectSigningAlg: requestObjectAlg,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("dynamic client registration failed: %w", err)
	}

	dynamicRegistrations.entries[alias] = dynamicRegistrationEntry{
		clientID:     reg.ClientID,
		clientSecret: reg.ClientSecret,
		moduleName:   moduleName,
		provider:     &provider,
	}
	return reg.ClientID, reg.ClientSecret, &provider, nil
}

// shouldRegisterDynamically reports whether a runtime configuration should
// resolve through dynamic client registration. Only full-flow modules need
// credentials; discovery-style modules intentionally break discovery
// (random-suffix issuers, INVALID issuer) and must not attempt registration.
func shouldRegisterDynamically(cfg rpRuntimeConfig) bool {
	return cfg.DynamicClientRegistration && cfg.startupAction() == startupActionFullFlow
}
