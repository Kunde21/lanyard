package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Kunde21/lanyard/rp"
)

// dynamicRegistrationEntry caches the credentials issued for one dynamically
// registered client, scoped to the conformance module window that requested
// them. The suite creates a fresh client record from each registration POST,
// so each module (identified by module_name) must use credentials issued in
// that module's window.
type dynamicRegistrationEntry struct {
	clientID     string
	clientSecret string
	moduleName   string
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

// ensureDynamicClientRegistration returns the client credentials for a
// dynamic conformance runtime. It registers a fresh client via RFC 7591 when
// a new module window starts (module_name differs from the cached one) or no
// cached registration exists, and reuses the cached credentials otherwise
// (callbacks do not carry module_name).
func ensureDynamicClientRegistration(ctx context.Context, cfg rpRuntimeConfig, moduleName string) (string, string, error) {
	alias := strings.TrimSpace(cfg.Alias)
	if alias == "" {
		return "", "", fmt.Errorf("dynamic client registration requires a runtime alias")
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		return "", "", fmt.Errorf("dynamic client registration requires a runtime issuer")
	}

	dynamicRegistrations.Lock()
	defer dynamicRegistrations.Unlock()

	if cached, ok := dynamicRegistrations.entries[alias]; ok {
		if moduleName == "" || moduleName == cached.moduleName {
			return cached.clientID, cached.clientSecret, nil
		}
	}

	registrar, err := rp.NewRegistrar(ctx, cfg.Issuer, rp.WithHTTPClient(newRPHTTPClient(nil)))
	if err != nil {
		return "", "", fmt.Errorf("dynamic registration setup failed: %w", err)
	}
	reg, err := registrar.Register(ctx, rp.ClientMetadata{
		RedirectURIs:            []string{cfg.RedirectURI},
		TokenEndpointAuthMethod: rp.AuthMethodBasic,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Lanyard example RP",
		Contacts:                []string{"dev@example.org"},
	})
	if err != nil {
		return "", "", fmt.Errorf("dynamic client registration failed: %w", err)
	}

	dynamicRegistrations.entries[alias] = dynamicRegistrationEntry{
		clientID:     reg.ClientID,
		clientSecret: reg.ClientSecret,
		moduleName:   moduleName,
	}
	return reg.ClientID, reg.ClientSecret, nil
}
