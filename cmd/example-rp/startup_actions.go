package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

func executeStartupAction(ctx context.Context, cfg rpRuntimeConfig, resolved resolvedRPRequest) (runtimeStartupResponse, error) {
	action := cfg.startupAction()
	switch action {
	case startupActionDiscoveryOnly:
		return runtimeStartupResponse{}, executeDiscoveryOnly(ctx, resolved)
	case startupActionDiscoveryAndJWKS:
		return runtimeStartupResponse{}, executeDiscoveryAndJWKS(ctx, resolved)
	case startupActionDiscoveryWebFinger, startupActionDiscoveryWebFingerUR:
		return runtimeStartupResponse{}, executeWebFingerDiscovery(ctx, resolved, action == startupActionDiscoveryWebFinger)
	case startupActionFullFlow:
		return prepareFullFlowStartup(ctx, resolved)
	default:
		return runtimeStartupResponse{}, nil
	}
}

// executeWebFingerDiscovery resolves the issuer via WebFinger (RFC 7033) —
// using an acct: resource or an HTTPS URL resource depending on the module —
// and then discovers the provider at the resolved location.
func executeWebFingerDiscovery(ctx context.Context, resolved resolvedRPRequest, acctResource bool) error {
	var resource string
	var err error
	if acctResource {
		resource, err = webFingerAcctResource(resolved.issuer)
	} else {
		resource, err = webFingerURLResource(resolved.issuer)
	}
	if err != nil {
		return fmt.Errorf("webfinger startup: build resource: %w", err)
	}

	metadataClient := newMetadataClient(resolved.keyProvider)
	provider, err := metadataClient.DiscoverProviderFromResource(ctx, resource)
	if err != nil {
		return fmt.Errorf("webfinger startup: discovery from resource %q failed: %w", resource, err)
	}

	slog.Info("webfinger startup complete",
		"resource", resource,
		"issuer", provider.Issuer,
		"jwks_uri", provider.JWKSURI,
	)
	return nil
}

func prepareFullFlowStartup(ctx context.Context, resolved resolvedRPRequest) (runtimeStartupResponse, error) {
	flow, err := buildRPForStartup(ctx, resolved)
	if err != nil {
		return runtimeStartupResponse{}, err
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/", nil).WithContext(ctx)
	authURL, err := flow.AuthorizationURL(rec, req)
	if err != nil {
		return runtimeStartupResponse{}, fmt.Errorf("full-flow startup: authorization url failed: %w", err)
	}

	cookies := rec.Header().Values("Set-Cookie")
	return runtimeStartupResponse{AuthorizationURL: authURL, Cookies: append([]string(nil), cookies...)}, nil
}

func executeDiscoveryOnly(ctx context.Context, resolved resolvedRPRequest) error {
	metadataClient := newMetadataClient(resolved.keyProvider)

	provider, err := discoverProviderForResolvedRequest(ctx, metadataClient, resolved)
	if err != nil {
		return fmt.Errorf("discovery-only startup: discovery failed: %w", err)
	}

	slog.Info("discovery-only startup complete",
		"issuer", resolved.issuer,
		"authorization_endpoint", provider.AuthorizationEndpoint,
		"token_endpoint", provider.TokenEndpoint,
		"jwks_uri", provider.JWKSURI,
	)
	return nil
}

func executeDiscoveryAndJWKS(ctx context.Context, resolved resolvedRPRequest) error {
	metadataClient := newMetadataClient(resolved.keyProvider)

	provider, err := discoverProviderForResolvedRequest(ctx, metadataClient, resolved)
	if err != nil {
		return fmt.Errorf("discovery+jwks startup: discovery failed: %w", err)
	}

	jwksURI := provider.JWKSURI
	if jwksURI == "" {
		return fmt.Errorf("discovery+jwks startup: provider metadata missing jwks_uri")
	}

	keySet, err := metadataClient.RemoteKeySetFromJWKSURI(jwksURI)
	if err != nil {
		return fmt.Errorf("discovery+jwks startup: jwks initialization failed: %w", err)
	}
	if _, err := keySet.Keys(ctx); err != nil {
		return fmt.Errorf("discovery+jwks startup: jwks fetch failed: %w", err)
	}

	slog.Info("discovery+jwks startup complete",
		"issuer", resolved.issuer,
		"jwks_uri", jwksURI,
	)
	return nil
}

func newMetadataClient(keyProvider rp.ClientKeyProvider) *metadata.Client {
	httpClient := newRPHTTPClient(keyProvider)
	metadataOpts := []metadata.Option{metadata.WithHTTPClient(httpClient)}
	if envTrue("RP_CONFORMANCE_FRESH_DISCOVERY") {
		metadataOpts = append(metadataOpts, metadata.WithConformanceFreshDiscovery(true))
	}
	return metadata.NewClient(metadataOpts...)
}

func discoverProviderForResolvedRequest(ctx context.Context, metadataClient *metadata.Client, resolved resolvedRPRequest) (metadata.Provider, error) {
	switch normalizeDiscoveryMode(resolved.discoveryMode, resolved.profile) {
	case "oauth2":
		as, err := metadataClient.DiscoverAuthorizationServer(ctx, resolved.issuer)
		if err != nil {
			return metadata.Provider{}, err
		}
		return metadata.Provider{AuthorizationServer: as}, nil
	default:
		return metadataClient.DiscoverProvider(ctx, resolved.issuer)
	}
}

func normalizeDiscoveryMode(mode, profile string) string {
	switch normalized := normalizeToken(mode); normalized {
	case "oidc", "oauth2":
		return normalized
	case "disabled":
		return normalized
	case "auto":
		fallthrough
	default:
		if normalizeToken(profile) == "oauth2" {
			return "oauth2"
		}
		return "oidc"
	}
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func buildRPForStartup(ctx context.Context, resolved resolvedRPRequest) (*rp.RP, error) {
	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/", nil).WithContext(ctx)
	return buildRPFromResolvedRequest(req, resolved)
}
