package rp

import (
	"context"
	"errors"
	"testing"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/google/go-cmp/cmp"
)

func TestNew_AutoNegotiatesAuthMethodPrefersPost(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithProviderDiscovery(providerForAuthMethods("client_secret_basic", "client_secret_post")),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff(AuthMethodPost, r.resolvedAuthMethod); diff != "" {
		t.Fatalf("resolved auth method mismatch (-want +got):\n%s", diff)
	}
	if r.allowMethodFallback {
		t.Fatalf("allowMethodFallback should be false when provider metadata declares supported methods")
	}
}

func TestNew_WithAuthMethodValidatesAgainstProviderMetadata(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithProviderDiscovery(providerForAuthMethods("client_secret_post")),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff(AuthMethodPost, r.resolvedAuthMethod); diff != "" {
		t.Fatalf("resolved auth method mismatch (-want +got):\n%s", diff)
	}
}

func TestNew_WithAuthMethodReturnsTypedErrorWhenUnsupported(t *testing.T) {
	_, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithProviderDiscovery(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodPost),
	)
	if err == nil {
		t.Fatalf("New() expected error")
	}

	var methodErr *AuthMethodError
	if !errors.As(err, &methodErr) {
		t.Fatalf("expected *AuthMethodError, got %T (%v)", err, err)
	}
	if !errors.Is(err, ErrAuthMethodNotSupported) {
		t.Fatalf("expected ErrAuthMethodNotSupported, got %v", err)
	}
}

func TestNew_WithSecretBasedAuthMethodRequiresClientSecret(t *testing.T) {
	_, err := New(
		context.Background(),
		"https://issuer.test",
		"client",
		"",
		"https://rp.test/callback",
		WithProviderDiscovery(providerForAuthMethods("client_secret_post")),
		WithAuthMethod(AuthMethodPost),
	)
	if err == nil {
		t.Fatalf("New() expected error")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func providerForAuthMethods(methods ...string) oidc.ProviderMetadata {
	return oidc.ProviderMetadata{
		AuthorizationServerMetadata: oidc.AuthorizationServerMetadata{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     "https://issuer.test/token",
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: append([]string(nil), methods...),
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
}
