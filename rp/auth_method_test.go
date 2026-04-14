package rp

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func TestNew_AutoNegotiatesAuthMethodPrefersPost(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic", "client_secret_post")),
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
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("client_secret_post")),
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
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
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
		WithClientID("client"),
		WithClientSecret(""),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("client_secret_post")),
		WithAuthMethod(AuthMethodPost),
	)
	if err == nil {
		t.Fatalf("New() expected error")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func providerForAuthMethods(methods ...string) metadata.Provider {
	return metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
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

func TestAuthMethodSelfSignedTLSClientAuth_ConstantValue(t *testing.T) {
	if diff := cmp.Diff(AuthMethod("self_signed_tls_client_auth"), AuthMethodSelfSignedTLSClientAuth); diff != "" {
		t.Fatalf("constant mismatch (-want +got):\n%s", diff)
	}
}

func TestMethodSupported_SelfSignedTLSClientAuth(t *testing.T) {
	tests := []struct {
		name      string
		method    AuthMethod
		supported []string
		want      bool
	}{
		{
			name:      "exact match",
			method:    AuthMethodSelfSignedTLSClientAuth,
			supported: []string{"self_signed_tls_client_auth"},
			want:      true,
		},
		{
			name:      "self_signed matched when provider has tls_client_auth",
			method:    AuthMethodSelfSignedTLSClientAuth,
			supported: []string{"tls_client_auth"},
			want:      true,
		},
		{
			name:      "tls_client_auth matched when provider has self_signed",
			method:    AuthMethodTLSClientAuth,
			supported: []string{"self_signed_tls_client_auth"},
			want:      true,
		},
		{
			name:      "self_signed not matched by unrelated methods",
			method:    AuthMethodSelfSignedTLSClientAuth,
			supported: []string{"client_secret_post"},
			want:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := methodSupported(tc.method, tc.supported)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("methodSupported mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNew_SelfSignedTLSClientAuth_RequiresClientKeyProviderWithTLSCert(t *testing.T) {
	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("self_signed_tls_client_auth")),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth),
	)
	if err == nil {
		t.Fatalf("New() expected error when no client key provider")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestNew_AutoNegotiatesSelfSignedTLSClientAuthWhenAdvertised(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("self_signed_tls_client_auth")),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff(AuthMethodSelfSignedTLSClientAuth, r.resolvedAuthMethod); diff != "" {
		t.Fatalf("resolved auth method mismatch (-want +got):\n%s", diff)
	}
}
