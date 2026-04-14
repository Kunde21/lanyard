package rp

import (
	"fmt"
	"strings"
)

type AuthMethod string

const (
	AuthMethodNone                    AuthMethod = "none"
	AuthMethodBasic                   AuthMethod = "client_secret_basic"
	AuthMethodPost                    AuthMethod = "client_secret_post"
	AuthMethodClientSecretJWT         AuthMethod = "client_secret_jwt"
	AuthMethodPrivateKeyJWT           AuthMethod = "private_key_jwt"
	AuthMethodTLSClientAuth           AuthMethod = "tls_client_auth"
	AuthMethodSelfSignedTLSClientAuth AuthMethod = "self_signed_tls_client_auth"
)

func (r *RP) resolveAuthMethod() error {
	return r.clientConfig.resolveAuthMethodFromProvider()
}

func (r *RP) applySupportedAuthMethods(supportedAuthMethods []string) error {
	oldProvider := r.provider
	r.provider.TokenEndpointAuthMethodsSupported = supportedAuthMethods
	err := r.clientConfig.resolveAuthMethodFromProvider()
	r.provider = oldProvider
	return err
}

func normalizeSupportedAuthMethods(methods []string) []string {
	normalized := make([]string, 0, len(methods))
	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		trimmed := strings.TrimSpace(strings.ToLower(method))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	return normalized
}

func methodExactMatch(method AuthMethod, supported []string) bool {
	want := strings.ToLower(strings.TrimSpace(string(method)))
	for _, current := range supported {
		if current == want {
			return true
		}
	}
	return false
}

func methodSupported(method AuthMethod, supported []string) bool {
	want := strings.ToLower(strings.TrimSpace(string(method)))
	if want == "" {
		return false
	}

	for _, current := range supported {
		if current == want {
			return true
		}
	}

	if want == "tls_client_auth" || want == "self_signed_tls_client_auth" {
		for _, current := range supported {
			if current == "tls_client_auth" || current == "self_signed_tls_client_auth" {
				return true
			}
		}
	}

	if want == "none" {
		return true
	}

	return false
}

func validateResolvedAuthMethod(method AuthMethod, clientSecret string) error {
	switch method {
	case AuthMethodBasic, AuthMethodPost:
		if strings.TrimSpace(clientSecret) == "" {
			return fmt.Errorf("%w: client_secret is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported token endpoint auth method %q", ErrInvalidConfiguration, method)
	}
}
