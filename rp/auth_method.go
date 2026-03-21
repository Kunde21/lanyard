package rp

import (
	"fmt"
	"strings"
)

// AuthMethod represents an OAuth2 client authentication method for token endpoint requests.
type AuthMethod string

const (
	// AuthMethodBasic uses HTTP Basic authentication (client_secret_basic).
	AuthMethodBasic AuthMethod = "client_secret_basic"
	// AuthMethodPost sends credentials in the form body (client_secret_post).
	AuthMethodPost AuthMethod = "client_secret_post"
	// AuthMethodPrivateKeyJWT uses a private key signed JWT assertion (private_key_jwt).
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
	// AuthMethodTLSClientAuth uses mutual TLS client authentication (tls_client_auth).
	AuthMethodTLSClientAuth AuthMethod = "tls_client_auth"
)

func (r *RP) resolveAuthMethod() error {
	return r.applySupportedAuthMethods(r.provider.TokenEndpointAuthMethodsSupported)
}

func (r *RP) applySupportedAuthMethods(supportedAuthMethods []string) error {
	supported := normalizeSupportedAuthMethods(supportedAuthMethods)
	resolved := AuthMethodPost
	allowFallback := false

	if len(supported) > 0 {
		if r.authMethod != "" {
			if !methodSupported(r.authMethod, supported) {
				return &AuthMethodError{Method: r.authMethod, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
			resolved = r.authMethod
			allowFallback = false
		} else {
			switch {
			case methodSupported(AuthMethodPrivateKeyJWT, supported):
				resolved = AuthMethodPrivateKeyJWT
			case methodSupported(AuthMethodTLSClientAuth, supported):
				resolved = AuthMethodTLSClientAuth
			case methodSupported(AuthMethodPost, supported):
				resolved = AuthMethodPost
			case methodSupported(AuthMethodBasic, supported):
				resolved = AuthMethodBasic
			default:
				return &AuthMethodError{Method: AuthMethodPost, Supported: supported, Err: ErrAuthMethodNotSupported}
			}
			allowFallback = false
		}
	} else if r.authMethod != "" {
		resolved = r.authMethod
		allowFallback = false
	} else {
		resolved = AuthMethodPost
		allowFallback = true
	}

	if err := r.validateResolvedAuthMethod(resolved); err != nil {
		return err
	}

	r.setAuthMethodState(resolved, allowFallback)

	return nil
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

func (r *RP) validateResolvedAuthMethod(method AuthMethod) error {
	switch method {
	case AuthMethodBasic, AuthMethodPost:
		if strings.TrimSpace(r.clientSecret) == "" {
			return fmt.Errorf("%w: client_secret is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodPrivateKeyJWT:
		if r.clientKeyProvider == nil {
			return fmt.Errorf("%w: client_key_provider is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	case AuthMethodTLSClientAuth:
		if r.clientKeyProvider == nil || r.clientKeyProvider.TLSCertificate() == nil {
			return fmt.Errorf("%w: tls certificate is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported token endpoint auth method %q", ErrInvalidConfiguration, method)
	}
}

func (r *RP) authMethodState() (AuthMethod, bool) {
	r.methodMu.RLock()
	defer r.methodMu.RUnlock()

	return r.resolvedAuthMethod, r.allowMethodFallback
}

func (r *RP) setAuthMethodState(method AuthMethod, allowFallback bool) {
	r.methodMu.Lock()
	r.resolvedAuthMethod = method
	r.allowMethodFallback = allowFallback
	r.methodMu.Unlock()
}
