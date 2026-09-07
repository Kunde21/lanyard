package metadata

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Kunde21/lanyard/validateurl"
)

func validateRequired(issuer, name, value string) error {
	if value == "" {
		return &ValidationError{Issuer: issuer, Field: name, Expected: "non-empty", Actual: ""}
	}
	return nil
}

func validateRequiredSlice(issuer, name string, slice []string) error {
	if len(slice) == 0 {
		return &ValidationError{Issuer: issuer, Field: name, Expected: "non-empty", Actual: "[]"}
	}
	return nil
}

func validateIssuerURL(issuer string) (*url.URL, error) {
	u, err := validateurl.ParseHTTPSAbsoluteNoQueryFragment(issuer)
	if err != nil {
		if errors.Is(err, validateurl.ErrInvalidFormat) {
			return nil, &ValidationError{
				Field:    "issuer",
				Expected: "valid https URL",
				Actual:   issuer,
				Err:      fmt.Errorf("failed to parse issuer: %w", err),
			}
		}
		if errors.Is(err, validateurl.ErrQueryOrFragment) {
			return nil, &ValidationError{
				Field:    "issuer",
				Expected: "issuer without query or fragment",
				Actual:   issuer,
				Err:      ErrInvalidIssuer,
			}
		}
		return nil, &ValidationError{
			Field:    "issuer",
			Expected: "absolute https URL",
			Actual:   issuer,
			Err:      ErrInvalidIssuer,
		}
	}

	return u, nil
}

func issuerMatches(expected, actual string, tolerateTrailingSlash bool) bool {
	if expected == actual {
		return true
	}

	if !tolerateTrailingSlash {
		return false
	}

	nExpected := strings.TrimSuffix(expected, "/")
	nActual := strings.TrimSuffix(actual, "/")
	return nExpected == nActual
}

// isLoopbackHost reports whether the URL host is a loopback address, where
// plain HTTP is development-acceptable (RFC 8252).
func isLoopbackHost(parsed *url.URL) bool {
	host := parsed.Hostname()
	return host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")
}

func validateHTTPSURL(issuer, fieldName, raw string, required bool) error {
	if raw == "" {
		if required {
			return &ValidationError{
				Issuer:   issuer,
				Field:    fieldName,
				Expected: "non-empty https URL",
				Actual:   raw,
			}
		}
		return nil
	}

	parsed, parseErr := url.Parse(raw)
	secure := parseErr == nil && (parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopbackHost(parsed)))
	if _, err := validateurl.ParseHTTPSAbsoluteNoQueryFragment(raw); err != nil && !secure {
		if errors.Is(err, validateurl.ErrInvalidFormat) {
			return &ValidationError{
				Issuer:   issuer,
				Field:    fieldName,
				Expected: "valid https URL",
				Actual:   raw,
				Err:      err,
			}
		}
		if errors.Is(err, validateurl.ErrQueryOrFragment) {
			return &ValidationError{
				Issuer:   issuer,
				Field:    fieldName,
				Expected: "URL without query or fragment",
				Actual:   raw,
				Err:      ErrInvalidIssuer,
			}
		}
		return &ValidationError{
			Issuer:   issuer,
			Field:    fieldName,
			Expected: "absolute https URL",
			Actual:   raw,
			Err:      ErrInvalidIssuer,
		}
	}

	return nil
}

func (c *Client) validateProvider(expectedIssuer string, provider Provider) error {
	return validateProviderDocument(expectedIssuer, provider, c.issuerTrailingSlashTolerance)
}

// ValidateProvider checks a provider document's endpoints (including
// extension endpoints and mTLS aliases) for secure, absolute URLs.
// Preloaded metadata bypasses discovery, so callers accepting provider
// metadata from their own configuration should validate it with this
// function (or rely on the RP constructors that do).
func ValidateProvider(expectedIssuer string, provider Provider) error {
	return validateProviderDocument(expectedIssuer, provider, false)
}

func validateProviderDocument(expectedIssuer string, provider Provider, tolerateTrailingSlash bool) error {
	if err := validateRequired(expectedIssuer, "issuer", provider.Issuer); err != nil {
		return err
	}
	if !issuerMatches(expectedIssuer, provider.Issuer, tolerateTrailingSlash) {
		return &ValidationError{
			Issuer:   expectedIssuer,
			Field:    "issuer",
			Expected: expectedIssuer,
			Actual:   provider.Issuer,
			Err:      ErrInvalidIssuer,
		}
	}
	if err := validateRequired(expectedIssuer, "authorization_endpoint", provider.AuthorizationEndpoint); err != nil {
		return err
	}
	if err := validateRequired(expectedIssuer, "jwks_uri", provider.JWKSURI); err != nil {
		return err
	}
	if err := validateRequiredSlice(expectedIssuer, "response_types_supported", provider.ResponseTypesSupported); err != nil {
		return err
	}
	if err := validateRequiredSlice(expectedIssuer, "subject_types_supported", provider.SubjectTypesSupported); err != nil {
		return err
	}
	if err := validateRequiredSlice(expectedIssuer, "id_token_signing_alg_values_supported", provider.IDTokenSigningAlgValuesSupported); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "authorization_endpoint", provider.AuthorizationEndpoint, true); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "jwks_uri", provider.JWKSURI, true); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "token_endpoint", provider.TokenEndpoint, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "userinfo_endpoint", provider.UserinfoEndpoint, false); err != nil {
		return err
	}
	// Extension endpoints that carry credentials or signed material
	// (fourth RC review R2).
	if err := validateEndpointsDocument(expectedIssuer, provider); err != nil {
		return err
	}
	return nil
}

// ValidateEndpoints checks that every endpoint set on the provider document -
// including extension endpoints and mTLS aliases - is an absolute secure
// URL (plain HTTP is development-acceptable only for loopback hosts). Use
// for preloaded provider metadata, which bypasses discovery validation.
func ValidateEndpoints(issuer string, provider Provider) error {
	return validateEndpointsDocument(issuer, provider)
}

func validateEndpointsDocument(issuer string, provider Provider) error {
	for field, endpoint := range map[string]string{
		"authorization_endpoint":                  provider.AuthorizationEndpoint,
		"jwks_uri":                                provider.JWKSURI,
		"token_endpoint":                          provider.TokenEndpoint,
		"userinfo_endpoint":                       provider.UserinfoEndpoint,
		"pushed_authorization_request_endpoint":   provider.PushedAuthorizationRequestEndpoint,
		"introspection_endpoint":                  provider.IntrospectionEndpoint,
		"registration_endpoint":                   provider.RegistrationEndpoint,
		"grant_management_endpoint":               provider.GrantManagementEndpoint,
		"mtls_endpoint_aliases.token_endpoint":    provider.MTLSEndpointAliases.TokenEndpoint,
		"mtls_endpoint_aliases.userinfo_endpoint": provider.MTLSEndpointAliases.UserinfoEndpoint,
		"mtls_endpoint_aliases.pushed_authorization_request_endpoint": provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint,
		"mtls_endpoint_aliases.introspection_endpoint":                provider.MTLSEndpointAliases.IntrospectionEndpoint,
	} {
		if err := validateHTTPSURL(issuer, field, endpoint, false); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) validateAuthorizationServer(expectedIssuer string, server AuthorizationServer) error {
	if err := validateRequired(expectedIssuer, "issuer", server.Issuer); err != nil {
		return err
	}
	if !issuerMatches(expectedIssuer, server.Issuer, c.issuerTrailingSlashTolerance) {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: expectedIssuer, Actual: server.Issuer, Err: ErrInvalidIssuer}
	}
	if err := validateRequiredSlice(expectedIssuer, "response_types_supported", server.ResponseTypesSupported); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "authorization_endpoint", server.AuthorizationEndpoint, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "jwks_uri", server.JWKSURI, false); err != nil {
		return err
	}
	return validateHTTPSURL(expectedIssuer, "token_endpoint", server.TokenEndpoint, false)
}
