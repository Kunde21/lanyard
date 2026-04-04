package metadata

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Kunde21/lanyard/validateurl"
)

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

	if _, err := validateurl.ParseHTTPSAbsoluteNoQueryFragment(raw); err != nil {
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
	if provider.Issuer == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: "non-empty", Actual: ""}
	}
	if !issuerMatches(expectedIssuer, provider.Issuer, c.issuerTrailingSlashTolerance) {
		return &ValidationError{
			Issuer:   expectedIssuer,
			Field:    "issuer",
			Expected: expectedIssuer,
			Actual:   provider.Issuer,
			Err:      ErrInvalidIssuer,
		}
	}
	if provider.AuthorizationEndpoint == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "authorization_endpoint", Expected: "non-empty", Actual: ""}
	}
	if provider.JWKSURI == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "jwks_uri", Expected: "non-empty", Actual: ""}
	}
	if len(provider.ResponseTypesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "response_types_supported", Expected: "non-empty", Actual: "[]"}
	}
	if len(provider.SubjectTypesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "subject_types_supported", Expected: "non-empty", Actual: "[]"}
	}
	if len(provider.IDTokenSigningAlgValuesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "id_token_signing_alg_values_supported", Expected: "non-empty", Actual: "[]"}
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

	return nil
}

func (c *Client) validateAuthorizationServer(expectedIssuer string, server AuthorizationServer) error {
	if server.Issuer == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: "non-empty", Actual: ""}
	}
	if !issuerMatches(expectedIssuer, server.Issuer, c.issuerTrailingSlashTolerance) {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: expectedIssuer, Actual: server.Issuer, Err: ErrInvalidIssuer}
	}
	if len(server.ResponseTypesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "response_types_supported", Expected: "non-empty", Actual: "[]"}
	}
	if err := validateHTTPSURL(expectedIssuer, "authorization_endpoint", server.AuthorizationEndpoint, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "jwks_uri", server.JWKSURI, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "token_endpoint", server.TokenEndpoint, false); err != nil {
		return err
	}

	return nil
}
