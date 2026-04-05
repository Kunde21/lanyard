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
	if err := validateRequired(expectedIssuer, "issuer", provider.Issuer); err != nil {
		return err
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
	return validateHTTPSURL(expectedIssuer, "userinfo_endpoint", provider.UserinfoEndpoint, false)
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
