package oidc

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

func (c *Client) validateProviderMetadata(expectedIssuer string, metadata ProviderMetadata) error {
	if metadata.Issuer == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: "non-empty", Actual: ""}
	}
	if !issuerMatches(expectedIssuer, metadata.Issuer, c.issuerTrailingSlashTolerance) {
		return &ValidationError{
			Issuer:   expectedIssuer,
			Field:    "issuer",
			Expected: expectedIssuer,
			Actual:   metadata.Issuer,
			Err:      ErrInvalidIssuer,
		}
	}
	if metadata.AuthorizationEndpoint == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "authorization_endpoint", Expected: "non-empty", Actual: ""}
	}
	if metadata.JWKSURI == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "jwks_uri", Expected: "non-empty", Actual: ""}
	}
	if len(metadata.ResponseTypesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "response_types_supported", Expected: "non-empty", Actual: "[]"}
	}
	if len(metadata.SubjectTypesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "subject_types_supported", Expected: "non-empty", Actual: "[]"}
	}
	if len(metadata.IDTokenSigningAlgValuesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "id_token_signing_alg_values_supported", Expected: "non-empty", Actual: "[]"}
	}
	if err := validateHTTPSURL(expectedIssuer, "authorization_endpoint", metadata.AuthorizationEndpoint, true); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "jwks_uri", metadata.JWKSURI, true); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "token_endpoint", metadata.TokenEndpoint, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "userinfo_endpoint", metadata.UserinfoEndpoint, false); err != nil {
		return err
	}

	return nil
}

func (c *Client) validateAuthorizationServerMetadata(expectedIssuer string, metadata AuthorizationServerMetadata) error {
	if metadata.Issuer == "" {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: "non-empty", Actual: ""}
	}
	if !issuerMatches(expectedIssuer, metadata.Issuer, c.issuerTrailingSlashTolerance) {
		return &ValidationError{Issuer: expectedIssuer, Field: "issuer", Expected: expectedIssuer, Actual: metadata.Issuer, Err: ErrInvalidIssuer}
	}
	if len(metadata.ResponseTypesSupported) == 0 {
		return &ValidationError{Issuer: expectedIssuer, Field: "response_types_supported", Expected: "non-empty", Actual: "[]"}
	}
	if err := validateHTTPSURL(expectedIssuer, "authorization_endpoint", metadata.AuthorizationEndpoint, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "jwks_uri", metadata.JWKSURI, false); err != nil {
		return err
	}
	if err := validateHTTPSURL(expectedIssuer, "token_endpoint", metadata.TokenEndpoint, false); err != nil {
		return err
	}

	return nil
}
