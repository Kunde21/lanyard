package metadata

import (
	"errors"
	"testing"
)

func TestIssuerMatchesTrailingSlashTolerance(t *testing.T) {
	if issuerMatches("https://example.com", "https://example.com/", false) {
		t.Fatalf("issuer should not match without tolerance")
	}
	if !issuerMatches("https://example.com", "https://example.com/", true) {
		t.Fatalf("issuer should match with tolerance")
	}
}

func TestValidateProviderRequiredFields(t *testing.T) {
	c := NewClient()
	_, err := validateIssuerURL("https://issuer.example.com")
	if err != nil {
		t.Fatalf("validateIssuerURL() failed: %v", err)
	}

	provider := Provider{
		AuthorizationServer: AuthorizationServer{Issuer: "https://issuer.example.com"},
	}
	err = c.validateProvider("https://issuer.example.com", provider)
	if err == nil {
		t.Fatalf("validateProvider() expected error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
}
