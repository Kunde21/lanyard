package oidc

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

func TestValidateProviderMetadataRequiredFields(t *testing.T) {
	c := NewClient()
	_, err := validateIssuerURL("https://issuer.example.com")
	if err != nil {
		t.Fatalf("validateIssuerURL() failed: %v", err)
	}

	meta := ProviderMetadata{
		AuthorizationServerMetadata: AuthorizationServerMetadata{Issuer: "https://issuer.example.com"},
	}
	err = c.validateProviderMetadata("https://issuer.example.com", meta)
	if err == nil {
		t.Fatalf("validateProviderMetadata() expected error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
}
