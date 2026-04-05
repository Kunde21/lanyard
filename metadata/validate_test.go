package metadata

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIssuerMatchesTrailingSlashTolerance(t *testing.T) {
	if issuerMatches("https://example.com", "https://example.com/", false) {
		t.Fatalf("issuer should not match without tolerance")
	}
	if !issuerMatches("https://example.com", "https://example.com/", true) {
		t.Fatalf("issuer should match with tolerance")
	}
}

func TestValidateRequired(t *testing.T) {
	err := validateRequired("https://issuer.example.com", "some_field", "value")
	if err != nil {
		t.Fatalf("validateRequired() unexpected error: %v", err)
	}

	err = validateRequired("https://issuer.example.com", "some_field", "")
	if err == nil {
		t.Fatalf("validateRequired() expected error for empty value")
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	want := &ValidationError{Issuer: "https://issuer.example.com", Field: "some_field", Expected: "non-empty", Actual: ""}
	if diff := cmp.Diff(want, ve); diff != "" {
		t.Errorf("validateRequired() mismatch (-want +got):\n%s", diff)
	}
}

func TestValidateRequiredSlice(t *testing.T) {
	err := validateRequiredSlice("https://issuer.example.com", "some_field", []string{"code"})
	if err != nil {
		t.Fatalf("validateRequiredSlice() unexpected error: %v", err)
	}

	err = validateRequiredSlice("https://issuer.example.com", "some_field", []string{})
	if err == nil {
		t.Fatalf("validateRequiredSlice() expected error for empty slice")
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	want := &ValidationError{Issuer: "https://issuer.example.com", Field: "some_field", Expected: "non-empty", Actual: "[]"}
	if diff := cmp.Diff(want, ve); diff != "" {
		t.Errorf("validateRequiredSlice() mismatch (-want +got):\n%s", diff)
	}

	err = validateRequiredSlice("https://issuer.example.com", "some_field", nil)
	if err == nil {
		t.Fatalf("validateRequiredSlice() expected error for nil slice")
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
