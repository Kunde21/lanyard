package oidc

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProviderMetadataClaimsUnknownFields(t *testing.T) {
	data, err := os.ReadFile("testdata/provider_metadata_fapi.json")
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	var metadata ProviderMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if metadata.PushedAuthorizationRequestEndpoint == "" {
		t.Fatalf("expected pushed_authorization_request_endpoint to be parsed")
	}

	var custom struct {
		GrantManagementEndpoint  string   `json:"grant_management_endpoint"`
		TrustFrameworksSupported []string `json:"trust_frameworks_supported"`
	}
	if err := metadata.Claims(&custom); err != nil {
		t.Fatalf("Claims() failed: %v", err)
	}

	if diff := cmp.Diff("https://fapi.example.com/grants", custom.GrantManagementEndpoint); diff != "" {
		t.Fatalf("GrantManagementEndpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"uk_open_banking"}, custom.TrustFrameworksSupported); diff != "" {
		t.Fatalf("TrustFrameworksSupported mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthorizationServerMetadataClaims(t *testing.T) {
	data, err := os.ReadFile("testdata/provider_metadata_minimal.json")
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	var metadata AuthorizationServerMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	var custom struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := metadata.Claims(&custom); err != nil {
		t.Fatalf("Claims() failed: %v", err)
	}

	if diff := cmp.Diff("https://server.example.com/token", custom.TokenEndpoint); diff != "" {
		t.Fatalf("TokenEndpoint mismatch (-want +got):\n%s", diff)
	}
}
