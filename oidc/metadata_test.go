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
	if diff := cmp.Diff("https://mtls.fapi.example.com/token", metadata.MTLSEndpointAliases.TokenEndpoint); diff != "" {
		t.Fatalf("MTLSEndpointAliases.TokenEndpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://mtls.fapi.example.com/par", metadata.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("MTLSEndpointAliases.PushedAuthorizationRequestEndpoint mismatch (-want +got):\n%s", diff)
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

func TestAuthorizationServerMetadata_DPoPFields(t *testing.T) {
	metadataJSON := `{
		"issuer": "https://issuer.test",
		"authorization_endpoint": "https://issuer.test/authorize",
		"jwks_uri": "https://issuer.test/jwks",
		"response_types_supported": ["code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256"],
		"dpop_signing_alg_values_supported": ["PS256", "ES256"],
		"dpop_bound_access_tokens": true,
		"tls_client_certificate_bound_access_tokens": false
	}`

	var metadata AuthorizationServerMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	want := []string{"PS256", "ES256"}
	if diff := cmp.Diff(want, metadata.DPoPSigningAlgValuesSupported); diff != "" {
		t.Fatalf("DPoPSigningAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if metadata.DPoPBoundAccessTokens == nil {
		t.Fatalf("expected DPoPBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(true, *metadata.DPoPBoundAccessTokens); diff != "" {
		t.Fatalf("DPoPBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
	if metadata.TLSClientCertificateBoundAccessTokens == nil {
		t.Fatalf("expected TLSClientCertificateBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(false, *metadata.TLSClientCertificateBoundAccessTokens); diff != "" {
		t.Fatalf("TLSClientCertificateBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
}

func TestProviderMetadata_DPoPFields(t *testing.T) {
	metadataJSON := `{
		"issuer": "https://issuer.test",
		"authorization_endpoint": "https://issuer.test/authorize",
		"jwks_uri": "https://issuer.test/jwks",
		"response_types_supported": ["code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256"],
		"dpop_signing_alg_values_supported": ["PS256", "ES256"],
		"dpop_bound_access_tokens": true,
		"tls_client_certificate_bound_access_tokens": false
	}`

	var metadata ProviderMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	want := []string{"PS256", "ES256"}
	if diff := cmp.Diff(want, metadata.DPoPSigningAlgValuesSupported); diff != "" {
		t.Fatalf("DPoPSigningAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if metadata.DPoPBoundAccessTokens == nil {
		t.Fatalf("expected DPoPBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(true, *metadata.DPoPBoundAccessTokens); diff != "" {
		t.Fatalf("DPoPBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
	if metadata.TLSClientCertificateBoundAccessTokens == nil {
		t.Fatalf("expected TLSClientCertificateBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(false, *metadata.TLSClientCertificateBoundAccessTokens); diff != "" {
		t.Fatalf("TLSClientCertificateBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
}
