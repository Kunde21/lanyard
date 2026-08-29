package metadata

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProviderClaimsUnknownFields(t *testing.T) {
	data, err := os.ReadFile("testdata/provider_metadata_fapi.json")
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	var provider Provider
	if err := json.Unmarshal(data, &provider); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if provider.PushedAuthorizationRequestEndpoint == "" {
		t.Fatalf("expected pushed_authorization_request_endpoint to be parsed")
	}
	if diff := cmp.Diff("https://mtls.fapi.example.com/token", provider.MTLSEndpointAliases.TokenEndpoint); diff != "" {
		t.Fatalf("MTLSEndpointAliases.TokenEndpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://mtls.fapi.example.com/par", provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("MTLSEndpointAliases.PushedAuthorizationRequestEndpoint mismatch (-want +got):\n%s", diff)
	}

	var custom struct {
		GrantManagementEndpoint  string   `json:"grant_management_endpoint"`
		TrustFrameworksSupported []string `json:"trust_frameworks_supported"`
	}
	if err := provider.Claims(&custom); err != nil {
		t.Fatalf("Claims() failed: %v", err)
	}

	if diff := cmp.Diff("https://fapi.example.com/grants", custom.GrantManagementEndpoint); diff != "" {
		t.Fatalf("GrantManagementEndpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"uk_open_banking"}, custom.TrustFrameworksSupported); diff != "" {
		t.Fatalf("TrustFrameworksSupported mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthorizationServerClaims(t *testing.T) {
	data, err := os.ReadFile("testdata/provider_metadata_minimal.json")
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	var server AuthorizationServer
	if err := json.Unmarshal(data, &server); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	var custom struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := server.Claims(&custom); err != nil {
		t.Fatalf("Claims() failed: %v", err)
	}

	if diff := cmp.Diff("https://server.example.com/token", custom.TokenEndpoint); diff != "" {
		t.Fatalf("TokenEndpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthorizationServer_DPoPFields(t *testing.T) {
	serverJSON := `{
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

	var server AuthorizationServer
	if err := json.Unmarshal([]byte(serverJSON), &server); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	want := []string{"PS256", "ES256"}
	if diff := cmp.Diff(want, server.DPoPSigningAlgValuesSupported); diff != "" {
		t.Fatalf("DPoPSigningAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if server.DPoPBoundAccessTokens == nil {
		t.Fatalf("expected DPoPBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(true, *server.DPoPBoundAccessTokens); diff != "" {
		t.Fatalf("DPoPBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
	if server.TLSClientCertificateBoundAccessTokens == nil {
		t.Fatalf("expected TLSClientCertificateBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(false, *server.TLSClientCertificateBoundAccessTokens); diff != "" {
		t.Fatalf("TLSClientCertificateBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthorizationServer_IntrospectionFields(t *testing.T) {
	serverJSON := `{
		"issuer": "https://issuer.test",
		"introspection_endpoint": "https://issuer.test/introspect",
		"introspection_endpoint_auth_methods_supported": ["private_key_jwt"],
		"introspection_endpoint_auth_signing_alg_values_supported": ["PS256"],
		"introspection_signing_alg_values_supported": ["PS256", "ES256"],
		"introspection_encryption_alg_values_supported": ["RSA-OAEP"],
		"introspection_encryption_enc_values_supported": ["A256GCM"],
		"mtls_endpoint_aliases": {
			"introspection_endpoint": "https://mtls.issuer.test/introspect"
		}
	}`

	var server AuthorizationServer
	if err := json.Unmarshal([]byte(serverJSON), &server); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if diff := cmp.Diff("https://issuer.test/introspect", server.IntrospectionEndpoint); diff != "" {
		t.Fatalf("IntrospectionEndpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"private_key_jwt"}, server.IntrospectionEndpointAuthMethodsSupported); diff != "" {
		t.Fatalf("IntrospectionEndpointAuthMethodsSupported mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"PS256"}, server.IntrospectionEndpointAuthSigningAlgValuesSupported); diff != "" {
		t.Fatalf("IntrospectionEndpointAuthSigningAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"PS256", "ES256"}, server.IntrospectionSigningAlgValuesSupported); diff != "" {
		t.Fatalf("IntrospectionSigningAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"RSA-OAEP"}, server.IntrospectionEncryptionAlgValuesSupported); diff != "" {
		t.Fatalf("IntrospectionEncryptionAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"A256GCM"}, server.IntrospectionEncryptionEncValuesSupported); diff != "" {
		t.Fatalf("IntrospectionEncryptionEncValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://mtls.issuer.test/introspect", server.MTLSEndpointAliases.IntrospectionEndpoint); diff != "" {
		t.Fatalf("MTLS IntrospectionEndpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestProvider_GrantManagementFields(t *testing.T) {
	serverJSON := `{
		"issuer": "https://issuer.test",
		"grant_management_endpoint": "https://issuer.test/grants",
		"grant_management_actions_supported": ["create", "query", "revoke", "merge", "replace"],
		"grant_management_action_required": true
	}`

	var server Provider
	if err := json.Unmarshal([]byte(serverJSON), &server); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if diff := cmp.Diff("https://issuer.test/grants", server.GrantManagementEndpoint); diff != "" {
		t.Fatalf("GrantManagementEndpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"create", "query", "revoke", "merge", "replace"}, server.GrantManagementActionsSupported); diff != "" {
		t.Fatalf("GrantManagementActionsSupported mismatch (-want +got):\n%s", diff)
	}
	if server.GrantManagementActionRequired == nil || !*server.GrantManagementActionRequired {
		t.Fatal("GrantManagementActionRequired = nil/false, want true")
	}

	encoded, err := json.Marshal(server)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}
	var roundTripped Provider
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("round-trip Unmarshal() failed: %v", err)
	}
	server.Raw = nil
	server.AuthorizationServer.Raw = nil
	roundTripped.Raw = nil
	roundTripped.AuthorizationServer.Raw = nil
	if diff := cmp.Diff(server, roundTripped); diff != "" {
		t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestProvider_GrantManagementFieldsOmitted(t *testing.T) {
	var server Provider
	if err := json.Unmarshal([]byte(`{"issuer":"https://issuer.test"}`), &server); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if server.GrantManagementEndpoint != "" {
		t.Fatalf("GrantManagementEndpoint = %q, want empty", server.GrantManagementEndpoint)
	}
	if len(server.GrantManagementActionsSupported) != 0 {
		t.Fatalf("GrantManagementActionsSupported = %v, want empty", server.GrantManagementActionsSupported)
	}
	if server.GrantManagementActionRequired != nil {
		t.Fatal("GrantManagementActionRequired = non-nil, want nil default (false per spec)")
	}
}

func TestProvider_DPoPFields(t *testing.T) {
	providerJSON := `{
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

	var provider Provider
	if err := json.Unmarshal([]byte(providerJSON), &provider); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	want := []string{"PS256", "ES256"}
	if diff := cmp.Diff(want, provider.DPoPSigningAlgValuesSupported); diff != "" {
		t.Fatalf("DPoPSigningAlgValuesSupported mismatch (-want +got):\n%s", diff)
	}
	if provider.DPoPBoundAccessTokens == nil {
		t.Fatalf("expected DPoPBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(true, *provider.DPoPBoundAccessTokens); diff != "" {
		t.Fatalf("DPoPBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
	if provider.TLSClientCertificateBoundAccessTokens == nil {
		t.Fatalf("expected TLSClientCertificateBoundAccessTokens to be set")
	}
	if diff := cmp.Diff(false, *provider.TLSClientCertificateBoundAccessTokens); diff != "" {
		t.Fatalf("TLSClientCertificateBoundAccessTokens mismatch (-want +got):\n%s", diff)
	}
}
