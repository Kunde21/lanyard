package main

import (
	"testing"
)

func TestConformancePublicJWKS_SelfSignedTlsClientAuth_ContainsX5C(t *testing.T) {
	jwks, err := conformancePublicJWKS("self_signed_tls_client_auth")
	if err != nil {
		t.Fatalf("conformancePublicJWKS() error: %v", err)
	}

	keys, ok := jwks["keys"].([]map[string]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	foundX5C := false
	for _, key := range keys {
		if x5c, ok := key["x5c"].([]string); ok && len(x5c) > 0 {
			foundX5C = true
			if key["kid"] != "client-mtls" {
				t.Errorf("x5c key kid = %q, want %q", key["kid"], "client-mtls")
			}
			if key["kty"] != "EC" {
				t.Errorf("x5c key kty = %q, want %q", key["kty"], "EC")
			}
			break
		}
	}
	if !foundX5C {
		t.Fatal("no JWK with x5c found for self_signed_tls_client_auth auth type")
	}
}

func TestConformancePublicJWKS_ClientSecretBasic_NoX5C(t *testing.T) {
	jwks, err := conformancePublicJWKS("client_secret_basic")
	if err != nil {
		t.Fatalf("conformancePublicJWKS() error: %v", err)
	}

	keys, ok := jwks["keys"].([]map[string]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	for _, key := range keys {
		if _, ok := key["x5c"]; ok {
			t.Fatal("x5c should not be present for client_secret_basic auth type")
		}
	}
}

func TestConformancePublicJWKS_EmptyAuthType_NoX5C(t *testing.T) {
	jwks, err := conformancePublicJWKS("")
	if err != nil {
		t.Fatalf("conformancePublicJWKS() error: %v", err)
	}

	keys, ok := jwks["keys"].([]map[string]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	for _, key := range keys {
		if _, ok := key["x5c"]; ok {
			t.Fatal("x5c should not be present for empty auth type")
		}
	}
}
