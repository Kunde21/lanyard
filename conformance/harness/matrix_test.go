package conformanceharness

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPlainFAPIMatrix_FirstFour(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-sp-final-plain-fapi-first4", "fapi2-security-profile-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 4 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 4", len(variants))
	}

	want := []map[string]string{
		{"client_auth_type": "private_key_jwt", "sender_constrain": "mtls", "authorization_request_type": "simple", "fapi_client_type": "oidc", "fapi_profile": "plain_fapi"},
		{"client_auth_type": "private_key_jwt", "sender_constrain": "dpop", "authorization_request_type": "simple", "fapi_client_type": "oidc", "fapi_profile": "plain_fapi"},
		{"client_auth_type": "mtls", "sender_constrain": "mtls", "authorization_request_type": "simple", "fapi_client_type": "oidc", "fapi_profile": "plain_fapi"},
		{"client_auth_type": "mtls", "sender_constrain": "dpop", "authorization_request_type": "simple", "fapi_client_type": "oidc", "fapi_profile": "plain_fapi"},
	}
	got := make([]map[string]string, 0, len(variants))
	for _, variant := range variants {
		got = append(got, variant.Variant)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("plain fapi first four mismatch (-want +got):\n%s", diff)
	}
}

func TestBuildRPRuntimeRequest_UsesDistinctAliasAndProfileValues(t *testing.T) {
	job := RunJob{
		JobID:    "job-001",
		Alias:    "alias-a",
		PlanName: "fapi2-security-profile-final-client-test-plan",
	}
	variant := map[string]string{
		"client_auth_type":           "private_key_jwt",
		"sender_constrain":           "dpop",
		"authorization_request_type": "simple",
		"fapi_client_type":           "oidc",
		"fapi_profile":               "plain_fapi",
	}
	req := buildRPRuntimeRequest(job, variant, "https://suite.localhost")
	if req.Alias != job.Alias {
		t.Fatalf("Alias = %q, want %q", req.Alias, job.Alias)
	}
	if req.ClientAuthType != "private_key_jwt" || req.SenderConstrain != "dpop" || req.FAPIProfile != "plain_fapi" {
		t.Fatalf("unexpected runtime request: %#v", req)
	}
	if req.RedirectURI != "https://rp.localhost/callback/alias-a" {
		t.Fatalf("RedirectURI = %q, want alias-specific callback", req.RedirectURI)
	}
}

func TestBuildPlanConfig_FAPI2IncludesStaticClientConfigWithoutRegistrationVariant(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type": "private_key_jwt",
		"fapi_profile":     "plain_fapi",
	}, "alias-a", 5)
	if got := cfg["alias"]; got != "alias-a" {
		t.Fatalf("alias = %#v, want %q", got, "alias-a")
	}
	server, ok := cfg["server"].(map[string]any)
	if !ok || len(server) == 0 {
		t.Fatalf("server jwks config missing: %#v", cfg["server"])
	}
	if _, ok := server["jwks"]; !ok {
		t.Fatalf("server jwks field missing: %#v", server)
	}
	client, ok := cfg["client"].(map[string]any)
	if !ok || client["redirect_uri"] != "https://rp.localhost/callback/alias-a" {
		t.Fatalf("client config mismatch: %#v", cfg["client"])
	}
	if got := cfg["waitTimeoutSeconds"]; got != 5 {
		t.Fatalf("waitTimeoutSeconds = %#v, want 5", got)
	}
}

func TestPlainFAPIMatrix_All16(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-sp-final-plain-fapi-all16", "fapi2-security-profile-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 16 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 16", len(variants))
	}

	got := make([]string, 0, len(variants))
	for _, variant := range variants {
		got = append(got, strings.Join([]string{
			variant.Variant["client_auth_type"],
			variant.Variant["sender_constrain"],
			variant.Variant["authorization_request_type"],
			variant.Variant["fapi_client_type"],
			variant.Variant["fapi_profile"],
		}, "|"))
	}

	want := []string{
		"private_key_jwt|mtls|simple|oidc|plain_fapi",
		"private_key_jwt|mtls|simple|plain_oauth|plain_fapi",
		"private_key_jwt|mtls|rar|oidc|plain_fapi",
		"private_key_jwt|mtls|rar|plain_oauth|plain_fapi",
		"private_key_jwt|dpop|simple|oidc|plain_fapi",
		"private_key_jwt|dpop|simple|plain_oauth|plain_fapi",
		"private_key_jwt|dpop|rar|oidc|plain_fapi",
		"private_key_jwt|dpop|rar|plain_oauth|plain_fapi",
		"mtls|mtls|simple|oidc|plain_fapi",
		"mtls|mtls|simple|plain_oauth|plain_fapi",
		"mtls|mtls|rar|oidc|plain_fapi",
		"mtls|mtls|rar|plain_oauth|plain_fapi",
		"mtls|dpop|simple|oidc|plain_fapi",
		"mtls|dpop|simple|plain_oauth|plain_fapi",
		"mtls|dpop|rar|oidc|plain_fapi",
		"mtls|dpop|rar|plain_oauth|plain_fapi",
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("plain fapi all16 mismatch (-want +got):\n%s", diff)
	}
}
