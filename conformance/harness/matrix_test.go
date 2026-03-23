package conformanceharness

import (
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
