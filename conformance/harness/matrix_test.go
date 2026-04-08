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

func TestMessageSigningMatrix_JAR4(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-ms-final-plain-fapi-jar4", "fapi2-message-signing-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 4 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 4", len(variants))
	}

	for _, v := range variants {
		if v.Variant["fapi_request_method"] != "signed_non_repudiation" {
			t.Errorf("variant %q: fapi_request_method = %q, want signed_non_repudiation", v.Name, v.Variant["fapi_request_method"])
		}
		if v.Variant["fapi_response_mode"] != "plain_response" {
			t.Errorf("variant %q: fapi_response_mode = %q, want plain_response", v.Name, v.Variant["fapi_response_mode"])
		}
		if v.RPProfile.FAPIRequestMethod != "signed_non_repudiation" {
			t.Errorf("variant %q: RPProfile.FAPIRequestMethod = %q, want signed_non_repudiation", v.Name, v.RPProfile.FAPIRequestMethod)
		}
	}
}

func TestMessageSigningMatrix_JARM4(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-ms-final-plain-fapi-jarm4", "fapi2-message-signing-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 4 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 4", len(variants))
	}

	for _, v := range variants {
		if v.Variant["fapi_request_method"] != "signed_non_repudiation" {
			t.Errorf("variant %q: fapi_request_method = %q, want signed_non_repudiation", v.Name, v.Variant["fapi_request_method"])
		}
		if v.Variant["fapi_response_mode"] != "jarm" {
			t.Errorf("variant %q: fapi_response_mode = %q, want jarm", v.Name, v.Variant["fapi_response_mode"])
		}
	}
}

func TestMessageSigningMatrix_All32(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-ms-final-plain-fapi-all32", "fapi2-message-signing-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 32 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 32", len(variants))
	}

	responseModeCounts := map[string]int{}
	for _, v := range variants {
		responseModeCounts[v.Variant["fapi_response_mode"]]++
		if v.Variant["fapi_request_method"] != "signed_non_repudiation" {
			t.Errorf("variant %q: fapi_request_method = %q, want signed_non_repudiation", v.Name, v.Variant["fapi_request_method"])
		}
	}

	if responseModeCounts["plain_response"] != 16 {
		t.Errorf("plain_response variants = %d, want 16", responseModeCounts["plain_response"])
	}
	if responseModeCounts["jarm"] != 16 {
		t.Errorf("jarm variants = %d, want 16", responseModeCounts["jarm"])
	}
}

func TestMessageSigningMatrix_IgnoresSecurityProfilePlan(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-ms-final-plain-fapi-jar4", "fapi2-security-profile-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 0 {
		t.Fatalf("expected 0 variants for message-signing matrix against security-profile plan, got %d", len(variants))
	}
}

func TestSecurityProfileMatrix_IgnoresMessageSigningPlan(t *testing.T) {
	variants, err := expandMatrixVariants("fapi2-sp-final-plain-fapi-first4", "fapi2-message-signing-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 0 {
		t.Fatalf("expected 0 variants for security-profile matrix against message-signing plan, got %d", len(variants))
	}
}

func TestFAPI1AdvancedMatrix_First4(t *testing.T) {
	variants, err := expandMatrixVariants("fapi1-adv-final-first4", "fapi1-advanced-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 4 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 4", len(variants))
	}
	for _, v := range variants {
		if v.Variant["sender_constrain"] != "mtls" {
			t.Errorf("variant %q: sender_constrain = %q, want mtls", v.Name, v.Variant["sender_constrain"])
		}
		if v.Variant["fapi_profile"] != "plain_fapi" {
			t.Errorf("variant %q: fapi_profile = %q, want plain_fapi", v.Name, v.Variant["fapi_profile"])
		}
		if v.Variant["fapi_request_method"] != "signed_non_repudiation" {
			t.Errorf("variant %q: fapi_request_method = %q, want signed_non_repudiation", v.Name, v.Variant["fapi_request_method"])
		}
		if v.RPProfile.FAPIRequestMethod != "signed_non_repudiation" {
			t.Errorf("variant %q: RPProfile.FAPIRequestMethod = %q, want signed_non_repudiation", v.Name, v.RPProfile.FAPIRequestMethod)
		}
	}
}

func TestFAPI1AdvancedMatrix_All12(t *testing.T) {
	variants, err := expandMatrixVariants("fapi1-adv-final-all12", "fapi1-advanced-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 12 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 12", len(variants))
	}
	authCounts := map[string]int{}
	reqMethodCounts := map[string]int{}
	clientTypeCounts := map[string]int{}
	responseModeCounts := map[string]int{}
	seen := map[string]bool{}
	for _, variant := range variants {
		v := variant.Variant
		authCounts[v["client_auth_type"]]++
		reqMethodCounts[v["fapi_auth_request_method"]]++
		clientTypeCounts[v["fapi_client_type"]]++
		responseModeCounts[v["fapi_response_mode"]]++
		if v["fapi_profile"] != "plain_fapi" {
			t.Fatalf("fapi_profile = %q, want plain_fapi", v["fapi_profile"])
		}
		if v["sender_constrain"] != "mtls" {
			t.Fatalf("sender_constrain = %q, want mtls", v["sender_constrain"])
		}
		if v["fapi_request_method"] != "signed_non_repudiation" {
			t.Fatalf("fapi_request_method = %q, want signed_non_repudiation", v["fapi_request_method"])
		}
		if variant.RPProfile.FAPIRequestMethod != "signed_non_repudiation" {
			t.Fatalf("RPProfile.FAPIRequestMethod = %q, want signed_non_repudiation", variant.RPProfile.FAPIRequestMethod)
		}
		if v["fapi_client_type"] == "plain_oauth" && v["fapi_response_mode"] == "plain_response" {
			t.Fatalf("invalid combination: plain_oauth with plain_response is rejected by conformance suite")
		}
		key := strings.Join([]string{
			v["client_auth_type"],
			v["fapi_auth_request_method"],
			v["fapi_client_type"],
			v["fapi_response_mode"],
		}, "|")
		seen[key] = true
	}
	if diff := cmp.Diff(map[string]int{"private_key_jwt": 6, "mtls": 6}, authCounts); diff != "" {
		t.Fatalf("client_auth_type distribution mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]int{"by_value": 6, "pushed": 6}, reqMethodCounts); diff != "" {
		t.Fatalf("fapi_auth_request_method distribution mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]int{"oidc": 8, "plain_oauth": 4}, clientTypeCounts); diff != "" {
		t.Fatalf("fapi_client_type distribution mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]int{"plain_response": 4, "jarm": 8}, responseModeCounts); diff != "" {
		t.Fatalf("fapi_response_mode distribution mismatch (-want +got):\n%s", diff)
	}
	if len(seen) != 12 {
		t.Fatalf("unique 4D combinations = %d, want 12", len(seen))
	}
}

func TestFAPI1AdvancedMatrix_IgnoresOtherPlans(t *testing.T) {
	variants, err := expandMatrixVariants("fapi1-adv-final-first4", "fapi2-security-profile-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 0 {
		t.Fatalf("expected 0 variants for mismatched plan, got %d", len(variants))
	}
}

func TestOtherMatrices_IgnoreFAPI1AdvancedPlan(t *testing.T) {
	testCases := []string{
		"fapi2-sp-final-plain-fapi-first4",
		"fapi2-ms-final-plain-fapi-jar4",
	}
	for _, matrixName := range testCases {
		variants, err := expandMatrixVariants(matrixName, "fapi1-advanced-final-client-test-plan")
		if err != nil {
			t.Fatalf("expandMatrixVariants(%q) failed: %v", matrixName, err)
		}
		if len(variants) != 0 {
			t.Fatalf("expandMatrixVariants(%q) returned %d variants, want 0", matrixName, len(variants))
		}
	}
}
