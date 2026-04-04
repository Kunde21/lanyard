package conformanceharness

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSelectPlans_ProfileExpansion(t *testing.T) {
	available := []AvailablePlan{
		{Name: "oidcc-client-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "oidcc-client-test-plan", Profile: "oidcc"},
		{Name: "oidcc-client-implicit-certification-test-plan", Profile: "oidc-rp"},
		{Name: "oidcc-client-formpost-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "fapi2-security-profile-id2-client-test-plan", Profile: "fapi2-rp"},
		{Name: "fapi2-message-signing-id1-client-test-plan", Profile: "fapi2-rp"},
		{Name: "fapi2-security-profile-final-client-test-plan", Profile: "Test a Relying Party / OAuth2 Client"},
		{Name: "fapi2-security-profile-final-client-credentials-grant-test-plan", Profile: "Test an OpenID Provider / Authorization Server"},
		{Name: "openid-provider-config-test-plan", Profile: "op"},
	}

	tests := []struct {
		name    string
		profile string
		want    []string
	}{
		{
			name:    "oidc rp profile",
			profile: "oidc-rp",
			want: []string{
				"oidcc-client-basic-certification-test-plan",
				"oidcc-client-formpost-basic-certification-test-plan",
			},
		},
		{
			name:    "fapi rp profile",
			profile: "fapi-rp",
			want: []string{
				"fapi2-message-signing-id1-client-test-plan",
				"fapi2-security-profile-final-client-test-plan",
				"fapi2-security-profile-id2-client-test-plan",
			},
		},
		{
			name:    "all rp profile",
			profile: "all-rp",
			want: []string{
				"fapi2-message-signing-id1-client-test-plan",
				"fapi2-security-profile-final-client-test-plan",
				"fapi2-security-profile-id2-client-test-plan",
				"oidcc-client-basic-certification-test-plan",
				"oidcc-client-formpost-basic-certification-test-plan",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := harnessConfig{Profile: tc.profile}
			plans, err := selectPlans(cfg, available)
			if err != nil {
				t.Fatalf("selectPlans() failed: %v", err)
			}

			got := make([]string, 0, len(plans))
			for _, p := range plans {
				got = append(got, p.Name)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("plan selection mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSelectPlans_Filters(t *testing.T) {
	available := []AvailablePlan{
		{Name: "oidcc-client-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "oidcc-client-test-plan", Profile: "oidcc"},
	}

	includeRE := regexp.MustCompile(`basic`)
	excludeRE := regexp.MustCompile(`implicit`)

	cfg := harnessConfig{
		Profile:          "oidc-rp",
		IncludePlanRegex: includeRE,
		ExcludePlanRegex: excludeRE,
	}

	plans, err := selectPlans(cfg, available)
	if err != nil {
		t.Fatalf("selectPlans() failed: %v", err)
	}

	got := []string{plans[0].Name}
	want := []string{"oidcc-client-basic-certification-test-plan"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("filtered plans mismatch (-want +got):\n%s", diff)
	}
}

func TestSelectPlans_FormPostFilter(t *testing.T) {
	available := []AvailablePlan{
		{Name: "oidcc-client-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "oidcc-client-formpost-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "oidcc-client-implicit-certification-test-plan", Profile: "oidc-rp"},
	}

	includeRE := regexp.MustCompile(`formpost-basic`)

	cfg := harnessConfig{
		Profile:          "oidc-rp",
		IncludePlanRegex: includeRE,
	}

	plans, err := selectPlans(cfg, available)
	if err != nil {
		t.Fatalf("selectPlans() failed: %v", err)
	}

	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if plans[0].Name != "oidcc-client-formpost-basic-certification-test-plan" {
		t.Fatalf("plan name = %q, want formpost plan", plans[0].Name)
	}
}
