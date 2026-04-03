package conformanceharness

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExpandRunJobs_DefaultSelectionProducesOneJobPerPlan(t *testing.T) {
	plans := []AvailablePlan{
		{Name: "oidcc-client-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "fapi2-security-profile-final-client-test-plan", Profile: "fapi-rp"},
	}

	cfg := harnessConfig{Profile: "all-rp"}

	got := expandRunJobs("run-001", cfg, plans)
	if len(got) != 2 {
		t.Fatalf("expandRunJobs() returned %d jobs, want 2", len(got))
	}

	if diff := cmp.Diff([]string{
		"oidcc-client-basic-certification-test-plan",
		"fapi2-security-profile-final-client-test-plan",
	}, []string{got[0].PlanName, got[1].PlanName}); diff != "" {
		t.Fatalf("job plan names mismatch (-want +got):\n%s", diff)
	}

	for _, job := range got {
		if job.JobID == "" {
			t.Fatalf("job for %s missing JobID", job.PlanName)
		}
		if job.Alias == "" {
			t.Fatalf("job for %s missing Alias", job.PlanName)
		}
	}
}

func TestExpandRunJobs_PlainFAPIMatrixProducesDistinctJobs(t *testing.T) {
	plans := []AvailablePlan{{
		Name:    "fapi2-security-profile-final-client-test-plan",
		Profile: "fapi-rp",
	}}

	cfg := harnessConfig{
		Profile: "fapi-rp",
		Matrix:  "fapi2-sp-final-plain-fapi-first4",
	}

	got := expandRunJobs("run-plain-fapi", cfg, plans)
	if len(got) != 4 {
		t.Fatalf("expandRunJobs() returned %d jobs, want 4", len(got))
	}

	seenJobIDs := map[string]struct{}{}
	seenAliases := map[string]struct{}{}
	for _, job := range got {
		if _, ok := seenJobIDs[job.JobID]; ok {
			t.Fatalf("duplicate JobID %q", job.JobID)
		}
		seenJobIDs[job.JobID] = struct{}{}

		if _, ok := seenAliases[job.Alias]; ok {
			t.Fatalf("duplicate Alias %q", job.Alias)
		}
		seenAliases[job.Alias] = struct{}{}
	}
}

func TestExpandRunJobs_PlainFAPIAll16ProducesDistinctJobs(t *testing.T) {
	plans := []AvailablePlan{{
		Name:    "fapi2-security-profile-final-client-test-plan",
		Profile: "fapi-rp",
	}}

	cfg := harnessConfig{
		Profile: "fapi-rp",
		Matrix:  "fapi2-sp-final-plain-fapi-all16",
	}

	got := expandRunJobs("run-plain-fapi-all16", cfg, plans)
	if len(got) != 16 {
		t.Fatalf("expandRunJobs() returned %d jobs, want 16", len(got))
	}

	seenJobIDs := map[string]struct{}{}
	seenAliases := map[string]struct{}{}
	seenCases := map[string]struct{}{}
	for _, job := range got {
		if _, ok := seenJobIDs[job.JobID]; ok {
			t.Fatalf("duplicate JobID %q", job.JobID)
		}
		seenJobIDs[job.JobID] = struct{}{}

		if _, ok := seenAliases[job.Alias]; ok {
			t.Fatalf("duplicate Alias %q", job.Alias)
		}
		seenAliases[job.Alias] = struct{}{}

		if _, ok := seenCases[job.MatrixCase]; ok {
			t.Fatalf("duplicate MatrixCase %q", job.MatrixCase)
		}
		seenCases[job.MatrixCase] = struct{}{}
	}
}
