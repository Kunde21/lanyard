package conformanceharness

import (
	"bytes"
	"fmt"
	"strings"
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
		Profile:  "fapi-rp",
		Matrices: []string{"fapi2-sp-final-plain-fapi-first4"},
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
		Profile:  "fapi-rp",
		Matrices: []string{"fapi2-sp-final-plain-fapi-all16"},
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

func TestExpandRunJobs_OverlappingMatricesDeduplicate(t *testing.T) {
	plans := []AvailablePlan{{
		Name:    "fapi2-security-profile-final-client-test-plan",
		Profile: "fapi-rp",
	}}

	cfg := harnessConfig{
		Profile:  "fapi-rp",
		Matrices: []string{"fapi2-sp-final-plain-fapi-all16", "fapi2-sp-final-plain-fapi-first4"},
	}

	got := expandRunJobs("run-overlap", cfg, plans)

	if len(got) != 16 {
		t.Fatalf("total jobs = %d, want 16 (first4 are subset of all16, so deduped to all16)", len(got))
	}

	seenKeys := map[string]struct{}{}
	for _, job := range got {
		key := variantKey(job.PlanName, job.PlanVariant)
		if _, ok := seenKeys[key]; ok {
			t.Errorf("duplicate variant: job=%s variant=%v", job.JobID, job.PlanVariant)
		}
		seenKeys[key] = struct{}{}
	}
}

func TestExpandRunJobs_MultipleMatricesExpandDifferentPlans(t *testing.T) {
	plans := []AvailablePlan{
		{Name: "oidcc-client-basic-certification-test-plan", Profile: "oidc-rp"},
		{Name: "fapi2-security-profile-final-client-test-plan", Profile: "fapi-rp"},
		{Name: "fapi2-message-signing-final-client-test-plan", Profile: "fapi-rp"},
	}

	cfg := harnessConfig{
		Profile:  "all-rp",
		Matrices: []string{"fapi2-sp-final-plain-fapi-first4", "fapi2-ms-final-plain-fapi-jar4"},
	}

	got := expandRunJobs("run-multi", cfg, plans)

	oidcJobs := 0
	spJobs := 0
	msJobs := 0
	for _, job := range got {
		switch {
		case strings.Contains(job.PlanName, "oidcc-client-basic"):
			oidcJobs++
		case strings.Contains(job.PlanName, "security-profile"):
			spJobs++
		case strings.Contains(job.PlanName, "message-signing"):
			msJobs++
		}
	}

	if oidcJobs != 1 {
		t.Errorf("OIDC jobs = %d, want 1", oidcJobs)
	}
	if spJobs != 4 {
		t.Errorf("SP jobs = %d, want 4", spJobs)
	}
	if msJobs != 4 {
		t.Errorf("MS jobs = %d, want 4", msJobs)
	}
	if len(got) != 9 {
		t.Fatalf("total jobs = %d, want 9 (1 OIDC + 4 SP + 4 MS)", len(got))
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

func TestPrintDryRunMatrix(t *testing.T) {
	jobs := []RunJob{
		{
			JobID:       "job-001",
			PlanName:    "oidcc-client-basic-certification-test-plan",
			MatrixCase:  "",
			PlanVariant: nil,
		},
		{
			JobID:      "job-002",
			PlanName:   "fapi2-security-profile-final-client-test-plan",
			MatrixCase: "plain-fapi-01",
			PlanVariant: map[string]string{
				"client_auth_type": "private_key_jwt",
				"sender_constrain": "mtls",
			},
		},
	}

	var buf bytes.Buffer
	printDryRunMatrix(func(format string, args ...any) {
		fmt.Fprintf(&buf, format+"\n", args...)
	}, jobs)

	got := buf.String()
	if !strings.Contains(got, "2 job") {
		t.Errorf("expected summary line with job count, got:\n%s", got)
	}
	if !strings.Contains(got, "job-001") {
		t.Errorf("expected job-001 in output, got:\n%s", got)
	}
	if !strings.Contains(got, "job-002") {
		t.Errorf("expected job-002 in output, got:\n%s", got)
	}
	if !strings.Contains(got, "plain-fapi-01") {
		t.Errorf("expected matrix case in output, got:\n%s", got)
	}
	if !strings.Contains(got, "client_auth_type=private_key_jwt") {
		t.Errorf("expected variant key=value in output, got:\n%s", got)
	}
}

func TestPrintDryRunMatrixEmpty(t *testing.T) {
	var buf bytes.Buffer
	printDryRunMatrix(func(format string, args ...any) {
		fmt.Fprintf(&buf, format+"\n", args...)
	}, nil)

	got := buf.String()
	if !strings.Contains(got, "0 job") {
		t.Errorf("expected 0 jobs summary, got:\n%s", got)
	}
}
