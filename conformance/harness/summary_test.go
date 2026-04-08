package conformanceharness

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestPrintSummary_AllPassed(t *testing.T) {
	now := time.Now().UTC()
	doc := reportDocument{
		RunID:    "20260408-125803",
		GitSHA:   "2b41faa910a54b8b6bacfa066dc5eba2acbf6385",
		Profile:  "all-rp",
		Matrices: []string{"fapi2-sp-final-plain-fapi-all16"},
		Failed:   false,
		Plans: []planResult{
			{
				PlanName:   "oidcc-client-basic-certification-test-plan",
				StartedAt:  now.Add(-5 * time.Minute),
				FinishedAt: now.Add(-4 * time.Minute),
				Tests: []testResult{
					{Result: "PASSED", Status: "FINISHED"},
					{Result: "PASSED", Status: "FINISHED"},
				},
			},
			{
				PlanName:   "fapi2-security-profile-final-client-test-plan",
				StartedAt:  now.Add(-4 * time.Minute),
				FinishedAt: now,
				Tests: []testResult{
					{Result: "PASSED", Status: "FINISHED"},
				},
			},
		},
	}

	var buf bytes.Buffer
	printSummary(&buf, doc)
	output := buf.String()

	if !strings.Contains(output, "ALL PASSED") {
		t.Errorf("expected 'ALL PASSED' in summary output, got:\n%s", output)
	}
	if !strings.Contains(output, "OIDCC Client Basic") {
		t.Errorf("expected 'OIDCC Client Basic' in summary output, got:\n%s", output)
	}
	if !strings.Contains(output, "FAPI2 Security Profile Final") {
		t.Errorf("expected 'FAPI2 Security Profile Final' in summary output, got:\n%s", output)
	}
	if !strings.Contains(output, "fapi2-sp-final-plain-fapi-all16") {
		t.Errorf("expected matrix name in summary output, got:\n%s", output)
	}
	if !strings.Contains(output, "2b41faa9") {
		t.Errorf("expected short git SHA in summary output, got:\n%s", output)
	}
}

func TestPrintSummary_WithFailures(t *testing.T) {
	now := time.Now().UTC()
	doc := reportDocument{
		RunID:         "20260408-125803",
		Profile:       "oidc-rp",
		Failed:        true,
		FailureReason: "one or more plans failed",
		Plans: []planResult{
			{
				PlanName:   "oidcc-client-basic-certification-test-plan",
				StartedAt:  now.Add(-2 * time.Minute),
				FinishedAt: now,
				Tests: []testResult{
					{Result: "PASSED", Status: "FINISHED"},
					{Result: "FAILED", Status: "FINISHED"},
				},
			},
		},
	}

	var buf bytes.Buffer
	printSummary(&buf, doc)
	output := buf.String()

	if !strings.Contains(output, "FAILED") {
		t.Errorf("expected 'FAILED' in summary output, got:\n%s", output)
	}
	if !strings.Contains(output, "one or more plans failed") {
		t.Errorf("expected failure reason in summary output, got:\n%s", output)
	}
}

func TestAggregateCounts(t *testing.T) {
	plans := []planResult{
		{Tests: []testResult{
			{Result: "PASSED", Status: "FINISHED"},
			{Result: "FAILED", Status: "FINISHED"},
		}},
		{Tests: []testResult{
			{Result: "PASSED", Status: "FINISHED"},
			{Result: "SKIPPED", Status: "FINISHED"},
			{Result: "UNKNOWN", Status: "ERROR"},
		}},
	}

	got := aggregateCounts(plans)
	want := summaryCounts{Plans: 2, Tests: 5, Passed: 2, Failed: 1, Skipped: 1, Errored: 1}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("aggregateCounts() mismatch (-want +got):\n%s", diff)
	}
}

func TestDisplayName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"oidcc-client-basic-certification-test-plan", "OIDCC Client Basic"},
		{"oidcc-client-formpost-basic-certification-test-plan", "OIDCC Client Formpost Basic"},
		{"fapi1-advanced-final-client-test-plan", "FAPI1 Advanced Final"},
		{"fapi2-message-signing-final-client-test-plan", "FAPI2 Message Signing Final"},
		{"fapi2-security-profile-final-client-test-plan", "FAPI2 Security Profile Final"},
		{"some-unknown-plan", "some-unknown-plan"},
	}

	for _, tc := range tests {
		got := displayName(tc.input)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("displayName(%q) mismatch (-want +got):\n%s", tc.input, diff)
		}
	}
}
