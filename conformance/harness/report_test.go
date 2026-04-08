package conformanceharness

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestWriteReport_RedactsSensitiveFields(t *testing.T) {
	tempDir := t.TempDir()
	cfg := harnessConfig{
		SuiteURL:          "https://suite.localhost",
		Profile:           "oidc-rp",
		ArtifactsDir:      tempDir,
		ExportZip:         false,
		Redact:            true,
		SelectedPlanNames: []string{"oidcc-client-basic-certification-test-plan"},
	}

	run := runReport{
		RunID:         "20260223-010203",
		StartedAt:     time.Now().UTC().Add(-time.Minute),
		FinishedAt:    time.Now().UTC(),
		Failed:        true,
		FailureReason: "token=abc123 client_secret=shh",
		Plans: []planResult{{
			PlanName:      "oidcc-client-basic-certification-test-plan",
			PlanID:        "plan-1",
			StartedAt:     time.Now().UTC().Add(-time.Minute),
			FinishedAt:    time.Now().UTC(),
			Duration:      "1m0s",
			Failed:        true,
			FailureReason: "client_secret=topsecret",
			Tests: []testResult{{
				ModuleName: "module-a",
				TestID:     "test-1",
				Status:     "FINISHED",
				Result:     "FAILED",
				Summary:    "token=secret-value",
			}},
		}},
	}

	reportPath, _, err := writeReport(context.Background(), cfg, run)
	if err != nil {
		t.Fatalf("writeReport() failed: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile(report) failed: %v", err)
	}

	if strings.Contains(string(data), "abc123") || strings.Contains(string(data), "topsecret") {
		t.Fatalf("report contains unredacted secret data: %s", data)
	}

	var doc reportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("json.Unmarshal(report) failed: %v", err)
	}

	wantPlanNames := []string{"oidcc-client-basic-certification-test-plan"}
	if diff := cmp.Diff(wantPlanNames, doc.SelectedPlans); diff != "" {
		t.Fatalf("selected plans mismatch (-want +got):\n%s", diff)
	}
}

func TestSanitizePathComponent(t *testing.T) {
	got := sanitizePathComponent("oidc plan/with spaces")
	want := "oidc-plan-with-spaces"
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("sanitizePathComponent() mismatch (-want +got):\n%s", diff)
	}
}

func TestWriteReport_CreatesRunReportPath(t *testing.T) {
	tempDir := t.TempDir()
	cfg := harnessConfig{
		SuiteURL:          "https://suite.localhost",
		Profile:           "oidc-rp",
		ArtifactsDir:      tempDir,
		ExportZip:         false,
		Redact:            false,
		SelectedPlanNames: []string{"plan-a"},
	}

	run := runReport{
		RunID:      "20260223-040506",
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Plans:      []planResult{},
	}

	reportPath, _, err := writeReport(context.Background(), cfg, run)
	if err != nil {
		t.Fatalf("writeReport() failed: %v", err)
	}

	want := filepath.Join(tempDir, run.RunID, "report.json")
	if diff := cmp.Diff(want, reportPath); diff != "" {
		t.Fatalf("report path mismatch (-want +got):\n%s", diff)
	}
}

func TestWriteReport_IncludesJobIdentityFields(t *testing.T) {
	tempDir := t.TempDir()
	cfg := harnessConfig{
		SuiteURL:          "https://suite.localhost",
		Profile:           "fapi-rp",
		ArtifactsDir:      tempDir,
		ExportZip:         false,
		Redact:            false,
		SelectedPlanNames: []string{"fapi2-security-profile-final-client-test-plan"},
	}

	run := runReport{
		RunID:      "20260323-111213",
		StartedAt:  time.Now().UTC().Add(-time.Minute),
		FinishedAt: time.Now().UTC(),
		Plans: []planResult{{
			PlanName:   "fapi2-security-profile-final-client-test-plan",
			PlanID:     "plan-1",
			StartedAt:  time.Now().UTC().Add(-time.Minute),
			FinishedAt: time.Now().UTC(),
			Duration:   "1m0s",
			Tests: []testResult{{
				ModuleName: "module-a",
				TestID:     "test-1",
				Status:     "FINISHED",
				Result:     "PASSED",
				Alias:      "alias-a",
			}},
		}},
	}

	reportPath, _, err := writeReport(context.Background(), cfg, run)
	if err != nil {
		t.Fatalf("writeReport() failed: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile(report) failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(report) failed: %v", err)
	}

	plans, ok := decoded["plans"].([]any)
	if !ok || len(plans) != 1 {
		t.Fatalf("decoded plans = %#v, want one plan", decoded["plans"])
	}
	plan, ok := plans[0].(map[string]any)
	if !ok {
		t.Fatalf("decoded plan = %#v, want object", plans[0])
	}
	tests, ok := plan["tests"].([]any)
	if !ok || len(tests) != 1 {
		t.Fatalf("decoded tests = %#v, want one test", plan["tests"])
	}
	testEntry, ok := tests[0].(map[string]any)
	if !ok {
		t.Fatalf("decoded test entry = %#v, want object", tests[0])
	}

	for _, field := range []string{"job_id", "variant"} {
		if _, ok := testEntry[field]; !ok {
			t.Fatalf("report test entry missing field %q: %#v", field, testEntry)
		}
	}
}

func TestExportPlanZip_UsesJobScopedArtifactPath(t *testing.T) {
	runDir := t.TempDir()
	plan := planResult{JobID: "job-001", PlanName: "shared-plan", PlanID: "plan-123"}

	got := planZipPath(runDir, plan)
	want := filepath.Join(runDir, "jobs", "job-001", "plan-shared-plan-plan-123.zip")
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("planZipPath() mismatch (-want +got):\n%s", diff)
	}
}

func TestWriteReport_IncludesMatricesWhenPresent(t *testing.T) {
	tempDir := t.TempDir()
	cfg := harnessConfig{
		SuiteURL:          "https://suite.localhost",
		Profile:           "all-rp",
		Matrices:          []string{"fapi2-sp-final-plain-fapi-all16", "fapi2-ms-final-plain-fapi-all32"},
		ArtifactsDir:      tempDir,
		ExportZip:         false,
		Redact:            false,
		SelectedPlanNames: []string{"plan-a"},
	}

	run := runReport{
		RunID:      "20260405-010203",
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Plans:      []planResult{},
	}

	reportPath, _, err := writeReport(context.Background(), cfg, run)
	if err != nil {
		t.Fatalf("writeReport() failed: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile(report) failed: %v", err)
	}

	var doc reportDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("json.Unmarshal(report) failed: %v", err)
	}

	want := []string{"fapi2-sp-final-plain-fapi-all16", "fapi2-ms-final-plain-fapi-all32"}
	if diff := cmp.Diff(want, doc.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
}
