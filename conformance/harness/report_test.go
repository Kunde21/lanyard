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

	reportPath, err := writeReport(context.Background(), cfg, run)
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

	reportPath, err := writeReport(context.Background(), cfg, run)
	if err != nil {
		t.Fatalf("writeReport() failed: %v", err)
	}

	want := filepath.Join(tempDir, run.RunID, "report.json")
	if diff := cmp.Diff(want, reportPath); diff != "" {
		t.Fatalf("report path mismatch (-want +got):\n%s", diff)
	}
}
