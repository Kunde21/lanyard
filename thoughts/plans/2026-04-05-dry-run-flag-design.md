# Dry-Run Flag Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `--dry-run` flag that prints the expanded test job matrix as a human-readable table and exits without executing tests.

**Architecture:** A new bool flag gates an early-return path in `TestConformanceHarness`. After plan discovery and job expansion, a `printDryRunMatrix` helper formats the table. The test calls `t.Skip` to exit cleanly.

**Tech Stack:** Go standard library, existing `flag` package, `go-cmp` for tests.

---

### Task 1: Add `printDryRunMatrix` helper and `DryRun` config field

**Files:**
- Modify: `conformance/harness/config.go`
- Modify: `conformance/harness/jobs.go`
- Create: `conformance/harness/jobs_test.go`

**Step 1: Add `DryRun` field to `harnessConfig`**

In `conformance/harness/config.go`, add a `DryRun bool` field to the `harnessConfig` struct.

**Step 2: Write the failing test for `printDryRunMatrix`**

Create `conformance/harness/jobs_test.go`:

```go
package conformanceharness

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestPrintDryRunMatrix(t *testing.T) {
	jobs := []RunJob{
		{
			JobID:      "job-001",
			PlanName:   "oidcc-client-basic-certification-test-plan",
			MatrixCase: "",
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
	if !strings.Contains(got, "2 jobs") {
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
	if !strings.Contains(got, "0 jobs") {
		t.Errorf("expected 0 jobs summary, got:\n%s", got)
	}
}
```

**Step 3: Run test to verify it fails**

Run: `go test ./conformance/harness -run TestPrintDryRunMatrix -v`
Expected: FAIL — `printDryRunMatrix` not defined.

**Step 4: Implement `printDryRunMatrix` in `conformance/harness/jobs.go`**

```go
func printDryRunMatrix(logf func(string, ...any), jobs []RunJob) {
	logf("DRY RUN: %d job(s) would be executed\n", len(jobs))
	if len(jobs) == 0 {
		return
	}

	for i, job := range jobs {
		caseLabel := "-"
		if job.MatrixCase != "" {
			caseLabel = job.MatrixCase
		}
		variantLabel := "-"
		if len(job.PlanVariant) > 0 {
			parts := make([]string, 0, len(job.PlanVariant))
			for k, v := range job.PlanVariant {
				parts = append(parts, k+"="+v)
			}
			variantLabel = strings.Join(parts, ", ")
		}
		logf("  %d\t%s\t%s\t%s\t%s", i+1, job.JobID, job.PlanName, caseLabel, variantLabel)
	}
}
```

**Step 5: Run test to verify it passes**

Run: `go test ./conformance/harness -run TestPrintDryRunMatrix -v`
Expected: PASS

**Step 6: Commit**

```bash
git add conformance/harness/config.go conformance/harness/jobs.go conformance/harness/jobs_test.go
git commit -m "feat(harness): add printDryRunMatrix helper and DryRun config field"
```

---

### Task 2: Wire `--dry-run` flag into `TestConformanceHarness`

**Files:**
- Modify: `conformance/harness/harness_test.go:15-42` (flag declarations)
- Modify: `conformance/harness/harness_test.go:49-115` (test function)

**Step 1: Add flag and config wiring**

In `harness_test.go`, add alongside other flag vars:

```go
flagDryRun = flag.Bool("dry-run", false, "Print the test matrix and exit without executing tests")
```

In `parseHarnessConfig`, set `cfg.DryRun = *flagDryRun`.

**Step 2: Add dry-run branch in `TestConformanceHarness`**

After plan selection (after `cfg.SelectedPlanNames` is populated, around line 97) and before `validatePrerequisites`, add:

```go
if cfg.DryRun {
	client := newSuiteClient(cfg.SuiteURL)
	availablePlans, err := client.ListAvailablePlans(ctx)
	if err != nil {
		t.Fatalf("failed to list available plans: %v", err)
	}
	selectedPlans, err := selectPlans(cfg, availablePlans)
	if err != nil {
		t.Fatalf("failed to select plans: %v", err)
	}
	cfg.SelectedPlanNames = make([]string, 0, len(selectedPlans))
	for _, plan := range selectedPlans {
		cfg.SelectedPlanNames = append(cfg.SelectedPlanNames, plan.Name)
	}
	jobs := expandRunJobs(time.Now().UTC().Format("20060102-150405"), cfg, selectedPlans)
	printDryRunMatrix(t.Logf, jobs)
	t.Skip("dry run: no tests executed")
}
```

**Step 3: Run full test suite to verify nothing is broken**

Run: `go test ./conformance/harness -v -count=1`
Expected: All existing tests PASS (skipped due to `LANYARD_CONFORMANCE` not set).

**Step 4: Run vet and format**

Run: `gofumpt ./conformance/harness/... && go vet ./conformance/harness/...`
Expected: No output (clean).

**Step 5: Commit**

```bash
git add conformance/harness/harness_test.go
git commit -m "feat(harness): add --dry-run flag to print test matrix without executing"
```
