# Multi-Matrix Conformance Suite Runner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow running multiple conformance matrices (e.g., OIDC + FAPI2-SP + FAPI2-MS) in a single test run instead of requiring separate invocations.

**Architecture:** Change the `-matrix` flag from a single string to a repeatable flag, add a `-preset` flag for convenient bundles, and deduplicate variant configs across matrices. The existing matrix-per-plan matching logic already handles routing (each matrix only produces variants for its matching plan), so this is primarily a wiring change.

**Tech Stack:** Go 1.25+, `github.com/google/go-cmp/cmp` for test assertions, Go standard `flag` package.

---

## Task 1: Change `Matrix` field from `string` to `[]string` in config

**Files:**
- Modify: `conformance/harness/config.go:14`

**Step 1: Update the harnessConfig struct**

In `conformance/harness/config.go`, change line 14:

```go
// Before:
Matrix               string

// After:
Matrices             []string
```

**Step 2: Verify it compiles**

Run: `go build ./conformance/harness/...`
Expected: Build errors in other files referencing `cfg.Matrix` — this is expected, we fix them next.

---

## Task 2: Make `-matrix` flag repeatable in harness_test.go

**Files:**
- Modify: `conformance/harness/harness_test.go:24,116,122`

**Step 1: Replace the single string flag with a repeatable flag**

Change line 24 from:

```go
flagMatrix           = flag.String("matrix", "", "Named matrix expansion to apply to selected plans")
```

To:

```go
flagMatrices repeatableStringFlag
```

Update the `init()` function (line 43-45) to register the new flag:

```go
func init() {
	flag.Var(&flagMatrices, "matrix", "Named matrix expansion to apply to selected plans (repeatable)")
	flag.Var(&flagForceVariants, "force-variant", "Force suite variant (repeatable key=value, e.g. client_auth_type=client_secret_post)")
}
```

Remove the old `flagMatrix` variable entirely.

**Step 2: Update `parseHarnessConfig()` to use the new field**

In `parseHarnessConfig()` (around line 116-136), replace:

```go
Matrix:               strings.TrimSpace(*flagMatrix),
```

With:

```go
Matrices:             []string(flagMatrices),
```

**Step 3: Verify it compiles**

Run: `go build ./conformance/harness/...`
Expected: Build errors only in `jobs.go` referencing `cfg.Matrix` — fix in next task.

---

## Task 3: Update `expandRunJobs` to iterate over all matrices

**Files:**
- Modify: `conformance/harness/jobs.go:21-38`

**Step 1: Write the failing test**

Add to `conformance/harness/jobs_test.go` (requires `"strings"` import):

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./conformance/harness -run TestExpandRunJobs_MultipleMatrices -v`
Expected: FAIL — `cfg.Matrix` no longer exists (or compile error).

**Step 3: Update `expandRunJobs` to use the multi-matrix field**

Replace `expandRunJobs` in `conformance/harness/jobs.go`:

```go
func expandRunJobs(runID string, cfg harnessConfig, plans []AvailablePlan) []RunJob {
	jobs := make([]RunJob, 0, len(plans))
	jobIndex := 1
	for _, plan := range plans {
		var allVariants []matrixVariant
		for _, matrixName := range cfg.Matrices {
			variants, err := expandMatrixVariants(matrixName, plan.Name)
			if err != nil {
				continue
			}
			allVariants = append(allVariants, variants...)
		}
		allVariants = deduplicateMatrixVariants(plan.Name, allVariants)

		if len(allVariants) == 0 {
			jobs = append(jobs, buildRunJob(runID, jobIndex, plan, "", "", nil, RPProfileConfig{}))
			jobIndex++
			continue
		}

		for _, variant := range allVariants {
			jobs = append(jobs, buildRunJob(runID, jobIndex, plan, "", variant.Name, variant.Variant, variant.RPProfile))
			jobIndex++
		}
	}
	return jobs
}
```

**Step 4: Add the deduplication helpers**

Add to `conformance/harness/jobs.go`:

```go
func deduplicateMatrixVariants(planName string, variants []matrixVariant) []matrixVariant {
	seen := make(map[string]struct{}, len(variants))
	deduped := make([]matrixVariant, 0, len(variants))
	for _, v := range variants {
		key := variantKey(planName, v.Variant)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, v)
	}
	return deduped
}

func variantKey(planName string, variant map[string]string) string {
	keys := make([]string, 0, len(variant))
	for k := range variant {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+variant[k])
	}
	return planName + "|" + strings.Join(parts, ",")
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./conformance/harness -run TestExpandRunJobs -v`
Expected: All `TestExpandRunJobs_*` tests PASS.

**Step 6: Commit**

```bash
git add conformance/harness/config.go conformance/harness/harness_test.go conformance/harness/jobs.go conformance/harness/jobs_test.go
git commit -m "feat: support multiple -matrix flags for batch conformance runs"
```

---

## Task 4: Add deduplication test for overlapping matrices

**Files:**
- Modify: `conformance/harness/jobs_test.go`

**Step 1: Write the overlapping matrices test**

```go
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
```

**Step 2: Run the test**

Run: `go test ./conformance/harness -run TestExpandRunJobs_OverlappingMatrices -v`
Expected: PASS (16 jobs, not 20).

**Step 3: Commit**

```bash
git add conformance/harness/jobs_test.go
git commit -m "test: verify overlapping matrix deduplication"
```

---

## Task 5: Update existing tests to use `Matrices` field

**Files:**
- Modify: `conformance/harness/jobs_test.go`

**Step 1: Update all existing test configs**

In `TestExpandRunJobs_PlainFAPIMatrixProducesDistinctJobs`, change:

```go
Matrix:  "fapi2-sp-final-plain-fapi-first4",
```

To:

```go
Matrices: []string{"fapi2-sp-final-plain-fapi-first4"},
```

Do the same for `TestExpandRunJobs_PlainFAPIAll16ProducesDistinctJobs`:

```go
Matrix:  "fapi2-sp-final-plain-fapi-all16",
```

To:

```go
Matrices: []string{"fapi2-sp-final-plain-fapi-all16"},
```

**Step 2: Run all existing tests**

Run: `go test ./conformance/harness -run TestExpandRunJobs -v`
Expected: All PASS.

**Step 3: Commit**

```bash
git add conformance/harness/jobs_test.go
git commit -m "refactor: update existing tests to use Matrices field"
```

---

## Task 6: Add `-preset` flag support

**Files:**
- Create: `conformance/harness/presets.go`
- Create: `conformance/harness/presets_test.go`
- Modify: `conformance/harness/harness_test.go:24-44,116-136`

**Step 1: Write the failing test**

Create `conformance/harness/presets_test.go`:

```go
package conformanceharness

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestResolvePreset_AllRPFull(t *testing.T) {
	cfg, err := resolvePreset("all-rp-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "all-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "all-rp")
	}
	want := []string{"fapi2-sp-final-plain-fapi-all16", "fapi2-ms-final-plain-fapi-all32"}
	if diff := cmp.Diff(want, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if !cfg.Parallel {
		t.Errorf("Parallel = false, want true")
	}
	if cfg.MaxParallelRuns != 8 {
		t.Errorf("MaxParallelRuns = %d, want 8", cfg.MaxParallelRuns)
	}
}

func TestResolvePreset_AllRPSmoke(t *testing.T) {
	cfg, err := resolvePreset("all-rp-smoke")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "all-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "all-rp")
	}
	if len(cfg.Matrices) != 2 {
		t.Fatalf("Matrices count = %d, want 2", len(cfg.Matrices))
	}
	if cfg.MaxParallelRuns != 4 {
		t.Errorf("MaxParallelRuns = %d, want 4", cfg.MaxParallelRuns)
	}
}

func TestResolvePreset_FAPI2SPFull(t *testing.T) {
	cfg, err := resolvePreset("fapi2-sp-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "fapi-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "fapi-rp")
	}
	if len(cfg.Matrices) != 1 || cfg.Matrices[0] != "fapi2-sp-final-plain-fapi-all16" {
		t.Fatalf("Matrices = %v, want [fapi2-sp-final-plain-fapi-all16]", cfg.Matrices)
	}
}

func TestResolvePreset_FAPI2MSFull(t *testing.T) {
	cfg, err := resolvePreset("fapi2-ms-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "fapi-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "fapi-rp")
	}
	if len(cfg.Matrices) != 1 || cfg.Matrices[0] != "fapi2-ms-final-plain-fapi-all32" {
		t.Fatalf("Matrices = %v, want [fapi2-ms-final-plain-fapi-all32]", cfg.Matrices)
	}
}

func TestResolvePreset_UnknownPresetReturnsError(t *testing.T) {
	_, err := resolvePreset("nonexistent")
	if err == nil {
		t.Fatal("resolvePreset() should return error for unknown preset")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention preset name, got: %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./conformance/harness -run TestResolvePreset -v`
Expected: FAIL — `resolvePreset` not defined.

**Step 3: Implement presets**

Create `conformance/harness/presets.go`:

```go
package conformanceharness

import "fmt"

type presetConfig struct {
	Profile          string
	Matrices         []string
	Parallel         bool
	MaxParallelRuns  int
	IncludePlanRegex string
}

var builtInPresets = map[string]presetConfig{
	"all-rp-full": {
		Profile:         "all-rp",
		Matrices:        []string{"fapi2-sp-final-plain-fapi-all16", "fapi2-ms-final-plain-fapi-all32"},
		Parallel:        true,
		MaxParallelRuns: 8,
	},
	"all-rp-smoke": {
		Profile:         "all-rp",
		Matrices:        []string{"fapi2-sp-final-plain-fapi-first4", "fapi2-ms-final-plain-fapi-jar4"},
		Parallel:        true,
		MaxParallelRuns: 4,
	},
	"fapi2-sp-full": {
		Profile:          "fapi-rp",
		Matrices:         []string{"fapi2-sp-final-plain-fapi-all16"},
		IncludePlanRegex: "fapi2-security-profile-final-client-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
	"fapi2-ms-full": {
		Profile:          "fapi-rp",
		Matrices:         []string{"fapi2-ms-final-plain-fapi-all32"},
		IncludePlanRegex: "fapi2-message-signing-final-client-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
}

func resolvePreset(name string) (presetConfig, error) {
	cfg, ok := builtInPresets[name]
	if !ok {
		return presetConfig{}, fmt.Errorf("unknown preset %q (available: all-rp-full, all-rp-smoke, fapi2-sp-full, fapi2-ms-full)", name)
	}
	return cfg, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./conformance/harness -run TestResolvePreset -v`
Expected: PASS.

**Step 5: Wire preset into `parseHarnessConfig()`**

In `conformance/harness/harness_test.go`, add the flag variable:

```go
flagPreset = flag.String("preset", "", "Named preset combining profile + matrices + parallel settings")
```

Update `parseHarnessConfig()` to apply preset defaults after building the initial `cfg` but before validation. Insert after the `Matrices` assignment and before regex compilation:

```go
if presetName := strings.TrimSpace(*flagPreset); presetName != "" {
	preset, err := resolvePreset(presetName)
	if err != nil {
		return harnessConfig{}, err
	}
	if cfg.Profile == "" {
		cfg.Profile = preset.Profile
	}
	if len(cfg.Matrices) == 0 {
		cfg.Matrices = preset.Matrices
	}
	if !*flagParallel && preset.Parallel {
		cfg.Parallel = preset.Parallel
	}
	if *flagMaxParallelRuns == 1 && preset.MaxParallelRuns > 0 {
		cfg.MaxParallelRuns = preset.MaxParallelRuns
	}
	if *flagIncludePlanRegex == "" && preset.IncludePlanRegex != "" {
		re, regexErr := compileRegex(preset.IncludePlanRegex)
		if regexErr != nil {
			return harnessConfig{}, fmt.Errorf("preset has invalid include-plan-regex: %w", regexErr)
		}
		cfg.IncludePlanRegex = re
	}
}
```

The preset uses "explicit flag wins over preset" semantics:
- If user passes `-profile=oidc-rp`, that wins even with a preset
- If user passes `-matrix=x`, that wins over preset matrices
- If user passes `-parallel=false`, that wins over preset's `true`

**Step 6: Run all harness tests**

Run: `go test ./conformance/harness -v`
Expected: All PASS.

**Step 7: Commit**

```bash
git add conformance/harness/presets.go conformance/harness/presets_test.go conformance/harness/harness_test.go
git commit -m "feat: add -preset flag for bundled matrix+profile configurations"
```

---

## Task 7: Add `Matrices` field to report

**Files:**
- Modify: `conformance/harness/report.go:15-25`
- Modify: `conformance/harness/report.go:52-62`

**Step 1: Add field to reportDocument**

In `reportDocument` struct, add after `Profile`:

```go
Matrices      []string     `json:"matrices,omitempty"`
```

**Step 2: Populate it in `writeReport`**

In the `writeReport` function, add `Matrices` to the `doc` construction:

```go
doc := reportDocument{
	RunID:         run.RunID,
	Timestamp:     time.Now().UTC(),
	GitSHA:        gitSHA,
	SuiteURL:      cfg.SuiteURL,
	Profile:       cfg.Profile,
	Matrices:      cfg.Matrices,
	SelectedPlans: append([]string{}, cfg.SelectedPlanNames...),
	Failed:        run.Failed,
	FailureReason: run.FailureReason,
	Plans:         reportablePlans,
}
```

**Step 3: Write a test**

Add to `conformance/harness/report_test.go`:

```go
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

	reportPath, err := writeReport(context.Background(), cfg, run)
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
```

**Step 4: Run tests**

Run: `go test ./conformance/harness -run TestWriteReport -v`
Expected: All PASS.

**Step 5: Commit**

```bash
git add conformance/harness/report.go conformance/harness/report_test.go
git commit -m "feat: include active matrices in conformance report JSON"
```

---

## Task 8: Add matrix name validation in parseHarnessConfig

**Files:**
- Modify: `conformance/harness/harness_test.go` (in `parseHarnessConfig`)

**Step 1: Validate each matrix name is known**

After the Matrices assignment in `parseHarnessConfig()`, add:

```go
for _, m := range cfg.Matrices {
	m = strings.TrimSpace(m)
	if m == "" || m == "off" {
		continue
	}
	if _, err := expandMatrixVariants(m, ""); err != nil {
		return harnessConfig{}, fmt.Errorf("unknown matrix %q in -matrix flag", m)
	}
}
```

`expandMatrixVariants(m, "")` with an empty plan name returns `nil, nil` for valid matrices (plan check doesn't match) and returns an error for unknown matrix names.

**Step 2: Run tests**

Run: `go test ./conformance/harness -v`
Expected: All PASS.

**Step 3: Commit**

```bash
git add conformance/harness/harness_test.go
git commit -m "feat: validate matrix names in multi-matrix config"
```

---

## Task 9: Update documentation

**Files:**
- Modify: `conformance/AGENTS.md`

**Step 1: Update the Common Flags table**

Update the `-matrix` row:

```markdown
| `-matrix`             | `""`                      | Named matrix expansion (repeatable; each matched to its plan automatically) |
```

Add a new row for `-preset`:

```markdown
| `-preset`             | `""`                      | Named preset bundling profile + matrices + parallel (all-rp-full, all-rp-smoke, fapi2-sp-full, fapi2-ms-full) |
```

**Step 2: Add Presets section**

Add a new section after the "Available Matrices" table:

```markdown
### Presets

Presets bundle profile + matrices + parallel settings for common configurations:

| Preset | Profile | Matrices | Parallel | Jobs |
|--------|---------|----------|----------|------|
| `all-rp-full` | all-rp | fapi2-sp-all16 + fapi2-ms-all32 | 8 | 49 (1 OIDC + 16 SP + 32 MS) |
| `all-rp-smoke` | all-rp | fapi2-sp-first4 + fapi2-ms-jar4 | 4 | 9 (1 OIDC + 4 SP + 4 MS) |
| `fapi2-sp-full` | fapi-rp | fapi2-sp-all16 | 8 | 16 |
| `fapi2-ms-full` | fapi-rp | fapi2-ms-all32 | 8 | 32 |

### Run All Profiles in One Batch

```bash
# Using preset (recommended):
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full

# Using explicit flags:
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=all-rp \
  -matrix=fapi2-sp-final-plain-fapi-all16 \
  -matrix=fapi2-ms-final-plain-fapi-all32 \
  -parallel -max-parallel-runs=8
```
```

**Step 3: Commit**

```bash
git add conformance/AGENTS.md
git commit -m "docs: document multi-matrix and preset support"
```

---

## Task 10: Final validation

**Step 1: Run full test suite**

Run: `go test ./conformance/harness -v -count=1`
Expected: All PASS.

**Step 2: Run linter**

Run: `gofumpt ./conformance/harness/... && go vet ./conformance/harness/...`
Expected: No issues.

**Step 3: Run full module build**

Run: `go build ./...`
Expected: Clean build.
