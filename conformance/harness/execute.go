package conformanceharness

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type runner struct {
	client *suiteClient
	cfg    harnessConfig
	logf   func(format string, args ...any)
}

func newRunner(client *suiteClient, cfg harnessConfig, logf func(format string, args ...any)) *runner {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &runner{client: client, cfg: cfg, logf: logf}
}

type runReport struct {
	RunID         string       `json:"run_id"`
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
	Failed        bool         `json:"failed"`
	FailureReason string       `json:"failure_reason,omitempty"`
	Plans         []planResult `json:"plans"`
}

type planResult struct {
	PlanName      string       `json:"plan_name"`
	PlanID        string       `json:"plan_id,omitempty"`
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
	Duration      string       `json:"duration"`
	Failed        bool         `json:"failed"`
	FailureReason string       `json:"failure_reason,omitempty"`
	Tests         []testResult `json:"tests"`
	ArtifactPath  string       `json:"artifact_path,omitempty"`
}

type testResult struct {
	ModuleName string    `json:"module_name"`
	TestID     string    `json:"test_id"`
	Status     string    `json:"status"`
	Result     string    `json:"result"`
	Summary    string    `json:"summary,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   string    `json:"duration"`
	Alias      string    `json:"alias"`
}

func (r *runner) Execute(ctx context.Context, plans []AvailablePlan) runReport {
	run := runReport{
		RunID:     time.Now().UTC().Format("20060102-150405"),
		StartedAt: time.Now().UTC(),
		Plans:     make([]planResult, 0, len(plans)),
	}

	for planIndex, selected := range plans {
		planRes := r.executePlan(ctx, selected, planIndex)
		run.Plans = append(run.Plans, planRes)
		if planRes.Failed {
			run.Failed = true
		}
	}

	run.FinishedAt = time.Now().UTC()
	if run.Failed && run.FailureReason == "" {
		run.FailureReason = "one or more plans failed"
	}

	r.logf("final summary: plans=%d failed=%t", len(run.Plans), run.Failed)
	return run
}

func (r *runner) executePlan(ctx context.Context, selected AvailablePlan, planIndex int) planResult {
	startedAt := time.Now().UTC()
	planRes := planResult{
		PlanName:  selected.Name,
		StartedAt: startedAt,
		Tests:     []testResult{},
	}
	r.logf("plan start: %s", selected.Name)

	planCtx, cancel := context.WithTimeout(ctx, r.cfg.PlanTimeout)
	defer cancel()

	planVariant := selectPlanVariant(selected)
	created, err := r.client.CreatePlan(planCtx, selected.Name, planVariant, map[string]any{})
	if err != nil {
		failPlan(&planRes, fmt.Sprintf("create plan failed: %v", err))
		r.logf("plan failed: %s (%s)", selected.Name, planRes.FailureReason)
		return planRes
	}
	planRes.PlanID = created.PlanID

	modules := created.Modules
	if len(modules) == 0 {
		modules = selected.Modules
	}
	modules = filterModules(modules, r.cfg.ModuleRegex)

	if len(modules) == 0 {
		failPlan(&planRes, "plan contains no executable modules after filtering")
		r.logf("plan failed: %s (%s)", selected.Name, planRes.FailureReason)
		return planRes
	}

	for moduleIndex, module := range modules {
		testRes := r.executeModule(planCtx, selected, module, created.PlanID, planIndex, moduleIndex)
		planRes.Tests = append(planRes.Tests, testRes)
		if moduleFailed(testRes) {
			planRes.Failed = true
		}
	}

	finalizePlan(&planRes)
	if planRes.Failed && planRes.FailureReason == "" {
		planRes.FailureReason = "one or more tests failed"
	}
	r.logf("plan done: %s tests=%d failed=%t", selected.Name, len(planRes.Tests), planRes.Failed)

	return planRes
}

func (r *runner) executeModule(ctx context.Context, selected AvailablePlan, module PlanModule, planID string, planIndex, moduleIndex int) testResult {
	startedAt := time.Now().UTC()
	alias := fmt.Sprintf("lanyard-%d-%d", planIndex+1, moduleIndex+1)

	res := testResult{ModuleName: module.Name, Alias: alias, StartedAt: startedAt}
	r.logf("  test start: plan=%s module=%s alias=%s", selected.Name, module.Name, alias)

	testID, err := r.client.CreateTestInstance(ctx, module.Name, planID, module.Variant, nil)
	if err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("create test instance failed: %v", err))
		r.logf("  test failed: module=%s err=%v", module.Name, err)
		return res
	}
	res.TestID = testID

	pollCtx, cancel := context.WithTimeout(ctx, r.cfg.TestTimeout)
	defer cancel()

	info, err := pollTestResult(pollCtx, r.client, testID)
	if err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("poll failed: %v", err))
		r.logf("  test failed: module=%s err=%v", module.Name, err)
		return res
	}

	res.Status = info.Status
	res.Result = info.Result
	res.Summary = info.Summary
	finalizeTest(&res)
	r.logf("  test done: module=%s status=%s result=%s", module.Name, res.Status, res.Result)
	return res
}

func pollTestResult(ctx context.Context, client *suiteClient, testID string) (testInfo, error) {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	var waitingSince time.Time
	startedFromConfigured := false

	for {
		if err := ctx.Err(); err != nil {
			return testInfo{}, err
		}

		info, err := client.GetTestInfo(ctx, testID)
		if err == nil {
			status := strings.ToUpper(strings.TrimSpace(info.Status))
			if status == "CONFIGURED" && !startedFromConfigured {
				if startErr := client.StartTest(ctx, testID); startErr != nil {
					return testInfo{}, fmt.Errorf("failed to start configured test: %w", startErr)
				}
				startedFromConfigured = true
			}

			if status == "WAITING" {
				if waitingSince.IsZero() {
					waitingSince = time.Now()
				}
				if time.Since(waitingSince) >= waitingStateWindow(ctx) {
					return testInfo{}, fmt.Errorf("test entered WAITING state and did not progress; interactive/browser step likely required")
				}
			} else {
				waitingSince = time.Time{}
			}

			if isTestDone(info) {
				return info, nil
			}
		}

		select {
		case <-ctx.Done():
			return testInfo{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitingStateWindow(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 20 * time.Second
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1 * time.Second
	}
	window := remaining / 3
	if window < 10*time.Second {
		window = 10 * time.Second
	}
	if window > 30*time.Second {
		window = 30 * time.Second
	}
	return window
}

func isTestDone(info testInfo) bool {
	status := strings.ToUpper(strings.TrimSpace(info.Status))
	if status == "FINISHED" || status == "COMPLETE" || status == "COMPLETED" || status == "DONE" {
		return true
	}
	result := strings.ToUpper(strings.TrimSpace(info.Result))
	return result != "" && result != "UNKNOWN"
}

func moduleFailed(result testResult) bool {
	res := strings.ToUpper(strings.TrimSpace(result.Result))
	if res == "PASSED" || res == "SUCCESS" {
		return false
	}
	return true
}

func filterModules(modules []PlanModule, moduleRegex *regexp.Regexp) []PlanModule {
	if moduleRegex == nil {
		return modules
	}
	filtered := make([]PlanModule, 0, len(modules))
	for _, module := range modules {
		if moduleRegex.MatchString(module.Name) {
			filtered = append(filtered, module)
		}
	}
	return filtered
}

func selectPlanVariant(plan AvailablePlan) map[string]string {
	if len(plan.Variants) == 0 {
		return nil
	}

	keys := make([]string, 0, len(plan.Variants))
	for key := range plan.Variants {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	selected := make(map[string]string, len(keys))
	for _, key := range keys {
		values := append([]string(nil), plan.Variants[key]...)
		if len(values) == 0 {
			continue
		}
		sort.Strings(values)
		selected[key] = values[0]
	}

	if len(selected) == 0 {
		return nil
	}
	return selected
}
