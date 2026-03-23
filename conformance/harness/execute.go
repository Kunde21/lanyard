package conformanceharness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type testInfoGetter interface {
	GetTestInfo(ctx context.Context, testID string) (testInfo, error)
	StartTest(ctx context.Context, testID string) error
}

type runner struct {
	client *suiteClient
	cfg    harnessConfig
	logf   func(format string, args ...any)
}

func newRunner(client *suiteClient, cfg harnessConfig, logf func(format string, args ...any)) *runner {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if cfg.WaitingMaxRetries < 0 {
		cfg.WaitingMaxRetries = 0
	}
	if cfg.WaitingRetryInterval <= 0 {
		cfg.WaitingRetryInterval = 10 * time.Second
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
	JobID         string            `json:"job_id"`
	Alias         string            `json:"alias"`
	PlanName      string            `json:"plan_name"`
	PlanID        string            `json:"plan_id,omitempty"`
	Variant       map[string]string `json:"variant"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Duration      string            `json:"duration"`
	Failed        bool              `json:"failed"`
	FailureReason string            `json:"failure_reason,omitempty"`
	Tests         []testResult      `json:"tests"`
	ArtifactPath  string            `json:"artifact_path,omitempty"`
}

type testResult struct {
	JobID      string            `json:"job_id"`
	ModuleName string            `json:"module_name"`
	TestID     string            `json:"test_id"`
	Status     string            `json:"status"`
	Result     string            `json:"result"`
	Summary    string            `json:"summary,omitempty"`
	Variant    map[string]string `json:"variant"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Duration   string            `json:"duration"`
	Alias      string            `json:"alias"`
}

func (r *runner) Execute(ctx context.Context, plans []AvailablePlan) runReport {
	runID := time.Now().UTC().Format("20060102-150405")
	jobs := expandRunJobs(runID, r.cfg, plans)
	run := runReport{
		RunID:     runID,
		StartedAt: time.Now().UTC(),
		Plans:     make([]planResult, 0, len(jobs)),
	}

	maxParallelRuns := 1
	if r.cfg.Parallel {
		maxParallelRuns = r.cfg.MaxParallelRuns
	}

	results, err := scheduleJobs(ctx, schedulerConfig{MaxParallelRuns: maxParallelRuns, FailFast: r.cfg.FailFast}, jobs, func(jobCtx context.Context, job RunJob) planResult {
		return newJobRunner(r.client, r.cfg, job, r.logf).execute(jobCtx)
	})
	if err != nil {
		run.Failed = true
		run.FailureReason = err.Error()
		run.FinishedAt = time.Now().UTC()
		return run
	}

	for _, planRes := range results {
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

func (jr *jobRunner) execute(ctx context.Context) planResult {
	startedAt := time.Now().UTC()
	planRes := planResult{
		JobID:     jr.job.JobID,
		Alias:     jr.job.Alias,
		PlanName:  jr.job.PlanName,
		Variant:   stableVariantMap(jr.job.PlanVariant),
		StartedAt: startedAt,
		Tests:     []testResult{},
	}
	jr.logf("plan start: job=%s plan=%s alias=%s", jr.job.JobID, jr.job.PlanName, jr.job.Alias)

	planCtx, cancel := context.WithTimeout(ctx, jr.cfg.PlanTimeout)
	defer cancel()
	runtimeCleanup, err := jr.registerRuntime(planCtx)
	if err != nil {
		failPlan(&planRes, fmt.Sprintf("register runtime failed: %v", err))
		jr.logf("plan failed: job=%s plan=%s (%s)", jr.job.JobID, jr.job.PlanName, planRes.FailureReason)
		return planRes
	}
	defer runtimeCleanup()

	planVariant := mergePlanVariant(jr.job.PlanVariant, jr.cfg.ForcedVariants)
	planConfig := buildPlanConfig(planVariant, jr.job.Alias)
	created, err := jr.client.CreatePlan(planCtx, jr.job.PlanName, planVariant, planConfig)
	if err != nil {
		failPlan(&planRes, fmt.Sprintf("create plan failed: %v", err))
		jr.logf("plan failed: job=%s plan=%s (%s)", jr.job.JobID, jr.job.PlanName, planRes.FailureReason)
		return planRes
	}
	planRes.PlanID = created.PlanID

	modules := created.Modules
	if len(modules) == 0 {
		modules = jr.job.Plan.Modules
	}
	modules = filterModules(modules, jr.cfg.ModuleRegex)

	if len(modules) == 0 {
		failPlan(&planRes, "plan contains no executable modules after filtering")
		jr.logf("plan failed: job=%s plan=%s (%s)", jr.job.JobID, jr.job.PlanName, planRes.FailureReason)
		return planRes
	}

	for moduleIndex, module := range modules {
		testRes := jr.executeModule(planCtx, module, created.PlanID, moduleIndex)
		planRes.Tests = append(planRes.Tests, testRes)
		if moduleFailed(testRes) {
			planRes.Failed = true
		}
	}

	finalizePlan(&planRes)
	if planRes.Failed && planRes.FailureReason == "" {
		planRes.FailureReason = "one or more tests failed"
	}
	jr.logf("plan done: job=%s plan=%s tests=%d failed=%t", jr.job.JobID, jr.job.PlanName, len(planRes.Tests), planRes.Failed)

	return planRes
}

func (jr *jobRunner) executeModule(ctx context.Context, module PlanModule, planID string, moduleIndex int) testResult {
	startedAt := time.Now().UTC()
	alias := fmt.Sprintf("%s-%d", jr.job.Alias, moduleIndex+1)

	res := testResult{JobID: jr.job.JobID, ModuleName: module.Name, Alias: alias, Variant: stableVariantMap(jr.job.PlanVariant), StartedAt: startedAt}
	jr.logf("  test start: job=%s plan=%s module=%s alias=%s", jr.job.JobID, jr.job.PlanName, module.Name, alias)

	planConfig := buildPlanConfig(mergePlanVariant(jr.job.PlanVariant, jr.cfg.ForcedVariants), jr.job.Alias)
	moduleVariant := mergeModuleVariant(module.Variant, jr.cfg.ForcedVariants)
	instance, err := jr.client.CreateTestInstance(ctx, module.Name, planID, moduleVariant, planConfig)
	if err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("create test instance failed: %v", err))
		jr.logf("  test failed: job=%s plan=%s module=%s alias=%s test_id=%s err=%v", jr.job.JobID, jr.job.PlanName, module.Name, alias, instance.ID, err)
		return res
	}
	res.TestID = instance.ID
	testID := instance.ID

	info, err := jr.client.GetTestInfo(ctx, testID)
	if err != nil {
		jr.logf("  warning: failed to get test info: %v", err)
	}
	suiteAlias := effectiveSuiteAlias(info.Alias, jr.job.Alias)
	jr.logf("  test context: job=%s plan=%s module=%s test_id=%s local_alias=%s suite_alias=%s", jr.job.JobID, jr.job.PlanName, module.Name, testID, alias, suiteAlias)

	issuer := constructIssuer(jr.cfg.SuiteURL, info.PlanID, suiteAlias)

	pollCtx, cancel := context.WithTimeout(ctx, jr.cfg.TestTimeout)
	defer cancel()

	trigger := jr.frontChannelTriggerForModule(module.Name, issuer, moduleVariant)
	pollInfo, err := pollTestResultWithConfig(pollCtx, jr.client, testID, trigger, jr.cfg.WaitingMaxRetries, jr.cfg.WaitingRetryInterval)
	if err != nil {
		cleanupErr := jr.cancelTestAndWaitTerminal(testID, jr.job.PlanName, module.Name, alias, suiteAlias)
		summary := fmt.Sprintf("poll failed: %v", err)
		if cleanupErr != nil {
			summary = fmt.Sprintf("%s (cleanup failed: %v)", summary, cleanupErr)
		}
		failTest(&res, "ERROR", "FAILED", summary)
		jr.logf("  test failed: job=%s plan=%s module=%s alias=%s suite_alias=%s test_id=%s err=%v cleanup_err=%v", jr.job.JobID, jr.job.PlanName, module.Name, alias, suiteAlias, testID, err, cleanupErr)
		return res
	}

	res.Status = pollInfo.Status
	res.Result = pollInfo.Result
	res.Summary = pollInfo.Summary
	finalizeTest(&res)
	jr.logf("  test done: job=%s plan=%s module=%s alias=%s suite_alias=%s test_id=%s status=%s result=%s", jr.job.JobID, jr.job.PlanName, module.Name, alias, suiteAlias, testID, res.Status, res.Result)
	return res
}

func (jr *jobRunner) cancelTestAndWaitTerminal(testID, planName, moduleName, localAlias, suiteAlias string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cancelErr := jr.client.CancelTest(cleanupCtx, testID)
	if cancelErr != nil {
		jr.logf("  cleanup warning: plan=%s module=%s local_alias=%s suite_alias=%s test_id=%s failed to cancel test: %v", planName, moduleName, localAlias, suiteAlias, testID, cancelErr)
	}

	waitErr := waitForTerminalTestState(cleanupCtx, jr.client, testID)
	if waitErr != nil {
		jr.logf("  cleanup warning: plan=%s module=%s local_alias=%s suite_alias=%s test_id=%s failed waiting for terminal state: %v", planName, moduleName, localAlias, suiteAlias, testID, waitErr)
	}

	if cancelErr != nil || waitErr != nil {
		return errors.Join(cancelErr, waitErr)
	}

	jr.logf("  cleanup done: plan=%s module=%s local_alias=%s suite_alias=%s test_id=%s reached terminal state", planName, moduleName, localAlias, suiteAlias, testID)
	return nil
}

func constructIssuer(suiteURL, planID, testAlias string) string {
	if testAlias == "" {
		return ""
	}
	return strings.TrimRight(suiteURL, "/") + "/test/a/" + testAlias + "/"
}

func effectiveSuiteAlias(infoAlias, jobAlias string) string {
	if alias := strings.TrimSpace(infoAlias); alias != "" {
		return alias
	}
	return strings.TrimSpace(jobAlias)
}

func (jr *jobRunner) triggerFrontChannelStep(ctx context.Context, testID string) error {
	return jr.doTrigger(ctx, testID, "/login", "", nil)
}

func (jr *jobRunner) frontChannelTriggerForModule(moduleName, issuer string, variant map[string]any) func(context.Context, string) error {
	return func(ctx context.Context, testID string) error {
		endpoint := moduleTriggerEndpoint(moduleName)
		return jr.doTrigger(ctx, testID, endpoint, issuer, variant)
	}
}

func (jr *jobRunner) doTrigger(ctx context.Context, testID, endpoint, issuer string, variant map[string]any) error {
	triggerCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	triggerURL := "https://rp.localhost" + endpoint
	query := url.Values{}
	if issuer != "" {
		query.Set("issuer", issuer)
	}

	if isFAPI2Variant(variant) {
		if v, ok := variant["client_auth_type"]; ok {
			query.Set("client_auth_type", fmt.Sprintf("%v", v))
		}
		if v, ok := variant["sender_constrain"]; ok {
			query.Set("sender_constrain", fmt.Sprintf("%v", v))
		}
		if v, ok := variant["fapi_profile"]; ok {
			query.Set("fapi_profile", fmt.Sprintf("%v", v))
		}
		if v, ok := variant["fapi_request_method"]; ok {
			query.Set("fapi_request_method", fmt.Sprintf("%v", v))
		}
		if v, ok := variant["fapi_response_mode"]; ok {
			query.Set("fapi_response_mode", fmt.Sprintf("%v", v))
		}
	}

	if len(query) > 0 {
		triggerURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(triggerCtx, http.MethodGet, triggerURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build front-channel request: %w", err)
	}

	resp, err := jr.frontClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed calling rp front-channel endpoint: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	jr.logf("    front-channel trigger: job=%s test_id=%s endpoint=%s issuer=%q status=%d", jr.job.JobID, testID, endpoint, issuer, resp.StatusCode)
	return nil
}

func moduleTriggerEndpoint(moduleName string) string {
	discoveryModules := map[string]string{
		"oidcc-client-test-discovery-openid-config":   "/discovery",
		"oidcc-client-test-discovery-jwks-uri-keys":   "/discovery-jwks",
		"oidcc-client-test-discovery-issuer-mismatch": "/discovery",
		"oidcc-client-test-discovery-webfinger-acct":  "/webfinger-acct",
		"oidcc-client-test-discovery-webfinger-url":   "/webfinger-url",
		"oidcc-client-test-userinfo-bearer-body":      "/login-userinfo-body",
	}
	if endpoint, ok := discoveryModules[moduleName]; ok {
		return endpoint
	}
	return "/login"
}

func pollTestResult(ctx context.Context, client testInfoGetter, testID string, onWaiting func(context.Context, string) error) (testInfo, error) {
	return pollTestResultWithConfig(ctx, client, testID, onWaiting, 3, 2*time.Second)
}

func pollTestResultWithConfig(ctx context.Context, client testInfoGetter, testID string, onWaiting func(context.Context, string) error, maxRetries int, retryInterval time.Duration) (testInfo, error) {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	waitingTriggerAttempts := 0
	var lastWaitingTrigger time.Time
	var waitingTriggerErr error
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
				if onWaiting != nil {
					shouldTrigger := waitingTriggerAttempts == 0
					if !shouldTrigger && waitingTriggerAttempts <= maxRetries {
						if retryInterval <= 0 {
							shouldTrigger = true
						} else if time.Since(lastWaitingTrigger) >= retryInterval {
							shouldTrigger = true
						}
					}

					if shouldTrigger {
						waitingTriggerAttempts++
						lastWaitingTrigger = time.Now()
						if err := onWaiting(ctx, testID); err != nil {
							waitingTriggerErr = err
						}
					}
				}
			} else {
				waitingTriggerAttempts = 0
				lastWaitingTrigger = time.Time{}
				waitingTriggerErr = nil
			}

			if waitingTriggerErr != nil && waitingTriggerAttempts >= maxRetries+1 {
				return testInfo{}, fmt.Errorf("test entered WAITING state and front-channel trigger failed after %d attempts: %w", waitingTriggerAttempts, waitingTriggerErr)
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

func waitForTerminalTestState(ctx context.Context, client *suiteClient, testID string) error {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		info, err := client.GetTestInfo(ctx, testID)
		if err == nil && isTerminalStatus(info) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func isTestDone(info testInfo) bool {
	if isTerminalStatus(info) {
		return true
	}

	result := strings.ToUpper(strings.TrimSpace(info.Result))
	return result != "" && result != "UNKNOWN"
}

func isTerminalStatus(info testInfo) bool {
	status := strings.ToUpper(strings.TrimSpace(info.Status))
	switch status {
	case "FINISHED", "COMPLETE", "COMPLETED", "DONE", "INTERRUPTED", "CANCELLED", "ERROR", "FAILED", "STOPPED":
		return true
	}

	return false
}

func moduleFailed(result testResult) bool {
	res := strings.ToUpper(strings.TrimSpace(result.Result))
	if res == "PASSED" || res == "SUCCESS" || res == "SKIPPED" {
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
		selected[key] = chooseVariantValue(key, values)
	}

	if len(selected) == 0 {
		return nil
	}
	return selected
}

func chooseVariantValue(key string, values []string) string {
	lowerKey := strings.ToLower(strings.TrimSpace(key))

	if lowerKey == "client_registration" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "static_client") {
				return value
			}
		}
	}

	if lowerKey == "fapi_profile" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "plain_fapi") {
				return value
			}
		}
	}

	if lowerKey == "fapi_client_type" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "oidc") {
				return value
			}
		}
	}

	if lowerKey == "client_auth_type" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "private_key_jwt") {
				return value
			}
		}
	}

	if lowerKey == "sender_constrain" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "dpop") {
				return value
			}
		}
	}

	if lowerKey == "fapi_request_method" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "signed_non_repudiation") {
				return value
			}
		}
	}

	if lowerKey == "fapi_response_mode" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "plain_response") {
				return value
			}
		}
	}

	return values[0]
}

func buildPlanConfig(planVariant map[string]string, alias string) map[string]any {
	if !usesStaticClientRegistration(planVariant) {
		return map[string]any{}
	}
	if strings.TrimSpace(alias) == "" {
		alias = "lanyard-local"
	}
	redirectURI := runtimeRedirectURI(alias)

	isFAPI2 := isFAPI2PlanVariant(planVariant)

	requestType := "plain_http_request"
	if v := strings.TrimSpace(planVariant["request_type"]); v != "" {
		requestType = v
	}

	cfg := map[string]any{
		"alias":       alias,
		"description": "Lanyard automated local conformance run",
		"client": map[string]any{
			"client_id":     "local-dev-client",
			"client_secret": "local-dev-secret-32-bytes-minimum!!",
			"redirect_uri":  redirectURI,
			"request_type":  requestType,
		},
		"client2": map[string]any{
			"client_id":     "local-dev-client-2",
			"client_secret": "local-dev-secret-2-32-bytes-min!!",
			"redirect_uri":  redirectURI,
			"request_type":  requestType,
		},
		"waitTimeoutSeconds": 300,
	}

	if isFAPI2 {
		cfg["server"] = loadJWKS("server.jwks.json")
		cfg["client"].(map[string]any)["jwks"] = loadJWKS("client.jwks.json")
		cfg["client2"].(map[string]any)["jwks"] = loadJWKS("client.jwks.json")

		if certPEM, keyPEM, err := loadClientMTLSCert(); err == nil {
			cfg["client"].(map[string]any)["certificate"] = certPEM
			cfg["client2"].(map[string]any)["certificate"] = certPEM
			_ = keyPEM
		}
	}

	return cfg
}

func runtimeRedirectURI(alias string) string {
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" {
		return "https://rp.localhost/callback"
	}
	return "https://rp.localhost/callback/" + url.PathEscape(trimmed)
}

func isFAPI2PlanVariant(planVariant map[string]string) bool {
	for key := range planVariant {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "fapi_") ||
			strings.HasPrefix(lower, "client_auth") ||
			strings.HasPrefix(lower, "sender_") {
			return true
		}
	}
	return false
}

func isFAPI2Variant(variant map[string]any) bool {
	if variant == nil {
		return false
	}
	for key := range variant {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "fapi_") ||
			strings.HasPrefix(lower, "client_auth") ||
			strings.HasPrefix(lower, "sender_") {
			return true
		}
	}
	return false
}

func loadJWKS(filename string) map[string]any {
	certsDir, err := repoPath("conformance/certs")
	if err != nil {
		return nil
	}
	path := filepath.Join(certsDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var jwks map[string]any
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil
	}
	return jwks
}

func loadClientMTLSCert() (string, string, error) {
	certsDir, err := repoPath("conformance/certs")
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(certsDir, "client-mtls.pem")
	keyPath := filepath.Join(certsDir, "client-mtls-key.pem")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", err
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", err
	}
	return string(certData), string(keyData), nil
}

func usesStaticClientRegistration(planVariant map[string]string) bool {
	v, ok := planVariant["client_registration"]
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), "static_client")
}
