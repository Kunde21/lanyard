package conformanceharness

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	planConfig := buildPlanConfig(planVariant, jr.job.Alias, jr.cfg.WaitTimeoutSeconds)
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
	action := startupActionForModule(module.Name)

	res := testResult{JobID: jr.job.JobID, ModuleName: module.Name, Alias: alias, Variant: stableVariantMap(jr.job.PlanVariant), StartedAt: startedAt}
	jr.logf("  test start: job=%s plan=%s module=%s alias=%s", jr.job.JobID, jr.job.PlanName, module.Name, alias)

	moduleVariant := mergeModuleVariant(module.Variant, jr.cfg.ForcedVariants)
	planVariant := mergePlanVariant(jr.job.PlanVariant, jr.cfg.ForcedVariants)
	createVariant := moduleVariant
	testPlanID := planID
	var testConfig map[string]any
	if action != "full_flow" {
		testPlanID = ""
		testConfig = buildStandaloneModuleConfig(alias, planVariant, jr.cfg.WaitTimeoutSeconds)
		createVariant = mergeVariantMaps(stringMapToAnyMap(planVariant), moduleVariant)
	}
	instance, err := jr.client.CreateTestInstance(ctx, module.Name, testPlanID, createVariant, testConfig)
	if err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("create test instance failed: %v", err))
		jr.logf("  test failed: job=%s plan=%s module=%s alias=%s test_id=%s err=%v", jr.job.JobID, jr.job.PlanName, module.Name, alias, instance.ID, err)
		return res
	}
	res.TestID = instance.ID
	testID := instance.ID

	info, err := waitForTestReady(ctx, jr.client, testID)
	if err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("wait for test readiness failed: %v", err))
		jr.logf("  test failed: job=%s plan=%s module=%s alias=%s test_id=%s err=%v", jr.job.JobID, jr.job.PlanName, module.Name, alias, testID, err)
		return res
	}
	runtimeAlias := effectiveSuiteAlias(info.Alias, jr.job.Alias)
	runtimeNamespace := alias
	jr.logf("  test context: job=%s plan=%s module=%s test_id=%s local_alias=%s suite_alias=%s runtime_alias=%s", jr.job.JobID, jr.job.PlanName, module.Name, testID, alias, info.Alias, runtimeAlias)

	pollCtx, cancel := context.WithTimeout(ctx, jr.cfg.TestTimeout)
	defer cancel()
	if err := jr.registerRuntimeAlias(pollCtx, runtimeAlias, runtimeNamespace, module.Name); err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("register runtime alias failed: %v", err))
		jr.logf("  test failed: job=%s plan=%s module=%s alias=%s runtime_alias=%s test_id=%s err=%v", jr.job.JobID, jr.job.PlanName, module.Name, alias, runtimeAlias, testID, err)
		return res
	}

	var trigger func(context.Context, string) error
	if action == "full_flow" {
		trigger = jr.frontChannelTriggerForAlias(runtimeAlias, module.Name)
	}

	pollInfo, err := pollTestResultWithConfig(pollCtx, jr.client, testID, trigger, jr.cfg.WaitingMaxRetries, jr.cfg.WaitingRetryInterval)
	if err != nil {
		cleanupErr := jr.cancelTestAndWaitTerminal(testID, jr.job.PlanName, module.Name, alias, runtimeAlias)
		summary := fmt.Sprintf("poll failed: %v", err)
		if cleanupErr != nil {
			summary = fmt.Sprintf("%s (cleanup failed: %v)", summary, cleanupErr)
		}
		failTest(&res, "ERROR", "FAILED", summary)
		jr.logf("  test failed: job=%s plan=%s module=%s alias=%s runtime_alias=%s test_id=%s err=%v cleanup_err=%v", jr.job.JobID, jr.job.PlanName, module.Name, alias, runtimeAlias, testID, err, cleanupErr)
		return res
	}

	res.Status = pollInfo.Status
	res.Result = pollInfo.Result
	res.Summary = pollInfo.Summary
	finalizeTest(&res)
	jr.logf("  test done: job=%s plan=%s module=%s alias=%s runtime_alias=%s test_id=%s status=%s result=%s", jr.job.JobID, jr.job.PlanName, module.Name, alias, runtimeAlias, testID, res.Status, res.Result)
	return res
}

func (jr *jobRunner) cancelTestAndWaitTerminal(testID, planName, moduleName, localAlias, runtimeAlias string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cancelErr := jr.client.CancelTest(cleanupCtx, testID)
	if cancelErr != nil {
		jr.logf("  cleanup warning: plan=%s module=%s local_alias=%s runtime_alias=%s test_id=%s failed to cancel test: %v", planName, moduleName, localAlias, runtimeAlias, testID, cancelErr)
	}

	waitErr := waitForTerminalTestState(cleanupCtx, jr.client, testID)
	if waitErr != nil {
		jr.logf("  cleanup warning: plan=%s module=%s local_alias=%s runtime_alias=%s test_id=%s failed waiting for terminal state: %v", planName, moduleName, localAlias, runtimeAlias, testID, waitErr)
	}

	if cancelErr != nil || waitErr != nil {
		return errors.Join(cancelErr, waitErr)
	}

	jr.logf("  cleanup done: plan=%s module=%s local_alias=%s runtime_alias=%s test_id=%s reached terminal state", planName, moduleName, localAlias, runtimeAlias, testID)
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

func (jr *jobRunner) frontChannelTriggerForAlias(alias string, moduleName string) func(context.Context, string) error {
	return func(ctx context.Context, testID string) error {
		return jr.executeStartupBrowserVisit(ctx, testID, alias, moduleName)
	}
}

func (jr *jobRunner) executeStartupBrowserVisit(ctx context.Context, testID, alias, moduleName string) error {
	triggerCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	startup, ok := jr.startupByAlias[alias]
	if !ok || strings.TrimSpace(startup.AuthorizationURL) == "" {
		return fmt.Errorf("startup browser visit missing authorization url for alias %q", alias)
	}
	req, err := http.NewRequestWithContext(triggerCtx, http.MethodGet, startup.AuthorizationURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build authorization request: %w", err)
	}
	if len(startup.Cookies) > 0 && jr.frontClient.Jar != nil {
		rpURL, err := url.Parse("https://rp.localhost/")
		if err != nil {
			return fmt.Errorf("failed to parse rp cookie url: %w", err)
		}
		cookies := make([]*http.Cookie, 0, len(startup.Cookies))
		for _, rawCookie := range startup.Cookies {
			if strings.TrimSpace(rawCookie) == "" {
				continue
			}
			cookie, err := http.ParseSetCookie(rawCookie)
			if err != nil {
				return fmt.Errorf("failed to parse startup cookie: %w", err)
			}
			cookies = append(cookies, cookie)
		}
		jr.frontClient.Jar.SetCookies(rpURL, cookies)
	}

	resp, finalURL, err := jr.executeBrowserVisit(triggerCtx, testID, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))

	jr.logf("    startup browser visit: job=%s test_id=%s alias=%s auth_url=%q final_url=%q status=%d", jr.job.JobID, testID, alias, startup.AuthorizationURL, finalURL, resp.StatusCode)
	if err := frontChannelTriggerStatusErrorForModule(resp.StatusCode, string(body), moduleName); err != nil {
		return err
	}
	return nil
}

func (jr *jobRunner) executeBrowserVisit(ctx context.Context, testID string, initialReq *http.Request) (*http.Response, string, error) {
	client := *jr.frontClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	currentReq := initialReq
	currentVisitURL := initialReq.URL.String()
	for redirects := 0; redirects < 10; redirects++ {
		resp, err := client.Do(currentReq)
		if err != nil {
			return nil, "", fmt.Errorf("failed calling rp front-channel endpoint: %w", err)
		}

		if err := jr.client.VisitBrowserURL(ctx, testID, currentVisitURL); err != nil {
			resp.Body.Close()
			return nil, "", fmt.Errorf("failed marking browser visit %q: %w", currentVisitURL, err)
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			resp.Body.Close()
			if location == "" {
				return nil, "", fmt.Errorf("redirect with empty location header")
			}

			nextURL, err := currentReq.URL.Parse(location)
			if err != nil {
				return nil, "", fmt.Errorf("failed resolving redirect location %q: %w", location, err)
			}
			currentVisitURL = nextURL.String()
			nextURL = mergeFragmentIntoQuery(nextURL)

			nextReq, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL.String(), nil)
			if err != nil {
				return nil, "", fmt.Errorf("failed to build redirect request: %w", err)
			}
			currentReq = nextReq
			continue
		}

		if isHTMLFormPostResponse(resp) {
			bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			if readErr == nil && isFormPostAutoSubmitHTML(string(bodyBytes)) {
				actionURL, formParams, ok := parseFormPostAutoSubmit(string(bodyBytes))
				if !ok {
					return nil, "", fmt.Errorf("failed to parse form-post auto-submit response")
				}

				resolvedURL, err := currentReq.URL.Parse(actionURL)
				if err != nil {
					return nil, "", fmt.Errorf("failed resolving form-post action %q: %w", actionURL, err)
				}

				formReq, err := http.NewRequestWithContext(ctx, http.MethodPost, resolvedURL.String(), strings.NewReader(formParams.Encode()))
				if err != nil {
					return nil, "", fmt.Errorf("failed to build form-post request: %w", err)
				}
				formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				if err := jr.client.VisitBrowserURL(ctx, testID, resolvedURL.String()); err != nil {
					return nil, "", fmt.Errorf("failed marking browser visit %q: %w", resolvedURL.String(), err)
				}

				formResp, err := client.Do(formReq)
				if err != nil {
					return nil, "", fmt.Errorf("failed submitting form-post callback: %w", err)
				}

				if formResp.StatusCode >= 300 && formResp.StatusCode < 400 {
					location := strings.TrimSpace(formResp.Header.Get("Location"))
					formResp.Body.Close()
					if location == "" {
						return nil, "", fmt.Errorf("redirect after form-post with empty location")
					}

					nextURL, err := resolvedURL.Parse(location)
					if err != nil {
						return nil, "", fmt.Errorf("failed resolving post-form-post redirect %q: %w", location, err)
					}
					currentVisitURL = nextURL.String()
					nextURL = mergeFragmentIntoQuery(nextURL)

					nextReq, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL.String(), nil)
					if err != nil {
						return nil, "", fmt.Errorf("failed to build post-form-post request: %w", err)
					}

					finalResp, err := client.Do(nextReq)
					if err != nil {
						return nil, "", fmt.Errorf("failed following post-form-post redirect: %w", err)
					}
					return finalResp, nextURL.String(), nil
				}

				return formResp, resolvedURL.String(), nil
			}

			resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
			return resp, currentReq.URL.String(), nil
		}

		return resp, currentReq.URL.String(), nil
	}

	return nil, "", fmt.Errorf("front-channel trigger exceeded redirect limit")
}

func mergeFragmentIntoQuery(nextURL *url.URL) *url.URL {
	if nextURL == nil || strings.TrimSpace(nextURL.Fragment) == "" {
		return nextURL
	}
	fragmentValues, err := url.ParseQuery(nextURL.Fragment)
	if err != nil || len(fragmentValues) == 0 {
		return nextURL
	}
	merged := *nextURL
	query := merged.Query()
	for key, values := range fragmentValues {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	merged.RawQuery = query.Encode()
	merged.Fragment = ""
	return &merged
}

func frontChannelTriggerStatusError(statusCode int, body string) error {
	if statusCode >= 200 && statusCode < 400 {
		return nil
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return fmt.Errorf("front-channel trigger failed: status=%d", statusCode)
	}
	return fmt.Errorf("front-channel trigger failed: status=%d body=%q", statusCode, body)
}

func frontChannelTriggerStatusErrorForModule(statusCode int, body string, moduleName string) error {
	if isNegativeTestModule(moduleName) {
		if statusCode >= 400 {
			return nil
		}
	}
	return frontChannelTriggerStatusError(statusCode, body)
}

func isNegativeTestModule(moduleName string) bool {
	negativeModules := map[string]bool{
		"fapi2-security-profile-final-client-test-invalid-authorization-response-iss":                             true,
		"fapi2-security-profile-final-client-test-remove-authorization-response-iss":                              true,
		"fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails":         true,
		"fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-missing-state-fails": true,
		"fapi2-security-profile-final-client-test-ensure-jarm-without-iss-fails":                                  true,
		"fapi2-security-profile-final-client-test-ensure-jarm-with-invalid-iss-fails":                             true,
		"fapi2-security-profile-final-client-test-ensure-jarm-without-aud-fails":                                  true,
		"fapi2-security-profile-final-client-test-ensure-jarm-with-invalid-aud-fails":                             true,
		"fapi2-security-profile-final-client-test-ensure-jarm-without-exp-fails":                                  true,
		"fapi2-security-profile-final-client-test-ensure-jarm-with-expired-exp-fails":                             true,
		"fapi2-security-profile-final-client-test-ensure-jarm-with-invalid-sig-fails":                             true,
		"fapi2-security-profile-final-client-test-ensure-jarm-signature-is-not-none":                              true,
		"fapi2-security-profile-final-client-test-invalid-iss":                                                    true,
		"fapi2-security-profile-final-client-test-invalid-aud":                                                    true,
		"fapi2-security-profile-final-client-test-invalid-secondary-aud":                                          true,
		"fapi2-security-profile-final-client-test-invalid-null-alg":                                               true,
		"fapi2-security-profile-final-client-test-invalid-alternate-alg":                                          true,
		"fapi2-security-profile-final-client-test-invalid-expired-exp":                                            true,
		"fapi2-security-profile-final-client-test-invalid-missing-exp":                                            true,
		"fapi2-security-profile-final-client-test-invalid-missing-aud":                                            true,
		"fapi2-security-profile-final-client-test-invalid-missing-iss":                                            true,
		"fapi2-security-profile-final-client-test-invalid-nonce":                                                  true,
		"fapi2-security-profile-final-client-test-invalid-missing-nonce":                                          true,
		"fapi1-advanced-final-client-test-invalid-shash":                                                          true,
		"fapi1-advanced-final-client-test-invalid-chash":                                                          true,
		"fapi1-advanced-final-client-test-invalid-nonce":                                                          true,
		"fapi1-advanced-final-client-test-invalid-iss":                                                            true,
		"fapi1-advanced-final-client-test-invalid-aud":                                                            true,
		"fapi1-advanced-final-client-test-invalid-secondary-aud":                                                  true,
		"fapi1-advanced-final-client-test-invalid-signature":                                                      true,
		"fapi1-advanced-final-client-test-invalid-null-alg":                                                       true,
		"fapi1-advanced-final-client-test-invalid-alternate-alg":                                                  true,
		"fapi1-advanced-final-client-test-invalid-expired-exp":                                                    true,
		"fapi1-advanced-final-client-test-invalid-missing-exp":                                                    true,
		"fapi1-advanced-final-client-test-invalid-missing-aud":                                                    true,
		"fapi1-advanced-final-client-test-invalid-missing-iss":                                                    true,
		"fapi1-advanced-final-client-test-invalid-missing-nonce":                                                  true,
		"fapi1-advanced-final-client-test-invalid-missing-shash":                                                  true,
		"fapi1-advanced-final-client-test-iat-is-week-in-past":                                                    true,
		"fapi1-advanced-final-client-test-encrypted-idtoken-usingrsa15":                                           true,
	}
	return negativeModules[moduleName]
}

func pollTestResult(ctx context.Context, client testInfoGetter, testID string, onWaiting func(context.Context, string) error) (testInfo, error) {
	return pollTestResultWithConfig(ctx, client, testID, onWaiting, 3, 2*time.Second)
}

func waitForTestReady(ctx context.Context, client testInfoGetter, testID string) (testInfo, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := client.GetTestInfo(ctx, testID)
		if err != nil {
			return testInfo{}, err
		}
		switch strings.ToUpper(strings.TrimSpace(info.Status)) {
		case "WAITING", "RUNNING":
			return info, nil
		case "CONFIGURED":
			if err := client.StartTest(ctx, testID); err != nil {
				return testInfo{}, fmt.Errorf("start configured test: %w", err)
			}
		case "CREATED", "PENDING", "QUEUED", "":
			// keep waiting until the suite exposes the module for interaction.
		default:
			if isTerminalStatus(info) {
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
	if res == "PASSED" || res == "SUCCESS" || res == "SKIPPED" || res == "WARNING" {
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

	if lowerKey == "request_type" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "plain_http_request") {
				return value
			}
		}
	}

	if lowerKey == "response_mode" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "default") {
				return value
			}
		}
	}

	return values[0]
}

func scopeStringForPlanVariant(planVariant map[string]string) string {
	return strings.Join(scopesForPlanVariant(planVariant), " ")
}

func buildPlanConfig(planVariant map[string]string, alias string, waitTimeoutSeconds int) map[string]any {
	if !usesStaticClientRegistration(planVariant) && !isFAPI2PlanVariant(planVariant) {
		return map[string]any{}
	}
	if waitTimeoutSeconds <= 0 {
		waitTimeoutSeconds = 5
	}
	if strings.TrimSpace(alias) == "" {
		alias = "lanyard-local"
	}
	redirectURI := runtimeRedirectURI(alias)

	isFAPI2 := isFAPI2PlanVariant(planVariant)

	requestType := requestTypeForPlanVariant(planVariant)
	scope := scopeStringForPlanVariant(planVariant)

	cfg := map[string]any{
		"alias":       alias,
		"description": "Lanyard automated local conformance run",
		"client": map[string]any{
			"client_id":     "local-dev-client",
			"client_secret": "local-dev-secret-32-bytes-minimum!!",
			"redirect_uri":  redirectURI,
			"scope":         scope,
			"request_type":  requestType,
		},
		"client2": map[string]any{
			"client_id":     "local-dev-client-2",
			"client_secret": "local-dev-secret-2-32-bytes-min!!",
			"redirect_uri":  redirectURI,
			"scope":         scope,
			"request_type":  requestType,
		},
		"waitTimeoutSeconds": waitTimeoutSeconds,
	}

	if isFAPI2 {
		cfg["server"] = map[string]any{"jwks": loadJWKS("server.jwks.json")}
		clientJWKS := loadPublicJWKS("client.jwks.json")
		clientJWKS = appendRSAEncryptionKeyToJWKS(clientJWKS, "client-encryption-rsa", "RSA-OAEP-256")

		if strings.EqualFold(strings.TrimSpace(planVariant["client_auth_type"]), "mtls") {
			clientJWKS = appendMTLSPublicKeyToJWKS(clientJWKS)
		}

		cfg["client"].(map[string]any)["jwks"] = clientJWKS
		cfg["client2"].(map[string]any)["jwks"] = clientJWKS
		cfg["client"].(map[string]any)["id_token_encrypted_response_alg"] = "RSA-OAEP-256"
		cfg["client"].(map[string]any)["id_token_encrypted_response_enc"] = "A256GCM"
		cfg["client2"].(map[string]any)["id_token_encrypted_response_alg"] = "RSA-OAEP-256"
		cfg["client2"].(map[string]any)["id_token_encrypted_response_enc"] = "A256GCM"

		if certPEM, keyPEM, err := loadClientMTLSCert(); err == nil {
			cfg["client"].(map[string]any)["certificate"] = certPEM
			cfg["client2"].(map[string]any)["certificate"] = certPEM
			_ = keyPEM
		}
	}

	authType := strings.ToLower(strings.TrimSpace(planVariant["client_auth_type"]))

	if !isFAPI2 {
		if authType == "private_key_jwt" || authType == "self_signed_tls_client_auth" {
			clientJWKS := loadPublicJWKS("client.jwks.json")
			cfg["client"].(map[string]any)["jwks"] = clientJWKS
			cfg["client2"].(map[string]any)["jwks"] = clientJWKS
		}
		if authType == "tls_client_auth" || authType == "self_signed_tls_client_auth" {
			if certPEM, _, err := loadClientMTLSCert(); err == nil {
				cfg["client"].(map[string]any)["certificate"] = certPEM
				cfg["client2"].(map[string]any)["certificate"] = certPEM
			}
			if authType == "tls_client_auth" {
				cfg["client"].(map[string]any)["tls_client_auth_san_dns"] = "client-mtls.localhost"
				cfg["client2"].(map[string]any)["tls_client_auth_san_dns"] = "client-mtls.localhost"
			}
		}
	}

	if requestTypeUsesSignedRequestObject(requestType) {
		clientJWKS := loadPublicJWKS("client.jwks.json")
		cfg["client"].(map[string]any)["jwks"] = clientJWKS
		cfg["client2"].(map[string]any)["jwks"] = clientJWKS
		cfg["client"].(map[string]any)["request_object_signing_alg"] = "PS256"
		cfg["client2"].(map[string]any)["request_object_signing_alg"] = "PS256"
	}

	if authType == "self_signed_tls_client_auth" {
		if jwks, ok := cfg["client"].(map[string]any)["jwks"].(map[string]any); ok {
			cfg["client"].(map[string]any)["jwks"] = appendSelfSignedCertToJWKS(jwks)
		}
	}

	if strings.EqualFold(strings.TrimSpace(requestType), "request_uri") {
		cfg["client"].(map[string]any)["request_uris"] = []string{"https://rp.localhost/request/"}
		cfg["client2"].(map[string]any)["request_uris"] = []string{"https://rp.localhost/request/"}
	}

	if strings.EqualFold(strings.TrimSpace(planVariant["authorization_request_type"]), "rar") {
		cfg["resource"] = map[string]any{
			"authorization_details_types_supported": []string{"account_information"},
		}
	}

	return cfg
}

func buildStandaloneModuleConfig(alias string, planVariant map[string]string, waitTimeoutSeconds int) map[string]any {
	if waitTimeoutSeconds <= 0 {
		waitTimeoutSeconds = 5
	}
	client := map[string]any{
		"client_id":    "local-dev-client",
		"redirect_uri": runtimeRedirectURI(alias),
		"request_type": requestTypeForPlanVariant(planVariant),
		"scope":        strings.Join(scopesForPlanVariant(planVariant), " "),
	}
	if secret := strings.TrimSpace("local-dev-secret-32-bytes-minimum!!"); secret != "" && !strings.EqualFold(strings.TrimSpace(planVariant["client_auth_type"]), "none") {
		client["client_secret"] = secret
	}
	authType := strings.ToLower(strings.TrimSpace(planVariant["client_auth_type"]))
	if authType == "private_key_jwt" || authType == "self_signed_tls_client_auth" {
		client["jwks"] = loadPublicJWKS("client.jwks.json")
	}
	if authType == "tls_client_auth" || authType == "self_signed_tls_client_auth" {
		if certPEM, _, err := loadClientMTLSCert(); err == nil {
			client["certificate"] = certPEM
		}
		if authType == "tls_client_auth" {
			client["tls_client_auth_san_dns"] = "client-mtls.localhost"
		}
	}
	if requestTypeUsesSignedRequestObject(requestTypeForPlanVariant(planVariant)) {
		client["jwks"] = loadPublicJWKS("client.jwks.json")
		client["request_object_signing_alg"] = "PS256"
	}
	if authType == "self_signed_tls_client_auth" {
		if jwks, ok := client["jwks"].(map[string]any); ok {
			client["jwks"] = appendSelfSignedCertToJWKS(jwks)
		}
	}
	if strings.EqualFold(strings.TrimSpace(requestTypeForPlanVariant(planVariant)), "request_uri") {
		client["request_uris"] = []string{"https://rp.localhost/request/"}
	}
	return map[string]any{
		"alias":              alias,
		"client":             client,
		"description":        "Lanyard automated local conformance run",
		"waitTimeoutSeconds": waitTimeoutSeconds,
	}
}

func runtimeRedirectURI(alias string) string {
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" {
		return "https://rp.localhost/callback"
	}
	return "https://rp.localhost/callback/" + url.PathEscape(trimmed)
}

func runtimeClientJWKSURI(alias string) string {
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" {
		return "https://rp.localhost/conformance/jwks/default"
	}
	return "https://rp.localhost/conformance/jwks/" + url.PathEscape(trimmed)
}

func requestTypeUsesSignedRequestObject(requestType string) bool {
	switch strings.ToLower(strings.TrimSpace(requestType)) {
	case "request_object", "request_uri":
		return true
	default:
		return false
	}
}

func requestTypeForPlanVariant(planVariant map[string]string) string {
	if v := strings.TrimSpace(planVariant["request_type"]); v != "" {
		return v
	}

	switch strings.ToLower(strings.TrimSpace(planVariant["fapi_auth_request_method"])) {
	case "pushed":
		return "pushed_authorization_request"
	case "by_value":
		return "plain_http_request"
	}

	switch strings.ToLower(strings.TrimSpace(planVariant["authorization_request_type"])) {
	case "", "simple":
		return "plain_http_request"
	case "par", "pushed_authorization_request":
		return "pushed_authorization_request"
	default:
		return "plain_http_request"
	}
}

func isFAPI2PlanVariant(planVariant map[string]string) bool {
	for key := range planVariant {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "sender_") ||
			lower == "authorization_request_type" ||
			lower == "fapi_profile" {
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

func loadPublicJWKS(filename string) map[string]any {
	jwks := loadJWKS(filename)
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return jwks
	}
	publicKeys := make([]any, 0, len(keys))
	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			publicKeys = append(publicKeys, rawKey)
			continue
		}
		publicKey := make(map[string]any, len(key))
		for k, v := range key {
			switch strings.ToLower(k) {
			case "d", "p", "q", "dp", "dq", "qi", "oth", "k":
				continue
			default:
				publicKey[k] = v
			}
		}
		publicKeys = append(publicKeys, publicKey)
	}
	jwks["keys"] = publicKeys
	return jwks
}

func appendMTLSPublicKeyToJWKS(jwks map[string]any) map[string]any {
	certPEM, _, err := loadClientMTLSCert()
	if err != nil {
		return jwks
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return jwks
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return jwks
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return jwks
	}

	curve := pubKey.Curve
	xC := new(big.Int).Set(pubKey.X)
	yC := new(big.Int).Set(pubKey.Y)

	byteLen := (curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, byteLen)
	yBytes := make([]byte, byteLen)
	xC.FillBytes(xBytes)
	yC.FillBytes(yBytes)

	keyJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": "client-mtls",
		"alg": "ES256",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	keys, _ := jwks["keys"].([]any)
	jwks["keys"] = append(keys, keyJWK)
	return jwks
}

func appendSelfSignedCertToJWKS(jwks map[string]any) map[string]any {
	certPEM, _, err := loadClientMTLSCert()
	if err != nil {
		return jwks
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return jwks
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return jwks
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return jwks
	}
	curve := pubKey.Curve
	byteLen := (curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, byteLen)
	yBytes := make([]byte, byteLen)
	pubKey.X.FillBytes(xBytes)
	pubKey.Y.FillBytes(yBytes)

	x5cEntry := base64.StdEncoding.EncodeToString(cert.Raw)

	keyJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": "client-mtls",
		"alg": "ES256",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		"x5c": []string{x5cEntry},
	}
	keys, _ := jwks["keys"].([]any)
	jwks["keys"] = append(keys, keyJWK)
	return jwks
}

func appendRSAEncryptionKeyToJWKS(jwks map[string]any, kid string, alg string) map[string]any {
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return jwks
	}

	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			continue
		}
		if key["use"] == "enc" && key["alg"] == alg {
			return jwks
		}
	}

	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok || key["kty"] != "RSA" {
			continue
		}
		encKey := make(map[string]any, len(key))
		for k, v := range key {
			encKey[k] = v
		}
		encKey["kid"] = kid
		encKey["use"] = "enc"
		encKey["alg"] = alg
		keys = append(keys, encKey)
		jwks["keys"] = keys
		return jwks
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
