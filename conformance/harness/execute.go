package conformanceharness

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
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
	client      *suiteClient
	cfg         harnessConfig
	logf        func(format string, args ...any)
	frontClient *http.Client
}

func newRunner(client *suiteClient, cfg harnessConfig, logf func(format string, args ...any)) *runner {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if cfg.WaitingMaxRetries <= 0 {
		cfg.WaitingMaxRetries = 10
	}
	if cfg.WaitingRetryInterval <= 0 {
		cfg.WaitingRetryInterval = 10 * time.Second
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		jar = nil
	}

	frontClient := &http.Client{
		Timeout: 45 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		},
	}

	return &runner{client: client, cfg: cfg, logf: logf, frontClient: frontClient}
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

	planVariant := mergePlanVariant(selectPlanVariant(selected), r.cfg.ForcedVariants)
	planConfig := buildPlanConfig(planVariant, fmt.Sprintf("lanyard-%d-%d", time.Now().UTC().UnixNano(), planIndex+1))
	created, err := r.client.CreatePlan(planCtx, selected.Name, planVariant, planConfig)
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

	moduleVariant := mergeModuleVariant(module.Variant, r.cfg.ForcedVariants)
	instance, err := r.client.CreateTestInstance(ctx, module.Name, planID, moduleVariant, nil)
	if err != nil {
		failTest(&res, "ERROR", "FAILED", fmt.Sprintf("create test instance failed: %v", err))
		r.logf("  test failed: plan=%s module=%s alias=%s test_id=%s err=%v", selected.Name, module.Name, alias, instance.ID, err)
		return res
	}
	res.TestID = instance.ID
	testID := instance.ID

	info, err := r.client.GetTestInfo(ctx, testID)
	if err != nil {
		r.logf("  warning: failed to get test info: %v", err)
	}
	suiteAlias := strings.TrimSpace(info.Alias)
	r.logf("  test context: plan=%s module=%s test_id=%s local_alias=%s suite_alias=%s", selected.Name, module.Name, testID, alias, suiteAlias)

	issuer := constructIssuer(r.cfg.SuiteURL, info.PlanID, info.Alias)

	pollCtx, cancel := context.WithTimeout(ctx, r.cfg.TestTimeout)
	defer cancel()

	trigger := r.frontChannelTriggerForModule(module.Name, issuer, moduleVariant)
	pollInfo, err := pollTestResultWithConfig(pollCtx, r.client, testID, trigger, r.cfg.WaitingMaxRetries, r.cfg.WaitingRetryInterval)
	if err != nil {
		cleanupErr := r.cancelTestAndWaitTerminal(testID, selected.Name, module.Name, alias, suiteAlias)
		summary := fmt.Sprintf("poll failed: %v", err)
		if cleanupErr != nil {
			summary = fmt.Sprintf("%s (cleanup failed: %v)", summary, cleanupErr)
		}
		failTest(&res, "ERROR", "FAILED", summary)
		r.logf("  test failed: plan=%s module=%s alias=%s suite_alias=%s test_id=%s err=%v cleanup_err=%v", selected.Name, module.Name, alias, suiteAlias, testID, err, cleanupErr)
		return res
	}

	res.Status = pollInfo.Status
	res.Result = pollInfo.Result
	res.Summary = pollInfo.Summary
	finalizeTest(&res)
	r.logf("  test done: plan=%s module=%s alias=%s suite_alias=%s test_id=%s status=%s result=%s", selected.Name, module.Name, alias, suiteAlias, testID, res.Status, res.Result)
	return res
}

func (r *runner) cancelTestAndWaitTerminal(testID, planName, moduleName, localAlias, suiteAlias string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cancelErr := r.client.CancelTest(cleanupCtx, testID)
	if cancelErr != nil {
		r.logf("  cleanup warning: plan=%s module=%s local_alias=%s suite_alias=%s test_id=%s failed to cancel test: %v", planName, moduleName, localAlias, suiteAlias, testID, cancelErr)
	}

	waitErr := waitForTerminalTestState(cleanupCtx, r.client, testID)
	if waitErr != nil {
		r.logf("  cleanup warning: plan=%s module=%s local_alias=%s suite_alias=%s test_id=%s failed waiting for terminal state: %v", planName, moduleName, localAlias, suiteAlias, testID, waitErr)
	}

	if cancelErr != nil || waitErr != nil {
		return errors.Join(cancelErr, waitErr)
	}

	r.logf("  cleanup done: plan=%s module=%s local_alias=%s suite_alias=%s test_id=%s reached terminal state", planName, moduleName, localAlias, suiteAlias, testID)
	return nil
}

func constructIssuer(suiteURL, planID, testAlias string) string {
	if testAlias == "" {
		return ""
	}
	return strings.TrimRight(suiteURL, "/") + "/test/a/" + testAlias + "/"
}

func (r *runner) triggerFrontChannelStep(ctx context.Context, testID string) error {
	return r.doTrigger(ctx, testID, "/login", "", nil)
}

func (r *runner) frontChannelTriggerForModule(moduleName, issuer string, variant map[string]any) func(context.Context, string) error {
	return func(ctx context.Context, testID string) error {
		endpoint := moduleTriggerEndpoint(moduleName)
		return r.doTrigger(ctx, testID, endpoint, issuer, variant)
	}
}

func (r *runner) doTrigger(ctx context.Context, testID, endpoint, issuer string, variant map[string]any) error {
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

	resp, err := r.frontClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed calling rp front-channel endpoint: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	r.logf("    front-channel trigger: test_id=%s endpoint=%s issuer=%q status=%d", testID, endpoint, issuer, resp.StatusCode)
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
			"redirect_uri":  "https://rp.localhost/callback",
			"request_type":  requestType,
		},
		"client2": map[string]any{
			"client_id":     "local-dev-client-2",
			"client_secret": "local-dev-secret-2-32-bytes-min!!",
			"redirect_uri":  "https://rp.localhost/callback",
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
