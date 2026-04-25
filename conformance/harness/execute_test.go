package conformanceharness

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockSuiteClient struct {
	mu        sync.Mutex
	testInfos map[string]testInfo
	callCount map[string]int
	onGetInfo func(testID string) (testInfo, error)
	onStart   func(testID string) error
}

func newMockSuiteClient() *mockSuiteClient {
	return &mockSuiteClient{
		testInfos: make(map[string]testInfo),
		callCount: make(map[string]int),
	}
}

func (m *mockSuiteClient) GetTestInfo(ctx context.Context, testID string) (testInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount[testID]++

	if m.onGetInfo != nil {
		return m.onGetInfo(testID)
	}

	info, ok := m.testInfos[testID]
	if !ok {
		return testInfo{}, errors.New("test not found")
	}
	return info, nil
}

func (m *mockSuiteClient) StartTest(ctx context.Context, testID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.onStart != nil {
		return m.onStart(testID)
	}
	return nil
}

func (m *mockSuiteClient) setTestInfo(testID string, info testInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.testInfos[testID] = info
}

func (m *mockSuiteClient) getCallCount(testID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount[testID]
}

func TestPollTestResultRetriesOnWaiting(t *testing.T) {
	client := newMockSuiteClient()
	testID := "test-waiting-retry"

	client.setTestInfo(testID, testInfo{ID: testID, Status: "WAITING", Result: ""})

	triggerCount := 0
	trigger := func(ctx context.Context, tid string) error {
		triggerCount++
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := pollTestResultWithConfig(ctx, client, testID, trigger, 3, 50*time.Millisecond)

	if err == nil {
		t.Fatal("expected timeout error")
	}

	if triggerCount == 0 {
		t.Error("expected at least one trigger attempt")
	}

	if triggerCount > 4 {
		t.Errorf("expected at most 4 trigger attempts (initial + 3 retries), got %d", triggerCount)
	}
}

func TestPollTestResultProgressesFromWaiting(t *testing.T) {
	client := newMockSuiteClient()
	testID := "test-waiting-progress"

	var mu sync.Mutex
	state := "WAITING"

	client.onGetInfo = func(tid string) (testInfo, error) {
		mu.Lock()
		defer mu.Unlock()
		if state == "WAITING" {
			return testInfo{ID: tid, Status: "WAITING", Result: ""}, nil
		}
		return testInfo{ID: tid, Status: "FINISHED", Result: "PASSED"}, nil
	}

	triggerCount := 0
	trigger := func(ctx context.Context, tid string) error {
		triggerCount++
		mu.Lock()
		state = "FINISHED"
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := pollTestResultWithConfig(ctx, client, testID, trigger, 3, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Status != "FINISHED" {
		t.Errorf("expected status FINISHED, got %s", info.Status)
	}

	if info.Result != "PASSED" {
		t.Errorf("expected result PASSED, got %s", info.Result)
	}

	if triggerCount == 0 {
		t.Error("expected at least one trigger attempt")
	}
}

func TestPollTestResultStartsConfiguredTest(t *testing.T) {
	client := newMockSuiteClient()
	testID := "test-configured"

	var startCalled bool
	var mu sync.Mutex
	callCount := 0

	client.onGetInfo = func(tid string) (testInfo, error) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		if callCount == 1 {
			return testInfo{ID: tid, Status: "CONFIGURED", Result: ""}, nil
		}
		return testInfo{ID: tid, Status: "FINISHED", Result: "PASSED"}, nil
	}
	client.onStart = func(tid string) error {
		startCalled = true
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := pollTestResultWithConfig(ctx, client, testID, nil, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !startCalled {
		t.Error("expected StartTest to be called for CONFIGURED test")
	}
}

func TestPollTestResultReturnsErrorOnTriggerFailure(t *testing.T) {
	client := newMockSuiteClient()
	testID := "test-trigger-error"

	triggerErr := errors.New("trigger failed")
	triggerCalled := false

	client.onGetInfo = func(tid string) (testInfo, error) {
		return testInfo{ID: tid, Status: "WAITING", Result: ""}, nil
	}

	trigger := func(ctx context.Context, tid string) error {
		triggerCalled = true
		return triggerErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := pollTestResultWithConfig(ctx, client, testID, trigger, 1, 100*time.Millisecond)

	if err == nil {
		t.Fatal("expected error from trigger failure")
	}

	if !triggerCalled {
		t.Error("expected trigger to be called")
	}

	if !strings.Contains(err.Error(), "trigger failed") && !strings.Contains(err.Error(), "did not progress") {
		t.Errorf("expected error containing 'trigger failed' or 'did not progress', got: %v", err)
	}
}

func TestIsTerminalStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{name: "finished", status: "FINISHED", want: true},
		{name: "interrupted", status: "INTERRUPTED", want: true},
		{name: "cancelled", status: "CANCELLED", want: true},
		{name: "running", status: "RUNNING", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isTerminalStatus(testInfo{Status: tc.status})
			if got != tc.want {
				t.Fatalf("isTerminalStatus(%q) = %t, want %t", tc.status, got, tc.want)
			}
		})
	}
}

func TestRequestTypeForPlanVariant(t *testing.T) {
	tests := []struct {
		name    string
		variant map[string]string
		want    string
	}{
		{
			name:    "explicit request type wins",
			variant: map[string]string{"request_type": "custom"},
			want:    "custom",
		},
		{
			name:    "simple maps to plain http request",
			variant: map[string]string{"authorization_request_type": "simple"},
			want:    "plain_http_request",
		},
		{
			name:    "par maps to pushed authorization request",
			variant: map[string]string{"authorization_request_type": "par"},
			want:    "pushed_authorization_request",
		},
		{
			name:    "fapi_auth_request_method pushed",
			variant: map[string]string{"fapi_auth_request_method": "pushed"},
			want:    "pushed_authorization_request",
		},
		{
			name:    "fapi_auth_request_method by_value",
			variant: map[string]string{"fapi_auth_request_method": "by_value"},
			want:    "plain_http_request",
		},
		{
			name:    "fapi_auth_request_method takes precedence over authorization_request_type",
			variant: map[string]string{"fapi_auth_request_method": "pushed", "authorization_request_type": "simple"},
			want:    "pushed_authorization_request",
		},
		{
			name:    "default is plain http request",
			variant: map[string]string{},
			want:    "plain_http_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := requestTypeForPlanVariant(tc.variant)
			if got != tc.want {
				t.Fatalf("requestTypeForPlanVariant() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectiveSuiteAlias_FallsBackToJobAlias(t *testing.T) {
	if got := effectiveSuiteAlias("", "job-alias"); got != "job-alias" {
		t.Fatalf("effectiveSuiteAlias() = %q, want %q", got, "job-alias")
	}
	if got := effectiveSuiteAlias("suite-alias", "job-alias"); got != "suite-alias" {
		t.Fatalf("effectiveSuiteAlias() = %q, want %q", got, "suite-alias")
	}
}

func TestFrontChannelTriggerStatusError_IncludesBody(t *testing.T) {
	err := frontChannelTriggerStatusError(500, "runtime missing")
	if err == nil {
		t.Fatal("expected error for failing front-channel status")
	}
	if !strings.Contains(err.Error(), "status=500") {
		t.Fatalf("error = %q, want status detail", err)
	}
	if !strings.Contains(err.Error(), "runtime missing") {
		t.Fatalf("error = %q, want body detail", err)
	}

	if err := frontChannelTriggerStatusError(302, "redirect"); err != nil {
		t.Fatalf("expected nil for redirect status, got %v", err)
	}
}

func TestFrontChannelTriggerStatusErrorForModule_NegativeTests(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		moduleName string
		wantErr    bool
	}{
		{
			name:       "negative test with 400 returns nil",
			statusCode: 400,
			moduleName: "fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails",
			wantErr:    false,
		},
		{
			name:       "negative test with 200 returns nil",
			statusCode: 200,
			moduleName: "fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails",
			wantErr:    false,
		},
		{
			name:       "positive test with 400 returns error",
			statusCode: 400,
			moduleName: "fapi2-security-profile-final-client-test-happy-path",
			wantErr:    true,
		},
		{
			name:       "positive test with 200 returns nil",
			statusCode: 200,
			moduleName: "fapi2-security-profile-final-client-test-happy-path",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := frontChannelTriggerStatusErrorForModule(tt.statusCode, "test body", tt.moduleName)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected nil, got error: %v", err)
			}
		})
	}
}

func TestExecuteBrowserVisit_ReportsEachVisitedURL(t *testing.T) {
	ctx := context.Background()

	var browserServer *httptest.Server
	browserServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, browserServer.URL+"/middle", http.StatusFound)
		case "/middle":
			http.Redirect(w, r, browserServer.URL+"/done", http.StatusFound)
		case "/done":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer browserServer.Close()

	visitedMu := sync.Mutex{}
	visited := []string{}
	suiteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/api/runner/browser/test-id/visit") {
			http.NotFound(w, r)
			return
		}
		visitedMu.Lock()
		visited = append(visited, r.URL.Query().Get("url"))
		visitedMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer suiteServer.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() failed: %v", err)
	}

	jr := &jobRunner{
		client:      newSuiteClient(suiteServer.URL),
		frontClient: &http.Client{Jar: jar, Timeout: 5 * time.Second},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, browserServer.URL+"/start", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() failed: %v", err)
	}

	resp, finalURL, err := jr.executeBrowserVisit(ctx, "test-id", req)
	if err != nil {
		t.Fatalf("executeBrowserVisit() failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if finalURL != browserServer.URL+"/done" {
		t.Fatalf("finalURL = %q, want %q", finalURL, browserServer.URL+"/done")
	}

	visitedMu.Lock()
	defer visitedMu.Unlock()
	want := []string{
		browserServer.URL + "/start",
		browserServer.URL + "/middle",
		browserServer.URL + "/done",
	}
	if !reflect.DeepEqual(visited, want) {
		t.Fatalf("visited URLs mismatch\n got: %v\nwant: %v", visited, want)
	}
}

func TestNewJobRunner_IsolatesMutableExecutionState(t *testing.T) {
	cfg := harnessConfig{ArtifactsDir: t.TempDir()}
	client := newSuiteClient("https://suite.localhost")

	jobA := RunJob{JobID: "job-a", Alias: "alias-a", PlanName: "plan-a"}
	jobB := RunJob{JobID: "job-b", Alias: "alias-b", PlanName: "plan-b"}

	runnerA := newJobRunner(client, cfg, jobA, t.Logf)
	runnerB := newJobRunner(client, cfg, jobB, t.Logf)

	if runnerA.frontClient == runnerB.frontClient {
		t.Fatal("job runners unexpectedly share front-channel HTTP client")
	}
	if runnerA.frontClient.Jar == runnerB.frontClient.Jar {
		t.Fatal("job runners unexpectedly share cookie jar")
	}
	if runnerA.job.Alias == runnerB.job.Alias {
		t.Fatal("job runners unexpectedly share alias")
	}

	wantA := filepath.Join(cfg.ArtifactsDir, "jobs", jobA.JobID)
	wantB := filepath.Join(cfg.ArtifactsDir, "jobs", jobB.JobID)
	if runnerA.artifactDir != wantA {
		t.Fatalf("runnerA artifactDir = %q, want %q", runnerA.artifactDir, wantA)
	}
	if runnerB.artifactDir != wantB {
		t.Fatalf("runnerB artifactDir = %q, want %q", runnerB.artifactDir, wantB)
	}
}

func TestBuildPlanConfig_RARAddsAuthorizationDetailsTypesSupported(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":           "private_key_jwt",
		"authorization_request_type": "rar",
		"fapi_client_type":           "plain_oauth",
		"fapi_profile":               "plain_fapi",
	}, "alias-a", 5)

	resource, ok := cfg["resource"].(map[string]any)
	if !ok {
		t.Fatalf("resource config missing: %#v", cfg["resource"])
	}
	if _, ok := resource["authorization_details_types_supported"]; !ok {
		t.Fatalf("authorization_details_types_supported missing: %#v", resource)
	}
}

func TestBuildPlanConfig_FAPI1EncryptedIDTokenClientMetadata(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":         "private_key_jwt",
		"fapi_auth_request_method": "by_value",
		"fapi_request_method":      "signed_non_repudiation",
		"fapi_client_type":         "oidc",
		"fapi_profile":             "plain_fapi",
		"fapi_response_mode":       "plain_response",
		"sender_constrain":         "mtls",
	}, "alias-a", 5)

	client2, ok := cfg["client2"].(map[string]any)
	if !ok {
		t.Fatalf("client2 config missing: %#v", cfg["client2"])
	}
	if got := client2["id_token_encrypted_response_alg"]; got != "RSA-OAEP-256" {
		t.Fatalf("id_token_encrypted_response_alg = %#v, want %q", got, "RSA-OAEP-256")
	}
	if got := client2["id_token_encrypted_response_enc"]; got != "A256GCM" {
		t.Fatalf("id_token_encrypted_response_enc = %#v, want %q", got, "A256GCM")
	}

	jwks, ok := client2["jwks"].(map[string]any)
	if !ok {
		t.Fatalf("client2 jwks missing: %#v", client2["jwks"])
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		t.Fatalf("client2 jwks keys missing: %#v", jwks["keys"])
	}
	foundEncKey := false
	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			continue
		}
		if key["use"] == "enc" && key["alg"] == "RSA-OAEP-256" {
			foundEncKey = true
			break
		}
	}
	if !foundEncKey {
		t.Fatal("client2 jwks must contain an RSA encryption key")
	}
}

func TestMergeFragmentIntoQuery(t *testing.T) {
	nextURL, err := url.Parse("https://rp.localhost/callback#code=abc&state=xyz")
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}

	merged := mergeFragmentIntoQuery(nextURL)
	if merged == nil {
		t.Fatal("mergeFragmentIntoQuery() returned nil")
	}
	if got := merged.RawQuery; got != "code=abc&state=xyz" {
		t.Fatalf("RawQuery = %q, want %q", got, "code=abc&state=xyz")
	}
	if merged.Fragment != "" {
		t.Fatalf("Fragment = %q, want empty", merged.Fragment)
	}
}

func TestIsNegativeTestModule(t *testing.T) {
	fapi1Negatives := []string{
		"fapi1-advanced-final-client-test-invalid-shash",
		"fapi1-advanced-final-client-test-invalid-chash",
		"fapi1-advanced-final-client-test-invalid-nonce",
		"fapi1-advanced-final-client-test-invalid-missing-exp",
		"fapi1-advanced-final-client-test-iat-is-week-in-past",
	}
	for _, name := range fapi1Negatives {
		t.Run("negative/"+name, func(t *testing.T) {
			if !isNegativeTestModule(name) {
				t.Errorf("isNegativeTestModule(%q) = false, want true", name)
			}
		})
	}

	nonNegatives := []string{
		"fapi1-advanced-final-client-test-happy-clients",
		"fapi1-advanced-final-client-test-code-id-token-client1",
		"fapi2-security-profile-final-client-test-happy-clients",
		"oidcc-client-test",
	}
	for _, name := range nonNegatives {
		t.Run("non_negative/"+name, func(t *testing.T) {
			if isNegativeTestModule(name) {
				t.Errorf("isNegativeTestModule(%q) = true, want false", name)
			}
		})
	}
}

func TestBuildPlanConfig_OIDCConfigPrivateKeyJWT(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":    "private_key_jwt",
		"request_type":        "plain_http_request",
		"client_registration": "static_client",
		"response_mode":       "default",
	}, "alias-test", 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	if _, hasJWKS := client["jwks"]; !hasJWKS {
		t.Fatal("client.jwks missing for private_key_jwt auth type")
	}
	client2, ok := cfg["client2"].(map[string]any)
	if !ok {
		t.Fatal("client2 config missing")
	}
	if _, hasJWKS := client2["jwks"]; !hasJWKS {
		t.Fatal("client2.jwks missing for private_key_jwt auth type")
	}
}

func TestBuildPlanConfig_OIDCConfigClientSecretBasic_NoJWKS(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":    "client_secret_basic",
		"request_type":        "plain_http_request",
		"client_registration": "static_client",
		"response_mode":       "default",
	}, "alias-test", 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	if _, hasJWKS := client["jwks"]; hasJWKS {
		t.Fatal("client.jwks should not be present for client_secret_basic auth type")
	}
}

func TestBuildStandaloneModuleConfig_UsesMinimalClientConfig(t *testing.T) {
	cfg := buildStandaloneModuleConfig("alias-test", map[string]string{
		"client_auth_type": "client_secret_basic",
		"request_type":     "plain_http_request",
	}, 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	if _, ok := client["client_id"]; !ok {
		t.Fatal("client_id missing")
	}
	if _, ok := client["client_secret"]; !ok {
		t.Fatal("client_secret missing")
	}
	if _, ok := cfg["client2"]; ok {
		t.Fatal("client2 must not be present in standalone module config")
	}
	if got := cfg["waitTimeoutSeconds"]; got != 5 {
		t.Fatalf("waitTimeoutSeconds = %#v, want 5", got)
	}
}

func TestBuildStandaloneModuleConfig_OmitsSecretForPublicClient(t *testing.T) {
	cfg := buildStandaloneModuleConfig("alias-test", map[string]string{
		"client_auth_type": "none",
	}, 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	if _, ok := client["client_secret"]; ok {
		t.Fatal("client_secret must not be present for public client")
	}
}

func TestFrontChannelTriggerNotUsedForDiscoveryModule(t *testing.T) {
	modules := []struct {
		name   string
		action string
	}{
		{"oidcc-client-test-discovery-openid-config", "discovery_only"},
		{"oidcc-client-test-discovery-webfinger-acct", "discovery_only"},
		{"oidcc-client-test-discovery-webfinger-url", "discovery_only"},
		{"oidcc-client-test-discovery-issuer-mismatch", "discovery_only"},
		{"oidcc-client-test-discovery-jwks-uri-keys", "discovery_and_jwks"},
	}
	for _, m := range modules {
		t.Run(m.name, func(t *testing.T) {
			action := startupActionForModule(m.name)
			if action != m.action {
				t.Fatalf("startupActionForModule(%q) = %q, want %q", m.name, action, m.action)
			}
			if action == "full_flow" {
				t.Fatalf("discovery module %q should not use full_flow", m.name)
			}
		})
	}
}

func TestExecuteModule_DiscoveryModulesSkipFrontChannelTrigger(t *testing.T) {
	tests := []struct {
		name            string
		moduleName      string
		expectNoTrigger bool
	}{
		{"discovery-openid-config skips trigger", "oidcc-client-test-discovery-openid-config", true},
		{"discovery-webfinger-acct skips trigger", "oidcc-client-test-discovery-webfinger-acct", true},
		{"discovery-webfinger-url skips trigger", "oidcc-client-test-discovery-webfinger-url", true},
		{"discovery-issuer-mismatch skips trigger", "oidcc-client-test-discovery-issuer-mismatch", true},
		{"discovery-jwks-uri-keys skips trigger", "oidcc-client-test-discovery-jwks-uri-keys", true},
		{"client-secret-basic uses trigger", "oidcc-client-test-client-secret-basic", false},
		{"userinfo-bearer-body uses trigger", "oidcc-client-test-userinfo-bearer-body", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := startupActionForModule(tt.moduleName)
			skipsTrigger := action != "full_flow"
			if skipsTrigger != tt.expectNoTrigger {
				t.Fatalf("startupActionForModule(%q) = %q, skipsTrigger=%v, want skipsTrigger=%v",
					tt.moduleName, action, skipsTrigger, tt.expectNoTrigger)
			}
		})
	}
}

func TestExecuteModule_DiscoveryModuleKeepsPlanAssociation(t *testing.T) {
	var gotPlanID string
	var gotTestName string
	runtimeRegistered := false

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/runner":
			gotPlanID = r.URL.Query().Get("plan")
			gotTestName = r.URL.Query().Get("test")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"test-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/info/test-1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"test-1","status":"FINISHED","result":"PASSED","alias":"suite-alias"}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer ts.Close()

	client := newSuiteClient(ts.URL)
	client.http = ts.Client()

	job := RunJob{
		JobID:    "job-001",
		Alias:    "job-alias",
		PlanName: "oidcc-client-config-certification-test-plan",
		PlanVariant: map[string]string{
			"client_auth_type":    "none",
			"request_type":        "request_uri",
			"client_registration": "static_client",
			"response_mode":       "form_post",
		},
	}

	jr := newJobRunner(client, harnessConfig{ArtifactsDir: t.TempDir(), SuiteURL: "https://suite.localhost", TestTimeout: 2 * time.Second}, job, t.Logf)
	jr.runtimeClient = &stubRuntimeClient{
		registerFn: func(_ context.Context, req rpRuntimeRequest) (rpRuntimeResponse, error) {
			runtimeRegistered = true
			if req.StartupAction != "discovery_only" {
				t.Fatalf("StartupAction = %q, want %q", req.StartupAction, "discovery_only")
			}
			return rpRuntimeResponse{}, nil
		},
		deleteFn: func(context.Context, string) error {
			return nil
		},
	}

	res := jr.executeModule(context.Background(), PlanModule{Name: "oidcc-client-test-discovery-openid-config"}, "plan-123", 0)

	if gotTestName != "oidcc-client-test-discovery-openid-config" {
		t.Fatalf("test name = %q, want %q", gotTestName, "oidcc-client-test-discovery-openid-config")
	}
	if gotPlanID != "plan-123" {
		t.Fatalf("plan id = %q, want %q", gotPlanID, "plan-123")
	}
	if !runtimeRegistered {
		t.Fatal("expected runtime registration")
	}
	if res.Status != "FINISHED" {
		t.Fatalf("status = %q, want %q", res.Status, "FINISHED")
	}
	if res.Result != "PASSED" {
		t.Fatalf("result = %q, want %q", res.Result, "PASSED")
	}
}

func TestBuildPlanConfig_OIDCConfigSelfSignedTlsClientAuth_ContainsX5C(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":    "self_signed_tls_client_auth",
		"request_type":        "plain_http_request",
		"client_registration": "static_client",
		"response_mode":       "default",
	}, "alias-test", 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	jwks, ok := client["jwks"].(map[string]any)
	if !ok {
		t.Fatal("client.jwks missing")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	foundX5C := false
	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			continue
		}
		if x5cRaw, ok := key["x5c"]; ok {
			var x5c []string
			switch v := x5cRaw.(type) {
			case []string:
				x5c = v
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						x5c = append(x5c, s)
					}
				}
			}
			if len(x5c) > 0 {
				foundX5C = true
				if key["kid"] != "client-mtls" {
					t.Errorf("x5c key kid = %q, want %q", key["kid"], "client-mtls")
				}
				if key["kty"] != "EC" {
					t.Errorf("x5c key kty = %q, want %q", key["kty"], "EC")
				}
				break
			}
		}
	}
	if !foundX5C {
		t.Fatal("no JWK with x5c found in client.jwks")
	}
}

func TestBuildPlanConfig_OIDCConfigSelfSignedTlsClientAuth_RequestObject_ContainsX5C(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":    "self_signed_tls_client_auth",
		"request_type":        "request_object",
		"client_registration": "static_client",
		"response_mode":       "default",
	}, "alias-test", 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	jwks, ok := client["jwks"].(map[string]any)
	if !ok {
		t.Fatal("client.jwks missing")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	foundX5C := false
	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			continue
		}
		if x5cRaw, ok := key["x5c"]; ok {
			var x5c []string
			switch v := x5cRaw.(type) {
			case []string:
				x5c = v
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						x5c = append(x5c, s)
					}
				}
			}
			if len(x5c) > 0 {
				foundX5C = true
				break
			}
		}
	}
	if !foundX5C {
		t.Fatal("no JWK with x5c found in client.jwks for request_object variant")
	}
}

func TestBuildPlanConfig_OIDCConfigPrivateKeyJWT_NoX5C(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":    "private_key_jwt",
		"request_type":        "plain_http_request",
		"client_registration": "static_client",
		"response_mode":       "default",
	}, "alias-test", 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	jwks, ok := client["jwks"].(map[string]any)
	if !ok {
		t.Fatal("client.jwks missing")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := key["x5c"]; ok {
			t.Fatal("x5c should not be present for private_key_jwt auth type")
		}
	}
}

func TestBuildStandaloneModuleConfig_SelfSignedTlsClientAuth_ContainsX5C(t *testing.T) {
	cfg := buildStandaloneModuleConfig("alias-test", map[string]string{
		"client_auth_type": "self_signed_tls_client_auth",
		"request_type":     "plain_http_request",
	}, 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	jwks, ok := client["jwks"].(map[string]any)
	if !ok {
		t.Fatal("client.jwks missing")
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		t.Fatal("jwks keys missing")
	}

	foundX5C := false
	for _, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			continue
		}
		if x5cRaw, ok := key["x5c"]; ok {
			var x5c []string
			switch v := x5cRaw.(type) {
			case []string:
				x5c = v
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						x5c = append(x5c, s)
					}
				}
			}
			if len(x5c) > 0 {
				foundX5C = true
				break
			}
		}
	}
	if !foundX5C {
		t.Fatal("no JWK with x5c found in client.jwks")
	}
}
