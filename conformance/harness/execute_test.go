package conformanceharness

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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

func TestModuleTriggerEndpoint(t *testing.T) {
	tests := []struct {
		moduleName string
		want       string
	}{
		{
			moduleName: "oidcc-client-test-discovery-openid-config",
			want:       "/discovery",
		},
		{
			moduleName: "oidcc-client-test-discovery-jwks-uri-keys",
			want:       "/discovery-jwks",
		},
		{
			moduleName: "oidcc-client-test-discovery-issuer-mismatch",
			want:       "/discovery",
		},
		{
			moduleName: "oidcc-client-test-discovery-webfinger-acct",
			want:       "/webfinger-acct",
		},
		{
			moduleName: "oidcc-client-test-discovery-webfinger-url",
			want:       "/webfinger-url",
		},
		{
			moduleName: "oidcc-client-test-client-secret-basic",
			want:       "/login",
		},
		{
			moduleName: "oidcc-client-test-userinfo-bearer-body",
			want:       "/login-userinfo-body",
		},
		{
			moduleName: "some-other-module",
			want:       "/login",
		},
	}

	for _, tc := range tests {
		t.Run(tc.moduleName, func(t *testing.T) {
			got := moduleTriggerEndpoint(tc.moduleName)
			if got != tc.want {
				t.Errorf("moduleTriggerEndpoint(%q) = %q, want %q", tc.moduleName, got, tc.want)
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
