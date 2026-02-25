package conformanceharness

import (
	"context"
	"errors"
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
		return testInfo{ID: tid, Status: "RUNNING", Result: "PASSED"}, nil
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
