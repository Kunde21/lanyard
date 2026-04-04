package conformanceharness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
)

func TestRPRuntimeClient_RegisterAndDelete(t *testing.T) {
	var mu sync.Mutex
	registered := map[string]map[string]any{}
	deleted := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case http.MethodPost:
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("Decode(register payload) failed: %v", err)
			}
			registered[payload["alias"].(string)] = payload
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			deleted = append(deleted, r.URL.Query().Get("alias"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client := newRPRuntimeClient(server.URL)
	cfg := rpRuntimeRequest{Alias: "alias-a", ClientID: "client-a", RedirectURI: "https://rp.localhost/callback"}
	if err := client.Register(context.Background(), cfg); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	if err := client.Delete(context.Background(), cfg.Alias); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := registered[cfg.Alias]; !ok {
		t.Fatalf("runtime alias %q was not registered", cfg.Alias)
	}
	if len(deleted) != 1 || deleted[0] != cfg.Alias {
		t.Fatalf("deleted aliases = %v, want [%q]", deleted, cfg.Alias)
	}
}

func TestJobRunner_RegistersAndDeletesRuntime(t *testing.T) {
	var mu sync.Mutex
	registered := []string{}
	deleted := []string{}

	runtimeClient := &stubRuntimeClient{
		registerFn: func(_ context.Context, req rpRuntimeRequest) error {
			mu.Lock()
			defer mu.Unlock()
			registered = append(registered, req.Alias)
			return nil
		},
		deleteFn: func(_ context.Context, alias string) error {
			mu.Lock()
			defer mu.Unlock()
			deleted = append(deleted, alias)
			return nil
		},
	}

	job := RunJob{
		JobID:    "job-001",
		Alias:    "alias-a",
		PlanName: "plan-a",
		PlanVariant: map[string]string{
			"client_registration": "static_client",
		},
		RPProfile: RPProfileConfig{FAPIProfile: "plain_fapi"},
	}
	jr := newJobRunner(newSuiteClient("https://suite.localhost"), harnessConfig{ArtifactsDir: t.TempDir()}, job, t.Logf)
	jr.runtimeClient = runtimeClient

	cleanup, err := jr.registerRuntime(context.Background())
	if err != nil {
		t.Fatalf("registerRuntime() failed: %v", err)
	}
	cleanup()

	mu.Lock()
	defer mu.Unlock()
	if len(registered) != 1 || registered[0] != job.Alias {
		t.Fatalf("registered aliases = %v, want [%q]", registered, job.Alias)
	}
	if len(deleted) != 1 || deleted[0] != job.Alias {
		t.Fatalf("deleted aliases = %v, want [%q]", deleted, job.Alias)
	}
}

func TestJobRunner_RegisterRuntimeAlias_UsesProvidedAlias(t *testing.T) {
	var got rpRuntimeRequest

	runtimeClient := &stubRuntimeClient{
		registerFn: func(_ context.Context, req rpRuntimeRequest) error {
			got = req
			return nil
		},
		deleteFn: func(_ context.Context, alias string) error {
			return nil
		},
	}

	job := RunJob{
		JobID:    "job-001",
		Alias:    "job-alias",
		PlanName: "plan-a",
		PlanVariant: map[string]string{
			"client_auth_type":           "mtls",
			"sender_constrain":           "mtls",
			"authorization_request_type": "simple",
			"fapi_client_type":           "oidc",
			"fapi_profile":               "plain_fapi",
		},
	}
	jr := newJobRunner(newSuiteClient("https://suite.localhost"), harnessConfig{ArtifactsDir: t.TempDir(), SuiteURL: "https://suite.localhost"}, job, t.Logf)
	jr.runtimeClient = runtimeClient

	if err := jr.registerRuntimeAlias(context.Background(), "suite-alias"); err != nil {
		t.Fatalf("registerRuntimeAlias() failed: %v", err)
	}

	if got.Alias != "suite-alias" {
		t.Fatalf("Alias = %q, want %q", got.Alias, "suite-alias")
	}
	if got.Issuer != "https://suite.localhost/test/a/suite-alias/" {
		t.Fatalf("Issuer = %q, want %q", got.Issuer, "https://suite.localhost/test/a/suite-alias/")
	}
	if got.RedirectURI != "https://rp.localhost/callback/suite-alias" {
		t.Fatalf("RedirectURI = %q, want %q", got.RedirectURI, "https://rp.localhost/callback/suite-alias")
	}
	if got.Namespace != "suite-alias" {
		t.Fatalf("Namespace = %q, want %q", got.Namespace, "suite-alias")
	}
}

func TestJobRunner_RuntimeCleanupDeletesAllRegisteredAliases(t *testing.T) {
	var mu sync.Mutex
	deleted := []string{}

	runtimeClient := &stubRuntimeClient{
		registerFn: func(_ context.Context, req rpRuntimeRequest) error {
			return nil
		},
		deleteFn: func(_ context.Context, alias string) error {
			mu.Lock()
			defer mu.Unlock()
			deleted = append(deleted, alias)
			return nil
		},
	}

	job := RunJob{JobID: "job-001", Alias: "job-alias", PlanName: "plan-a"}
	jr := newJobRunner(newSuiteClient("https://suite.localhost"), harnessConfig{ArtifactsDir: t.TempDir(), SuiteURL: "https://suite.localhost"}, job, t.Logf)
	jr.runtimeClient = runtimeClient

	cleanup, err := jr.registerRuntime(context.Background())
	if err != nil {
		t.Fatalf("registerRuntime() failed: %v", err)
	}
	if err := jr.registerRuntimeAlias(context.Background(), "suite-alias"); err != nil {
		t.Fatalf("registerRuntimeAlias() failed: %v", err)
	}
	cleanup()

	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 2 {
		t.Fatalf("deleted aliases = %v, want 2 aliases", deleted)
	}
	seen := map[string]bool{}
	for _, alias := range deleted {
		seen[alias] = true
	}
	if !seen["job-alias"] || !seen["suite-alias"] {
		t.Fatalf("deleted aliases = %v, want both job and suite aliases", deleted)
	}
}

type stubRuntimeClient struct {
	registerFn func(context.Context, rpRuntimeRequest) error
	deleteFn   func(context.Context, string) error
}

func (s *stubRuntimeClient) Register(ctx context.Context, req rpRuntimeRequest) error {
	return s.registerFn(ctx, req)
}

func (s *stubRuntimeClient) Delete(ctx context.Context, alias string) error {
	return s.deleteFn(ctx, alias)
}

func TestBuildRPRuntimeRequest_PlainOAuthOmitsOpenIDScope(t *testing.T) {
	job := RunJob{Alias: "alias-a", PlanName: "fapi2-security-profile-final-client-test-plan"}
	req := buildRPRuntimeRequest(job, map[string]string{
		"client_auth_type":           "private_key_jwt",
		"sender_constrain":           "dpop",
		"authorization_request_type": "simple",
		"fapi_client_type":           "plain_oauth",
		"fapi_profile":               "plain_fapi",
	}, "https://suite.localhost")

	if slices.Contains(req.Scopes, "openid") {
		t.Fatalf("Scopes = %v, must not contain openid for plain_oauth", req.Scopes)
	}
}

func TestResponseModeForPlan(t *testing.T) {
	tests := []struct {
		planName string
		want     string
	}{
		{planName: "oidcc-client-formpost-basic-certification-test-plan", want: "form_post"},
		{planName: "OIDCC-CLIENT-FORMPOST-BASIC-CERTIFICATION-TEST-PLAN", want: "form_post"},
		{planName: "oidcc-client-basic-certification-test-plan", want: ""},
		{planName: "fapi2-security-profile-final-client-test-plan", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.planName, func(t *testing.T) {
			got := responseModeForPlan(tc.planName)
			if got != tc.want {
				t.Fatalf("responseModeForPlan() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildRPRuntimeRequest_FormPostIncludesResponseMode(t *testing.T) {
	job := RunJob{Alias: "alias-a", PlanName: "oidcc-client-formpost-basic-certification-test-plan"}
	req := buildRPRuntimeRequest(job, map[string]string{
		"client_registration": "static_client",
	}, "https://suite.localhost")

	if req.ResponseMode != "form_post" {
		t.Fatalf("ResponseMode = %q, want %q", req.ResponseMode, "form_post")
	}
}

func TestBuildRPRuntimeRequest_BasicExcludesResponseMode(t *testing.T) {
	job := RunJob{Alias: "alias-a", PlanName: "oidcc-client-basic-certification-test-plan"}
	req := buildRPRuntimeRequest(job, map[string]string{
		"client_registration": "static_client",
	}, "https://suite.localhost")

	if req.ResponseMode != "" {
		t.Fatalf("ResponseMode = %q, want empty", req.ResponseMode)
	}
}
