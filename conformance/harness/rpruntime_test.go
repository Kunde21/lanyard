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

func TestBuildRPRuntimeRequest_MessageSigningFields(t *testing.T) {
	job := RunJob{Alias: "alias-a", PlanName: "fapi2-message-signing-final-client-test-plan"}
	req := buildRPRuntimeRequest(job, map[string]string{
		"client_auth_type":           "private_key_jwt",
		"sender_constrain":           "dpop",
		"authorization_request_type": "simple",
		"fapi_client_type":           "oidc",
		"fapi_profile":               "plain_fapi",
		"fapi_request_method":        "signed_non_repudiation",
		"fapi_response_mode":         "jarm",
	}, "https://suite.localhost")

	if req.FAPIRequestMethod != "signed_non_repudiation" {
		t.Fatalf("FAPIRequestMethod = %q, want %q", req.FAPIRequestMethod, "signed_non_repudiation")
	}
	if req.FAPIResponseMode != "jarm" {
		t.Fatalf("FAPIResponseMode = %q, want %q", req.FAPIResponseMode, "jarm")
	}
	if req.ResponseMode != "query.jwt" {
		t.Fatalf("ResponseMode = %q, want %q (query.jwt for JARM)", req.ResponseMode, "query.jwt")
	}
}

func TestResponseModeForVariant(t *testing.T) {
	tests := []struct {
		name    string
		variant map[string]string
		want    string
	}{
		{name: "jarm", variant: map[string]string{"fapi_response_mode": "jarm"}, want: "query.jwt"},
		{name: "plain_response", variant: map[string]string{"fapi_response_mode": "plain_response"}, want: ""},
		{name: "empty", variant: map[string]string{}, want: ""},
		{name: "missing key", variant: nil, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := responseModeForVariant(tc.variant)
			if got != tc.want {
				t.Fatalf("responseModeForVariant() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCoalesceResponseMode(t *testing.T) {
	tests := []struct {
		name        string
		planMode    string
		variantMode string
		want        string
	}{
		{name: "variant overrides plan", planMode: "form_post", variantMode: "query.jwt", want: "query.jwt"},
		{name: "plan used when variant empty", planMode: "form_post", variantMode: "", want: "form_post"},
		{name: "both empty", planMode: "", variantMode: "", want: ""},
		{name: "only variant set", planMode: "", variantMode: "query.jwt", want: "query.jwt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := coalesceResponseMode(tc.planMode, tc.variantMode)
			if got != tc.want {
				t.Fatalf("coalesceResponseMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequirePARForVariant(t *testing.T) {
	tests := []struct {
		name    string
		variant map[string]string
		want    bool
	}{
		{name: "fapi1 pushed requires PAR", variant: map[string]string{"fapi_auth_request_method": "pushed"}, want: true},
		{name: "fapi1 by_value no PAR", variant: map[string]string{"fapi_auth_request_method": "by_value"}, want: false},
		{name: "fapi2 without fapi_auth_request_method uses heuristic", variant: map[string]string{"client_auth_type": "private_key_jwt", "fapi_profile": "plain_fapi"}, want: true},
		{name: "oidc no PAR", variant: map[string]string{"client_registration": "static_client"}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := requirePARForVariant(tc.variant)
			if got != tc.want {
				t.Fatalf("requirePARForVariant() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildRPRuntimeRequest_FAPI1AdvancedByValue(t *testing.T) {
	job := RunJob{Alias: "alias-a", PlanName: "fapi1-advanced-final-client-test-plan"}
	req := buildRPRuntimeRequest(job, map[string]string{
		"client_auth_type":         "private_key_jwt",
		"fapi_auth_request_method": "by_value",
		"fapi_client_type":         "oidc",
		"fapi_profile":             "plain_fapi",
		"fapi_response_mode":       "plain_response",
		"sender_constrain":         "mtls",
	}, "https://suite.localhost")

	if req.RequirePAR {
		t.Fatalf("RequirePAR = true, want false for by_value")
	}
	if req.RequestType != "plain_http_request" {
		t.Fatalf("RequestType = %q, want %q", req.RequestType, "plain_http_request")
	}
	if req.ResponseType != "code id_token" {
		t.Fatalf("ResponseType = %q, want %q", req.ResponseType, "code id_token")
	}
	if req.FAPIRequestMethod != "signed_non_repudiation" {
		t.Fatalf("FAPIRequestMethod = %q, want %q", req.FAPIRequestMethod, "signed_non_repudiation")
	}
}

func TestBuildRPRuntimeRequest_FAPI1AdvancedPushed(t *testing.T) {
	job := RunJob{Alias: "alias-a", PlanName: "fapi1-advanced-final-client-test-plan"}
	req := buildRPRuntimeRequest(job, map[string]string{
		"client_auth_type":         "private_key_jwt",
		"fapi_auth_request_method": "pushed",
		"fapi_client_type":         "oidc",
		"fapi_profile":             "plain_fapi",
		"fapi_response_mode":       "plain_response",
		"sender_constrain":         "mtls",
	}, "https://suite.localhost")

	if !req.RequirePAR {
		t.Fatalf("RequirePAR = false, want true for pushed")
	}
	if req.RequestType != "pushed_authorization_request" {
		t.Fatalf("RequestType = %q, want %q", req.RequestType, "pushed_authorization_request")
	}
	if req.ResponseType != "code id_token" {
		t.Fatalf("ResponseType = %q, want %q", req.ResponseType, "code id_token")
	}
	if req.FAPIRequestMethod != "signed_non_repudiation" {
		t.Fatalf("FAPIRequestMethod = %q, want %q", req.FAPIRequestMethod, "signed_non_repudiation")
	}
}
