package conformanceharness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
