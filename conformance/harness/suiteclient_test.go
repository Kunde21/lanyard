package conformanceharness

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAvailablePlansModules(t *testing.T) {
	raw := []byte(`[
	  {
	    "name": "plan-string-modules",
	    "modules": ["alpha", "beta"]
	  },
	  {
	    "planName": "plan-object-modules",
	    "modules": [
	      {"testModule": "gamma", "variant": {"foo": "bar"}},
	      {"module": "delta"}
	    ]
	  }
	]`)
	plans, err := parseAvailablePlans(raw)
	if err != nil {
		t.Fatalf("parseAvailablePlans() failed: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("expected 2 plans, got %d", len(plans))
	}
	if len(plans[0].Modules) != 2 {
		t.Fatalf("expected 2 modules for first plan, got %d", len(plans[0].Modules))
	}
	if plans[1].Modules[0].Variant == nil {
		t.Fatalf("expected variant for module")
	}
}

func TestParseVariantsHandlesValues(t *testing.T) {
	raw := []byte(`[
	  {
	    "name": "with-variants",
	    "variants": {
	      "mode": {
	        "variantValues": {"one": {}, "two": {}}
	      }
	    }
	  }
	]`)
	plans, err := parseAvailablePlans(raw)
	if err != nil {
		t.Fatalf("parseAvailablePlans() failed: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if len(plans[0].Variants) != 1 {
		t.Fatalf("expected 1 variant group, got %d", len(plans[0].Variants))
	}
}

func TestParseCreatedPlanFallbackNames(t *testing.T) {
	raw := []byte(`{"plan_id": "pid", "displayName": "ignored", "planName": "custom"}`)
	plan := parseCreatedPlan(raw)
	if plan.PlanID != "pid" {
		t.Fatalf("expected plan id, got %q", plan.PlanID)
	}
	if plan.Name != "custom" {
		t.Fatalf("expected plan name fallback, got %q", plan.Name)
	}
}

func TestParseTestInfoMixedFields(t *testing.T) {
	raw := []byte(`{"status":"running","result":"unknown","summary":"in-flight"}`)
	info := parseTestInfo(raw)
	if info.Summary != "in-flight" {
		t.Fatalf("expected summary, got %q", info.Summary)
	}
	if info.Status != "RUNNING" {
		t.Fatalf("status uppercased, got %q", info.Status)
	}
}

func TestFirstStringHelper(t *testing.T) {
	m := map[string]json.RawMessage{
		"planName": json.RawMessage(`"primary"`),
		"name":     json.RawMessage(`"secondary"`),
	}
	if v := firstString(m, "planName", "name"); v != "primary" {
		t.Fatalf("expected primary, got %q", v)
	}
}

func TestCreateTestInstance_SendsConfigBodyForPlanModules(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(body) failed: %v", err)
		}
		if err := json.Unmarshal(data, &gotBody); err != nil {
			t.Fatalf("Unmarshal(body) failed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"test-1"}`))
	}))
	defer ts.Close()

	client := newSuiteClient(ts.URL)
	client.http = ts.Client()
	_, err := client.CreateTestInstance(context.Background(), "module-a", "plan-1", nil, map[string]any{"alias": "job-a"})
	if err != nil {
		t.Fatalf("CreateTestInstance() failed: %v", err)
	}
	if gotBody["alias"] != "job-a" {
		t.Fatalf("config body alias = %#v, want %q", gotBody["alias"], "job-a")
	}
}
