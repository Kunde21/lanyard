package conformanceharness

import (
	"encoding/json"
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
