package conformanceharness

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestResolvePreset_AllRPFull(t *testing.T) {
	cfg, err := resolvePreset("all-rp-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "all-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "all-rp")
	}
	want := []string{
		"oidcc-config-cert-all42",
		"fapi2-sp-final-plain-fapi-all16",
		"fapi2-ms-final-plain-fapi-all32",
		"fapi1-adv-final-all12",
	}
	if diff := cmp.Diff(want, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if !cfg.Parallel {
		t.Errorf("Parallel = false, want true")
	}
	if cfg.MaxParallelRuns != 12 {
		t.Errorf("MaxParallelRuns = %d, want 8", cfg.MaxParallelRuns)
	}
	if cfg.ExcludePlanRegex != "ciba|brazil|id1-|id2-|client-credentials" {
		t.Errorf("ExcludePlanRegex = %q, want %q", cfg.ExcludePlanRegex, "ciba|brazil|id1-|id2-|client-credentials")
	}
}

func TestResolvePreset_AllRPSmoke(t *testing.T) {
	cfg, err := resolvePreset("all-rp-smoke")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "all-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "all-rp")
	}
	want := []string{
		"oidcc-config-cert-first2",
		"fapi2-sp-final-plain-fapi-first4",
		"fapi2-ms-final-plain-fapi-jar4",
		"fapi1-adv-final-first4",
	}
	if diff := cmp.Diff(want, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if cfg.MaxParallelRuns != 4 {
		t.Errorf("MaxParallelRuns = %d, want 4", cfg.MaxParallelRuns)
	}
}

func TestResolvePreset_FAPI2SPFull(t *testing.T) {
	cfg, err := resolvePreset("fapi2-sp-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "fapi-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "fapi-rp")
	}
	if len(cfg.Matrices) != 1 || cfg.Matrices[0] != "fapi2-sp-final-plain-fapi-all16" {
		t.Fatalf("Matrices = %v, want [fapi2-sp-final-plain-fapi-all16]", cfg.Matrices)
	}
}

func TestResolvePreset_FAPI2MSFull(t *testing.T) {
	cfg, err := resolvePreset("fapi2-ms-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "fapi-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "fapi-rp")
	}
	if len(cfg.Matrices) != 1 || cfg.Matrices[0] != "fapi2-ms-final-plain-fapi-all32" {
		t.Fatalf("Matrices = %v, want [fapi2-ms-final-plain-fapi-all32]", cfg.Matrices)
	}
}

func TestResolvePreset_UnknownPresetReturnsError(t *testing.T) {
	_, err := resolvePreset("nonexistent")
	if err == nil {
		t.Fatal("resolvePreset() should return error for unknown preset")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention preset name, got: %v", err)
	}
}

func TestResolvePreset_FAPI1AdvFull(t *testing.T) {
	cfg, err := resolvePreset("fapi1-adv-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "fapi-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "fapi-rp")
	}
	want := []string{"fapi1-adv-final-all12"}
	if diff := cmp.Diff(want, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if cfg.IncludePlanRegex != "fapi1-advanced-final-client-test-plan" {
		t.Errorf("IncludePlanRegex = %q, want %q", cfg.IncludePlanRegex, "fapi1-advanced-final-client-test-plan")
	}
	if !cfg.Parallel {
		t.Errorf("Parallel = false, want true")
	}
	if cfg.MaxParallelRuns != 8 {
		t.Errorf("MaxParallelRuns = %d, want 8", cfg.MaxParallelRuns)
	}
}

func TestResolvePreset_FAPI1AdvSmoke(t *testing.T) {
	cfg, err := resolvePreset("fapi1-adv-smoke")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "fapi-rp" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "fapi-rp")
	}
	want := []string{"fapi1-adv-final-first4"}
	if diff := cmp.Diff(want, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if cfg.IncludePlanRegex != "fapi1-advanced-final-client-test-plan" {
		t.Errorf("IncludePlanRegex = %q, want %q", cfg.IncludePlanRegex, "fapi1-advanced-final-client-test-plan")
	}
	if !cfg.Parallel {
		t.Errorf("Parallel = false, want true")
	}
	if cfg.MaxParallelRuns != 4 {
		t.Errorf("MaxParallelRuns = %d, want 4", cfg.MaxParallelRuns)
	}
}

func TestResolvePreset_OIDCConfigFull(t *testing.T) {
	cfg, err := resolvePreset("oidcc-config-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "oidc-rp" {
		t.Fatalf("Profile = %q, want oidc-rp", cfg.Profile)
	}
	if diff := cmp.Diff([]string{"oidcc-config-cert-all42"}, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if !cfg.Parallel {
		t.Fatal("Parallel = false, want true")
	}
}

func TestResolvePreset_OIDCConfigSmoke(t *testing.T) {
	cfg, err := resolvePreset("oidcc-config-smoke")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "oidc-rp" {
		t.Fatalf("Profile = %q, want oidc-rp", cfg.Profile)
	}
	if diff := cmp.Diff([]string{"oidcc-config-cert-first2"}, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if !cfg.Parallel {
		t.Fatal("Parallel = false, want true")
	}
}
