package conformanceharness

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseForcedVariants(t *testing.T) {
	got, err := parseForcedVariants([]string{
		"client_auth_type=client_secret_post",
		"response_type=code",
		"response_mode=default",
	})
	if err != nil {
		t.Fatalf("parseForcedVariants() failed: %v", err)
	}

	want := map[string]string{
		"client_auth_type": "client_secret_post",
		"response_type":    "code",
		"response_mode":    "default",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("parsed forced variants mismatch (-want +got):\n%s", diff)
	}
}

func TestMergePlanVariant(t *testing.T) {
	base := map[string]string{
		"client_registration": "static_client",
		"response_type":       "id_token",
	}
	overrides := map[string]string{
		"client_auth_type": "client_secret_post",
		"response_type":    "code",
	}

	got := mergePlanVariant(base, overrides)
	want := map[string]string{
		"client_registration": "static_client",
		"client_auth_type":    "client_secret_post",
		"response_type":       "code",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("merged plan variant mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeModuleVariant(t *testing.T) {
	base := map[string]any{
		"response_mode": "form_post",
		"existing":      true,
	}
	overrides := map[string]string{
		"client_auth_type": "client_secret_post",
		"response_mode":    "default",
	}

	got := mergeModuleVariant(base, overrides)
	want := map[string]any{
		"client_auth_type": "client_secret_post",
		"response_mode":    "default",
		"existing":         true,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("merged module variant mismatch (-want +got):\n%s", diff)
	}
}

func TestParseHarnessConfig_ParsesForceVariantFlags(t *testing.T) {
	originalProfile := *flagProfile
	originalSuiteURL := *flagSuiteURL
	originalArtifactsDir := *flagArtifactsDir
	originalIncludePlanRegex := *flagIncludePlanRegex
	originalExcludePlanRegex := *flagExcludePlanRegex
	originalModuleRegex := *flagModuleRegex
	originalForceVariants := append(repeatableStringFlag(nil), flagForceVariants...)

	defer func() {
		*flagProfile = originalProfile
		*flagSuiteURL = originalSuiteURL
		*flagArtifactsDir = originalArtifactsDir
		*flagIncludePlanRegex = originalIncludePlanRegex
		*flagExcludePlanRegex = originalExcludePlanRegex
		*flagModuleRegex = originalModuleRegex
		flagForceVariants = originalForceVariants
	}()

	*flagProfile = "oidc-rp"
	*flagSuiteURL = "https://suite.test"
	*flagArtifactsDir = t.TempDir()
	*flagIncludePlanRegex = ""
	*flagExcludePlanRegex = ""
	*flagModuleRegex = ""
	flagForceVariants = repeatableStringFlag{
		"client_auth_type=client_secret_post",
		"response_type=code",
	}

	cfg, err := parseHarnessConfig()
	if err != nil {
		t.Fatalf("parseHarnessConfig() failed: %v", err)
	}

	want := map[string]string{
		"client_auth_type": "client_secret_post",
		"response_type":    "code",
	}
	if diff := cmp.Diff(want, cfg.ForcedVariants); diff != "" {
		t.Fatalf("forced variants mismatch (-want +got):\n%s", diff)
	}
}
