package conformanceharness

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	flagProfile          = flag.String("profile", "", "Conformance profile to run: oidc-rp|fapi-rp|all-rp")
	flagSuiteURL         = flag.String("suite-url", "https://suite.test", "Base URL for the conformance suite")
	flagArtifactsDir     = flag.String("artifacts-dir", "./artifacts", "Directory for run artifacts")
	flagIncludePlanRegex = flag.String("include-plan-regex", "", "Regex for plan names to include")
	flagExcludePlanRegex = flag.String("exclude-plan-regex", "", "Regex for plan names to exclude")
	flagModuleRegex      = flag.String("module-regex", "", "Regex for module names to include")

	flagProvisionTimeout = flag.Duration("provision-timeout", 5*time.Minute, "Max time to provision local conformance stack")
	flagPlanTimeout      = flag.Duration("plan-timeout", 30*time.Minute, "Max time for a single plan execution")
	flagTestTimeout      = flag.Duration("test-timeout", 5*time.Minute, "Max time for a single test instance")

	flagKeepRunning = flag.Bool("keep-running", false, "Leave docker compose services running after test")
	flagExportZip   = flag.Bool("export-zip", true, "Export suite plan result ZIP artifacts")
	flagRedact      = flag.Bool("redact", true, "Redact sensitive keys in artifacts/log output")
	flagRebuild     = flag.Bool("rebuild-suite", false, "Force rebuilding suite image before compose up")
)

func TestConformanceHarness(t *testing.T) {
	if os.Getenv("LANYARD_CONFORMANCE") != "1" {
		t.Skip("set LANYARD_CONFORMANCE=1 to run local conformance harness")
	}

	cfg, err := parseHarnessConfig()
	if err != nil {
		t.Fatalf("invalid harness configuration: %v\n\n%s", err, harnessUsage())
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ProvisionTimeout+cfg.PlanTimeout*time.Duration(max(1, len(cfg.SelectedPlanNames))))
	defer cancel()

	if err := validatePrerequisites(cfg); err != nil {
		t.Fatalf("prerequisite validation failed: %v", err)
	}

	if err := ensureProvisioned(ctx, cfg); err != nil {
		t.Fatalf("failed to provision conformance stack: %v", err)
	}
	if !cfg.KeepRunning {
		t.Cleanup(func() {
			downCtx, downCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer downCancel()
			if err := composeDown(downCtx); err != nil {
				t.Logf("compose teardown failed: %v", err)
			}
		})
	}

	client := newSuiteClient(cfg.SuiteURL)
	availablePlans, err := client.ListAvailablePlans(ctx)
	if err != nil {
		t.Fatalf("failed to list available plans: %v", err)
	}

	selectedPlans, err := selectPlans(cfg, availablePlans)
	if err != nil {
		t.Fatalf("failed to select plans: %v", err)
	}
	if len(selectedPlans) == 0 {
		t.Fatalf("no plans selected for profile %q after filtering", cfg.Profile)
	}
	cfg.SelectedPlanNames = make([]string, 0, len(selectedPlans))
	for _, plan := range selectedPlans {
		cfg.SelectedPlanNames = append(cfg.SelectedPlanNames, plan.Name)
	}

	runner := newRunner(client, cfg, t.Logf)
	runReport := runner.Execute(ctx, selectedPlans)

	if err := os.MkdirAll(filepath.Clean(cfg.ArtifactsDir), 0o755); err != nil {
		t.Fatalf("failed to create artifacts dir: %v", err)
	}

	reportPath, writeErr := writeReport(ctx, cfg, runReport)
	if writeErr != nil {
		t.Fatalf("failed to write report: %v", writeErr)
	}
	t.Logf("wrote conformance report to %s", reportPath)

	if runReport.Failed {
		t.Fatalf("conformance run failed; report: %s", reportPath)
	}
}

func parseHarnessConfig() (harnessConfig, error) {
	cfg := harnessConfig{
		Profile:          strings.TrimSpace(*flagProfile),
		SuiteURL:         strings.TrimSpace(*flagSuiteURL),
		ArtifactsDir:     strings.TrimSpace(*flagArtifactsDir),
		ProvisionTimeout: *flagProvisionTimeout,
		PlanTimeout:      *flagPlanTimeout,
		TestTimeout:      *flagTestTimeout,
		KeepRunning:      *flagKeepRunning,
		ExportZip:        *flagExportZip,
		Redact:           *flagRedact,
		RebuildSuite:     *flagRebuild,
	}

	if cfg.Profile == "" {
		return harnessConfig{}, fmt.Errorf("-profile is required when LANYARD_CONFORMANCE=1")
	}
	if cfg.Profile != "oidc-rp" && cfg.Profile != "fapi-rp" && cfg.Profile != "all-rp" {
		return harnessConfig{}, fmt.Errorf("invalid -profile %q", cfg.Profile)
	}
	if cfg.SuiteURL == "" {
		return harnessConfig{}, fmt.Errorf("-suite-url cannot be empty")
	}
	if cfg.ArtifactsDir == "" {
		return harnessConfig{}, fmt.Errorf("-artifacts-dir cannot be empty")
	}
	if !filepath.IsAbs(cfg.ArtifactsDir) {
		repoArtifactsPath, err := repoPath(cfg.ArtifactsDir)
		if err != nil {
			return harnessConfig{}, fmt.Errorf("failed to resolve artifacts path: %w", err)
		}
		cfg.ArtifactsDir = repoArtifactsPath
	}
	if cfg.ProvisionTimeout <= 0 || cfg.PlanTimeout <= 0 || cfg.TestTimeout <= 0 {
		return harnessConfig{}, fmt.Errorf("timeouts must be positive durations")
	}

	includeRE, err := compileRegex(strings.TrimSpace(*flagIncludePlanRegex))
	if err != nil {
		return harnessConfig{}, fmt.Errorf("invalid -include-plan-regex: %w", err)
	}
	excludeRE, err := compileRegex(strings.TrimSpace(*flagExcludePlanRegex))
	if err != nil {
		return harnessConfig{}, fmt.Errorf("invalid -exclude-plan-regex: %w", err)
	}
	moduleRE, err := compileRegex(strings.TrimSpace(*flagModuleRegex))
	if err != nil {
		return harnessConfig{}, fmt.Errorf("invalid -module-regex: %w", err)
	}

	cfg.IncludePlanRegex = includeRE
	cfg.ExcludePlanRegex = excludeRE
	cfg.ModuleRegex = moduleRE

	return cfg, nil
}

func compileRegex(raw string) (*regexp.Regexp, error) {
	if raw == "" {
		return nil, nil
	}
	return regexp.Compile(raw)
}

func harnessUsage() string {
	var b strings.Builder
	b.WriteString("Conformance harness flags:\n")
	flag.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "test.") {
			return
		}
		b.WriteString(fmt.Sprintf("  -%s (default %q): %s\n", f.Name, f.DefValue, f.Usage))
	})
	return b.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
