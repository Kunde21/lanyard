package conformanceharness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type reportDocument struct {
	RunID         string       `json:"run_id"`
	Timestamp     time.Time    `json:"timestamp"`
	GitSHA        string       `json:"git_sha,omitempty"`
	SuiteURL      string       `json:"suite_url"`
	Profile       string       `json:"profile"`
	Matrices      []string     `json:"matrices,omitempty"`
	SelectedPlans []string     `json:"selected_plans"`
	Failed        bool         `json:"failed"`
	FailureReason string       `json:"failure_reason,omitempty"`
	Plans         []planResult `json:"plans"`
}

func writeReport(ctx context.Context, cfg harnessConfig, run runReport) (string, reportDocument, error) {
	runDir := filepath.Join(cfg.ArtifactsDir, run.RunID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", reportDocument{}, fmt.Errorf("failed to create run artifact directory: %w", err)
	}

	gitSHA := currentGitSHA(ctx)
	reportablePlans := make([]planResult, len(run.Plans))
	copy(reportablePlans, run.Plans)

	for i := range reportablePlans {
		if cfg.ExportZip && reportablePlans[i].PlanID != "" {
			artifactPath, err := exportPlanZip(ctx, cfg, runDir, reportablePlans[i])
			if err != nil {
				reportablePlans[i].Failed = true
				if reportablePlans[i].FailureReason == "" {
					reportablePlans[i].FailureReason = fmt.Sprintf("failed to export zip: %v", err)
				}
				run.Failed = true
			} else {
				reportablePlans[i].ArtifactPath = artifactPath
			}
		}
	}

	doc := reportDocument{
		RunID:         run.RunID,
		Timestamp:     time.Now().UTC(),
		GitSHA:        gitSHA,
		SuiteURL:      cfg.SuiteURL,
		Profile:       cfg.Profile,
		Matrices:      cfg.Matrices,
		SelectedPlans: append([]string{}, cfg.SelectedPlanNames...),
		Failed:        run.Failed,
		FailureReason: run.FailureReason,
		Plans:         reportablePlans,
	}

	if cfg.Redact {
		doc = redactReport(doc)
	}

	reportPath := filepath.Join(runDir, "report.json")
	f, err := os.Create(filepath.Clean(reportPath))
	if err != nil {
		return "", reportDocument{}, fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", reportDocument{}, fmt.Errorf("failed to encode report JSON: %w", err)
	}

	return reportPath, doc, nil
}

func exportPlanZip(ctx context.Context, cfg harnessConfig, runDir string, plan planResult) (string, error) {
	client := newSuiteClient(cfg.SuiteURL)
	zipData, err := client.ExportPlanZip(ctx, plan.PlanID)
	if err != nil {
		return "", err
	}

	path := planZipPath(runDir, plan)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("failed creating plan zip directory: %w", err)
	}
	if err := os.WriteFile(filepath.Clean(path), zipData, 0o644); err != nil {
		return "", fmt.Errorf("failed writing zip file: %w", err)
	}
	return path, nil
}

func planZipPath(runDir string, plan planResult) string {
	safeName := sanitizePathComponent(plan.PlanName)
	filename := fmt.Sprintf("plan-%s-%s.zip", safeName, plan.PlanID)
	if strings.TrimSpace(plan.JobID) == "" {
		return filepath.Join(runDir, filename)
	}
	return filepath.Join(runDir, "jobs", sanitizePathComponent(plan.JobID), filename)
}

func sanitizePathComponent(raw string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	clean := re.ReplaceAllString(strings.TrimSpace(raw), "-")
	clean = strings.Trim(clean, "-.")
	if clean == "" {
		return "plan"
	}
	return clean
}

func currentGitSHA(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var redactionKeyPattern = regexp.MustCompile(`(?i)(secret|token|password|assertion|private_key|client_secret)`)

func redactReport(doc reportDocument) reportDocument {
	redacted := doc
	redacted.SelectedPlans = append([]string{}, doc.SelectedPlans...)
	redacted.Plans = make([]planResult, len(doc.Plans))

	for i, plan := range doc.Plans {
		planCopy := plan
		planCopy.Tests = make([]testResult, len(plan.Tests))
		for j, test := range plan.Tests {
			testCopy := test
			testCopy.Summary = redactString(test.Summary)
			planCopy.Tests[j] = testCopy
		}
		planCopy.FailureReason = redactString(plan.FailureReason)
		redacted.Plans[i] = planCopy
	}

	redacted.FailureReason = redactString(doc.FailureReason)
	return redacted
}

func redactString(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}

	parts := strings.Fields(s)
	for i, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 && redactionKeyPattern.MatchString(kv[0]) {
				parts[i] = kv[0] + "=[REDACTED]"
			}
		}
	}
	joined := strings.Join(parts, " ")

	if redactionKeyPattern.MatchString(joined) {
		return redactionKeyPattern.ReplaceAllStringFunc(joined, func(match string) string {
			if strings.EqualFold(match, "client_secret") || strings.EqualFold(match, "token") {
				return "[REDACTED]"
			}
			return match
		})
	}
	return joined
}
