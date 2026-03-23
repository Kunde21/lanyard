package conformanceharness

import (
	"fmt"
	"sort"
	"strings"
)

type RunJob struct {
	JobID             string
	Alias             string
	PlanName          string
	Plan              AvailablePlan
	PlanVariant       map[string]string
	RPProfile         RPProfileConfig
	MatrixName        string
	MatrixCase        string
	ArtifactDirSuffix string
}

func expandRunJobs(runID string, cfg harnessConfig, plans []AvailablePlan) []RunJob {
	jobs := make([]RunJob, 0, len(plans))
	jobIndex := 1
	for _, plan := range plans {
		variants, err := expandMatrixVariants(cfg.Matrix, plan.Name)
		if err != nil || len(variants) == 0 {
			jobs = append(jobs, buildRunJob(runID, jobIndex, plan, cfg.Matrix, "", nil, RPProfileConfig{}))
			jobIndex++
			continue
		}

		for _, variant := range variants {
			jobs = append(jobs, buildRunJob(runID, jobIndex, plan, cfg.Matrix, variant.Name, variant.Variant, variant.RPProfile))
			jobIndex++
		}
	}
	return jobs
}

func buildRunJob(runID string, jobIndex int, plan AvailablePlan, matrixName, matrixCase string, matrixVariant map[string]string, rpProfile RPProfileConfig) RunJob {
	planVariant := mergePlanVariant(selectPlanVariant(plan), matrixVariant)
	jobID := fmt.Sprintf("job-%03d", jobIndex)
	aliasParts := []string{sanitizeAliasPart(runID), fmt.Sprintf("%03d", jobIndex)}
	if matrixCase != "" {
		aliasParts = append(aliasParts, sanitizeAliasPart(matrixCase))
	}
	alias := strings.Trim(strings.Join(aliasParts, "-"), "-")
	if alias == "" {
		alias = fmt.Sprintf("run-%03d", jobIndex)
	}

	return RunJob{
		JobID:             jobID,
		Alias:             alias,
		PlanName:          plan.Name,
		Plan:              plan,
		PlanVariant:       planVariant,
		RPProfile:         rpProfile,
		MatrixName:        matrixName,
		MatrixCase:        matrixCase,
		ArtifactDirSuffix: jobID,
	}
}

func sanitizeAliasPart(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	prevDash := false
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case !prevDash:
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func stableVariantMap(variant map[string]string) map[string]string {
	if len(variant) == 0 {
		return nil
	}
	keys := make([]string, 0, len(variant))
	for k := range variant {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	stable := make(map[string]string, len(variant))
	for _, k := range keys {
		stable[k] = variant[k]
	}
	return stable
}
