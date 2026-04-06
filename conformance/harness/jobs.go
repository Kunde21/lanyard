package conformanceharness

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Kunde21/markdownfmt/markdown"
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
		var allVariants []matrixVariant
		for _, matrixName := range cfg.Matrices {
			variants, err := expandMatrixVariants(matrixName, plan.Name)
			if err != nil {
				continue
			}
			allVariants = append(allVariants, variants...)
		}
		allVariants = deduplicateMatrixVariants(plan.Name, allVariants)

		if len(allVariants) == 0 {
			jobs = append(jobs, buildRunJob(runID, jobIndex, plan, "", "", nil, RPProfileConfig{}))
			jobIndex++
			continue
		}

		for _, variant := range allVariants {
			jobs = append(jobs, buildRunJob(runID, jobIndex, plan, "", variant.Name, variant.Variant, variant.RPProfile))
			jobIndex++
		}
	}
	return jobs
}

func deduplicateMatrixVariants(planName string, variants []matrixVariant) []matrixVariant {
	seen := make(map[string]struct{}, len(variants))
	deduped := make([]matrixVariant, 0, len(variants))
	for _, v := range variants {
		key := variantKey(planName, v.Variant)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, v)
	}
	return deduped
}

func variantKey(planName string, variant map[string]string) string {
	keys := make([]string, 0, len(variant))
	for k := range variant {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+variant[k])
	}
	return planName + "|" + strings.Join(parts, ",")
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

var planGroupPrefixes = []string{
	"fapi2-security-profile",
	"fapi2-message-signing",
	"fapi1-advanced",
	"oidcc-client",
	"fapi-ciba",
}

func splitPlanName(name string) (group, specific string) {
	for _, prefix := range planGroupPrefixes {
		if strings.HasPrefix(name, prefix+"-") {
			return prefix, name[len(prefix)+1:]
		}
	}
	return name, "none"
}

func printDryRunMatrix(jobs []RunJob) {
	if len(jobs) == 0 {
		fmt.Printf("DRY RUN: 0 job(s) would be executed\n")
		return
	}

	var b strings.Builder
	b.WriteString("| no | job_id | plan | matrix_case | variant |\n")
	b.WriteString("|----|--------|------|-------------|----------|\n")
	for i, job := range jobs {
		caseLabel := "none"
		if job.MatrixCase != "" {
			caseLabel = job.MatrixCase
		}
		planGroup, planSpecific := splitPlanName(job.PlanName)

		if len(job.PlanVariant) == 0 {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | none |\n", i+1, job.JobID, planGroup, caseLabel)
			fmt.Fprintf(&b, "| | | %s | | |\n", planSpecific)
			continue
		}

		keys := make([]string, 0, len(job.PlanVariant))
		for k := range job.PlanVariant {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s=%s |\n", i+1, job.JobID, planGroup, caseLabel, keys[0], job.PlanVariant[keys[0]])
		fmt.Fprintf(&b, "| | | %s | | %s=%s |\n", planSpecific, keys[1], job.PlanVariant[keys[1]])
		for _, k := range keys[2:] {
			fmt.Fprintf(&b, "| | | | | %s=%s |\n", k, job.PlanVariant[k])
		}
	}

	formatted, err := markdown.Process("", []byte(b.String()))
	if err != nil {
		fmt.Printf("DRY RUN: %d job(s) would be executed\n\n%s", len(jobs), b.String())
		return
	}

	fmt.Printf("DRY RUN: %d job(s) would be executed\n\n%s", len(jobs), string(formatted))
}
