package conformanceharness

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	oidcExplicitPlans = map[string]struct{}{
		"oidcc-client-basic-certification-test-plan":          {},
		"oidcc-client-test-plan":                              {},
		"oidcc-client-formpost-basic-certification-test-plan": {},
	}
	oidcFallbackPattern = regexp.MustCompile(`(?i)oidc.*(client|rp)|rp.*oidc|openid.*relying`)
	fapiFallbackPattern = regexp.MustCompile(`(?i)fapi.*(client|rp)|rp.*fapi`)
)

func selectPlans(cfg harnessConfig, available []AvailablePlan) ([]AvailablePlan, error) {
	base := make([]AvailablePlan, 0, len(available))
	for _, plan := range available {
		if matchesProfile(cfg.Profile, plan) {
			base = append(base, plan)
		}
	}

	filtered := make([]AvailablePlan, 0, len(base))
	for _, plan := range base {
		if cfg.IncludePlanRegex != nil && !cfg.IncludePlanRegex.MatchString(plan.Name) {
			continue
		}
		if cfg.ExcludePlanRegex != nil && cfg.ExcludePlanRegex.MatchString(plan.Name) {
			continue
		}
		filtered = append(filtered, plan)
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("profile %q with current filters selected no plans", cfg.Profile)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Name < filtered[j].Name
	})
	return filtered, nil
}

func matchesProfile(profile string, plan AvailablePlan) bool {
	switch profile {
	case "oidc-rp":
		return isOIDCRPPlan(plan)
	case "fapi-rp":
		return isFAPIRPPlan(plan)
	case "all-rp":
		return isOIDCRPPlan(plan) || isFAPIRPPlan(plan)
	default:
		return false
	}
}

func isOIDCRPPlan(plan AvailablePlan) bool {
	if _, ok := oidcExplicitPlans[strings.ToLower(plan.Name)]; ok {
		return true
	}
	joined := strings.ToLower(plan.Name + " " + plan.Profile)
	return strings.Contains(joined, "rp") && oidcFallbackPattern.MatchString(joined)
}

func isFAPIRPPlan(plan AvailablePlan) bool {
	joined := strings.ToLower(plan.Name + " " + plan.Profile)
	return strings.Contains(joined, "rp") && fapiFallbackPattern.MatchString(joined)
}
