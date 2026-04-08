package conformanceharness

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type summaryCounts struct {
	Plans   int
	Tests   int
	Passed  int
	Failed  int
	Skipped int
	Errored int
}

type planGroup struct {
	Name    string
	Plans   int
	Tests   int
	Passed  int
	Failed  int
	Skipped int
	Errored int
}

func printSummary(w io.Writer, doc reportDocument) {
	counts := aggregateCounts(doc.Plans)
	groups := aggregateByPlanName(doc.Plans)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintf(w, "  Conformance Report: %s\n", doc.RunID)
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════════")

	if counts.Failed > 0 || doc.Failed {
		fmt.Fprintf(w, "  Result: FAILED (%s)\n", failureMessage(counts))
	} else {
		fmt.Fprintf(w, "  Result: ALL PASSED — %d/%d tests passed\n", counts.Passed, counts.Tests)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Breakdown by Plan Type")
	fmt.Fprintln(w, "  ─────────────────────────────────────────────────────────────")
	fmt.Fprintf(w, "  %-44s %5s %6s %s\n", "Plan", "Plans", "Tests", "Status")
	fmt.Fprintf(w, "  %-44s %5s %6s %s\n", "────", "─────", "─────", "──────")
	for _, g := range groups {
		status := "All PASSED"
		if g.Failed > 0 || g.Errored > 0 {
			status = fmt.Sprintf("FAILED (%d)", g.Failed+g.Errored)
		}
		fmt.Fprintf(w, "  %-44s %5d %6d %s\n", displayName(g.Name), g.Plans, g.Tests, status)
	}
	fmt.Fprintln(w)

	if len(doc.Matrices) > 0 {
		fmt.Fprintln(w, "  Matrices")
		fmt.Fprintln(w, "  ─────────────────────────────────────────────────────────────")
		for _, m := range doc.Matrices {
			fmt.Fprintf(w, "  • %s\n", m)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "  Details")
	fmt.Fprintln(w, "  ─────────────────────────────────────────────────────────────")
	if doc.GitSHA != "" {
		if len(doc.GitSHA) > 8 {
			fmt.Fprintf(w, "  Git SHA:  %s\n", doc.GitSHA[:8])
		} else {
			fmt.Fprintf(w, "  Git SHA:  %s\n", doc.GitSHA)
		}
	}
	fmt.Fprintf(w, "  Profile:  %s\n", doc.Profile)

	overallDuration := overallRunDuration(doc)
	if overallDuration != "" {
		fmt.Fprintf(w, "  Duration: %s\n", overallDuration)
	}

	if doc.FailureReason != "" {
		fmt.Fprintf(w, "  Failure:  %s\n", doc.FailureReason)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)
}

func printRunSummary(doc reportDocument) {
	printSummary(os.Stdout, doc)
}

func aggregateCounts(plans []planResult) summaryCounts {
	var c summaryCounts
	c.Plans = len(plans)
	for _, p := range plans {
		c.Tests += len(p.Tests)
		for _, t := range p.Tests {
			switch strings.ToUpper(strings.TrimSpace(t.Result)) {
			case "PASSED", "SUCCESS":
				c.Passed++
			case "SKIPPED", "WARNING":
				c.Skipped++
			case "FAILED":
				c.Failed++
			default:
				if strings.EqualFold(t.Status, "ERROR") {
					c.Errored++
				} else {
					c.Failed++
				}
			}
		}
	}
	return c
}

func aggregateByPlanName(plans []planResult) []planGroup {
	seen := make(map[string]*planGroup, len(plans))
	var order []string
	for _, p := range plans {
		name := p.PlanName
		g, ok := seen[name]
		if !ok {
			order = append(order, name)
			seen[name] = &planGroup{Name: name}
			g = seen[name]
		}
		g.Plans++
		g.Tests += len(p.Tests)
		for _, t := range p.Tests {
			switch strings.ToUpper(strings.TrimSpace(t.Result)) {
			case "PASSED", "SUCCESS":
				g.Passed++
			case "SKIPPED", "WARNING":
				g.Skipped++
			case "FAILED":
				g.Failed++
			default:
				if strings.EqualFold(t.Status, "ERROR") {
					g.Errored++
				} else {
					g.Failed++
				}
			}
		}
	}
	groups := make([]planGroup, 0, len(order))
	for _, name := range order {
		groups = append(groups, *seen[name])
	}
	return groups
}

func failureMessage(c summaryCounts) string {
	parts := []string{}
	if c.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", c.Failed))
	}
	if c.Errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", c.Errored))
	}
	if c.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", c.Skipped))
	}
	return fmt.Sprintf("%d/%d tests passed, %s", c.Passed, c.Tests, strings.Join(parts, ", "))
}

func displayName(planName string) string {
	switch {
	case strings.Contains(planName, "oidcc-client-basic"):
		return "OIDCC Client Basic"
	case strings.Contains(planName, "oidcc-client-formpost"):
		return "OIDCC Client Formpost Basic"
	case strings.Contains(planName, "fapi1-advanced"):
		return "FAPI1 Advanced Final"
	case strings.Contains(planName, "fapi2-message-signing"):
		return "FAPI2 Message Signing Final"
	case strings.Contains(planName, "fapi2-security-profile"):
		return "FAPI2 Security Profile Final"
	default:
		if len(planName) > 42 {
			return planName[:39] + "..."
		}
		return planName
	}
}

func overallRunDuration(doc reportDocument) string {
	if len(doc.Plans) == 0 {
		return ""
	}
	earliest := doc.Plans[0].StartedAt
	var latest time.Time
	for _, p := range doc.Plans {
		if p.StartedAt.Before(earliest) {
			earliest = p.StartedAt
		}
		if p.FinishedAt.After(latest) {
			latest = p.FinishedAt
		}
	}
	if latest.IsZero() || earliest.IsZero() {
		return ""
	}
	d := latest.Sub(earliest)
	return d.Truncate(time.Second).String()
}
