package conformanceharness

import "time"

func finishTiming(start time.Time) (time.Time, string) {
	finished := time.Now().UTC()
	return finished, finished.Sub(start).String()
}

func failPlan(res *planResult, reason string) {
	res.Failed = true
	res.FailureReason = reason
	res.FinishedAt, res.Duration = finishTiming(res.StartedAt)
}

func failTest(res *testResult, status, result, summary string) {
	res.Status = status
	res.Result = result
	res.Summary = summary
	res.FinishedAt, res.Duration = finishTiming(res.StartedAt)
}

func finalizePlan(res *planResult) {
	res.FinishedAt, res.Duration = finishTiming(res.StartedAt)
}

func finalizeTest(res *testResult) {
	res.FinishedAt, res.Duration = finishTiming(res.StartedAt)
}
