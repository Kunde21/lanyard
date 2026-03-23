package conformanceharness

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestScheduler_RespectsMaxParallelismAndRunsAllJobs(t *testing.T) {
	jobs := []RunJob{
		{JobID: "job-001"},
		{JobID: "job-002"},
		{JobID: "job-003"},
		{JobID: "job-004"},
	}

	var mu sync.Mutex
	current := 0
	maxSeen := 0
	runOrder := map[string]int{}

	results, err := scheduleJobs(context.Background(), schedulerConfig{MaxParallelRuns: 2}, jobs, func(ctx context.Context, job RunJob) planResult {
		mu.Lock()
		current++
		if current > maxSeen {
			maxSeen = current
		}
		runOrder[job.JobID]++
		mu.Unlock()

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		current--
		mu.Unlock()

		return planResult{JobID: job.JobID, PlanName: fmt.Sprintf("plan-%s", job.JobID)}
	})
	if err != nil {
		t.Fatalf("scheduleJobs() failed: %v", err)
	}
	if len(results) != len(jobs) {
		t.Fatalf("scheduleJobs() returned %d results, want %d", len(results), len(jobs))
	}
	if maxSeen > 2 {
		t.Fatalf("scheduleJobs() max parallelism = %d, want <= 2", maxSeen)
	}
	for _, job := range jobs {
		if runOrder[job.JobID] != 1 {
			t.Fatalf("job %s ran %d times, want 1", job.JobID, runOrder[job.JobID])
		}
	}
}

func TestScheduler_FailSafeRunsRemainingJobsAfterFailure(t *testing.T) {
	jobs := []RunJob{{JobID: "job-001"}, {JobID: "job-002"}, {JobID: "job-003"}}

	var mu sync.Mutex
	seen := []string{}

	results, err := scheduleJobs(context.Background(), schedulerConfig{MaxParallelRuns: 2, FailFast: false}, jobs, func(ctx context.Context, job RunJob) planResult {
		mu.Lock()
		seen = append(seen, job.JobID)
		mu.Unlock()
		if job.JobID == "job-002" {
			return planResult{JobID: job.JobID, PlanName: job.JobID, Failed: true, FailureReason: "boom"}
		}
		return planResult{JobID: job.JobID, PlanName: job.JobID}
	})
	if err != nil {
		t.Fatalf("scheduleJobs() failed: %v", err)
	}
	if len(results) != len(jobs) {
		t.Fatalf("scheduleJobs() returned %d results, want %d", len(results), len(jobs))
	}
	if len(seen) != len(jobs) {
		t.Fatalf("executed %d jobs, want %d", len(seen), len(jobs))
	}
}

func TestScheduler_FailFastCancelsQueuedJobsAfterFailure(t *testing.T) {
	jobs := []RunJob{{JobID: "job-001"}, {JobID: "job-002"}, {JobID: "job-003"}, {JobID: "job-004"}}

	startGate := make(chan struct{})
	var mu sync.Mutex
	seen := []string{}

	results, err := scheduleJobs(context.Background(), schedulerConfig{MaxParallelRuns: 1, FailFast: true}, jobs, func(ctx context.Context, job RunJob) planResult {
		mu.Lock()
		seen = append(seen, job.JobID)
		mu.Unlock()
		if job.JobID == "job-001" {
			return planResult{JobID: job.JobID, PlanName: job.JobID, Failed: true, FailureReason: "boom"}
		}
		select {
		case <-ctx.Done():
			return planResult{JobID: job.JobID, PlanName: job.JobID, Failed: true, FailureReason: ctx.Err().Error()}
		case <-startGate:
			return planResult{JobID: job.JobID, PlanName: job.JobID}
		}
	})
	close(startGate)
	if err != nil {
		t.Fatalf("scheduleJobs() failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("scheduleJobs() returned %d results, want 1", len(results))
	}
	if len(seen) != 1 || seen[0] != "job-001" {
		t.Fatalf("executed jobs = %v, want only first job", seen)
	}
	if !results[0].Failed {
		t.Fatal("expected first job result to be failed")
	}
}
