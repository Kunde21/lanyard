package conformanceharness

import (
	"context"
	"sort"
	"sync"
)

type schedulerConfig struct {
	MaxParallelRuns int
	FailFast        bool
}

type scheduledResult struct {
	index  int
	result planResult
}

func scheduleJobs(ctx context.Context, cfg schedulerConfig, jobs []RunJob, exec func(context.Context, RunJob) planResult) ([]planResult, error) {
	if cfg.MaxParallelRuns <= 0 {
		cfg.MaxParallelRuns = 1
	}
	if len(jobs) == 0 {
		return nil, nil
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultsCh := make(chan scheduledResult, len(jobs))
	var wg sync.WaitGroup

	next := 0
	running := 0
	stopLaunching := false
	results := make([]scheduledResult, 0, len(jobs))

	startJob := func(index int) {
		job := jobs[index]
		running++
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultsCh <- scheduledResult{index: index, result: exec(workCtx, job)}
		}()
	}

	for {
		for !stopLaunching && next < len(jobs) && running < cfg.MaxParallelRuns {
			startJob(next)
			next++
		}

		if running == 0 {
			break
		}

		result := <-resultsCh
		running--
		results = append(results, result)
		if cfg.FailFast && result.result.Failed {
			stopLaunching = true
			cancel()
		}
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()
	for result := range resultsCh {
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].index < results[j].index
	})
	ordered := make([]planResult, 0, len(results))
	for _, result := range results {
		ordered = append(ordered, result.result)
	}
	return ordered, nil
}
