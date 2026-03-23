package conformanceharness

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"time"
)

type jobRunner struct {
	client        *suiteClient
	cfg           harnessConfig
	job           RunJob
	logf          func(format string, args ...any)
	frontClient   *http.Client
	artifactDir   string
	runtimeClient rpRuntimeClient
}

func newJobRunner(client *suiteClient, cfg harnessConfig, job RunJob, logf func(format string, args ...any)) *jobRunner {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		jar = nil
	}

	frontClient := &http.Client{
		Timeout: 45 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		},
	}

	artifactDir := filepath.Join(cfg.ArtifactsDir, "jobs", job.JobID)
	return &jobRunner{
		client:        client,
		cfg:           cfg,
		job:           job,
		logf:          logf,
		frontClient:   frontClient,
		artifactDir:   artifactDir,
		runtimeClient: newRPRuntimeClient("https://rp.localhost"),
	}
}

func (jr *jobRunner) registerRuntime(ctx context.Context) (func(), error) {
	if jr.runtimeClient == nil {
		return func() {}, nil
	}
	planVariant := mergePlanVariant(jr.job.PlanVariant, jr.cfg.ForcedVariants)
	req := buildRPRuntimeRequest(jr.job, planVariant, jr.cfg.SuiteURL)
	if err := jr.runtimeClient.Register(ctx, req); err != nil {
		return nil, err
	}
	return func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := jr.runtimeClient.Delete(cleanupCtx, jr.job.Alias); err != nil {
			jr.logf("runtime cleanup warning: job=%s alias=%s err=%v", jr.job.JobID, jr.job.Alias, err)
		}
	}, nil
}
