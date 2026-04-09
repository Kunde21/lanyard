package conformanceharness

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"time"
)

type jobRunner struct {
	client         *suiteClient
	cfg            harnessConfig
	job            RunJob
	logf           func(format string, args ...any)
	frontClient    *http.Client
	artifactDir    string
	runtimeClient  rpRuntimeClient
	runtimeAliases map[string]struct{}
	startupByAlias map[string]rpRuntimeResponse
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
		client:         client,
		cfg:            cfg,
		job:            job,
		logf:           logf,
		frontClient:    frontClient,
		artifactDir:    artifactDir,
		runtimeClient:  newRPRuntimeClient("https://rp.localhost"),
		runtimeAliases: map[string]struct{}{},
		startupByAlias: map[string]rpRuntimeResponse{},
	}
}

func (jr *jobRunner) registerRuntime(ctx context.Context) (func(), error) {
	if err := jr.registerRuntimeAlias(ctx, jr.job.Alias, ""); err != nil {
		return nil, err
	}
	return func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for alias := range jr.runtimeAliases {
			if err := jr.runtimeClient.Delete(cleanupCtx, alias); err != nil {
				jr.logf("runtime cleanup warning: job=%s alias=%s err=%v", jr.job.JobID, alias, err)
			}
		}
	}, nil
}

func (jr *jobRunner) registerRuntimeAlias(ctx context.Context, alias string, moduleName string) error {
	if jr.runtimeClient == nil {
		return nil
	}
	planVariant := mergePlanVariant(jr.job.PlanVariant, jr.cfg.ForcedVariants)
	req := buildRPRuntimeRequestForAlias(jr.job, planVariant, jr.cfg.SuiteURL, alias)
	if strings.TrimSpace(moduleName) != "" {
		req.StartupAction = startupActionForModule(moduleName)
		req.StartupAllowError = startupAllowsErrorForModule(moduleName)
		if moduleUsesSecondClient(moduleName) {
			req.ClientID = "local-dev-client-2"
			req.ClientSecret = "local-dev-secret-2-32-bytes-min!!"
		}
	}
	resp, err := jr.runtimeClient.Register(ctx, req)
	if err != nil {
		return err
	}
	jr.runtimeAliases[req.Alias] = struct{}{}
	jr.startupByAlias[req.Alias] = resp
	return nil
}

func moduleUsesSecondClient(moduleName string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(moduleName)), "encrypted-idtoken")
}
