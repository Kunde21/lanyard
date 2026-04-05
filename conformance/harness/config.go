package conformanceharness

import (
	"regexp"
	"time"
)

type harnessConfig struct {
	Profile              string
	SuiteURL             string
	ArtifactsDir         string
	Parallel             bool
	MaxParallelRuns      int
	Matrices             []string
	FailFast             bool
	IncludePlanRegex     *regexp.Regexp
	ExcludePlanRegex     *regexp.Regexp
	ModuleRegex          *regexp.Regexp
	ProvisionTimeout     time.Duration
	PlanTimeout          time.Duration
	TestTimeout          time.Duration
	SuiteWaitTimeout     time.Duration
	WaitTimeoutSeconds   int
	SkipProvision        bool
	Cleanup              bool
	ExportZip            bool
	Redact               bool
	RebuildSuite         bool
	SelectedPlanNames    []string
	ForcedVariants       map[string]string
	WaitingMaxRetries    int
	WaitingRetryInterval time.Duration
}
