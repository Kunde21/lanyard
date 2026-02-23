package conformanceharness

import (
	"regexp"
	"time"
)

type harnessConfig struct {
	Profile           string
	SuiteURL          string
	ArtifactsDir      string
	IncludePlanRegex  *regexp.Regexp
	ExcludePlanRegex  *regexp.Regexp
	ModuleRegex       *regexp.Regexp
	ProvisionTimeout  time.Duration
	PlanTimeout       time.Duration
	TestTimeout       time.Duration
	KeepRunning       bool
	ExportZip         bool
	Redact            bool
	RebuildSuite      bool
	SelectedPlanNames []string
}
