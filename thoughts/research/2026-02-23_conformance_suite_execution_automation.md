---
date: "2026-02-23T19:51:09+07:00"
git_commit: 8dcce57d4097ec956de6adb85ae45dfcb67c739d
branch: master
repository: lanyard
topic: "Conformance Suite Execution Automation - FEATURE-004 Implementation Research"
tags: [research, conformance, oidc, automation, go-test, docker, reporting]
last_updated: "2026-02-23T19:51:09+07:00"
---

## Ticket Synopsis

**Ticket**: FEATURE-004 - Automate Local Conformance Suite Execution

This research investigates the implementation of an automated OpenID Connect RP conformance suite execution system. The feature provides a one-command local execution path using Go's `go test` framework, automatically provisions required Docker services, supports profile/subset selection, generates JSON artifacts, and ensures non-zero exit on failure.

**Key Requirements Addressed**:
- Single-command execution via `go test` wrapper
- Automatic service provisioning via Docker Compose
- Profile selection (oidc-rp, fapi-rp, all-rp)
- JSON artifact generation in `./artifacts`
- Non-zero exit on conformance failure
- Linux-only local execution scope

## Summary

The conformance automation feature is **fully implemented** in the `conformance/harness/` package. The implementation provides:

1. **One-Command Entry Point**: `LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -args -profile=oidc-rp`
2. **Complete Docker Orchestration**: Builds suite image, provisions MongoDB, suite, RP, and Caddy services
3. **Flexible Profile Selection**: Three profiles with regex-based filtering for fine-grained control
4. **Dual-Output Reporting**: Real-time console logging + structured JSON artifacts with ZIP exports
5. **Sensitive Data Redaction**: Automatic redaction of secrets, tokens, and passwords
6. **Proper Failure Propagation**: Any non-PASSED result propagates to non-zero exit status

The implementation follows Go best practices with proper context propagation, error wrapping, resource cleanup via `t.Cleanup()`, and environment-gated test execution.

## Detailed Findings

### 1. Test Harness Architecture

The conformance harness uses a **layered architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│  Entry Point: harness_test.go (TestConformanceHarness)         │
│  - Environment gating (LANYARD_CONFORMANCE=1)                  │
│  - Configuration parsing and validation                          │
│  - Orchestration pipeline (8 sequential steps)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
    ┌──────────────┬──────────┼──────────┬──────────┐
    ▼              ▼          ▼          ▼          ▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│config.go │ │prereqs.go│ │provision.│ │profiles. │ │report.go │
│(Config)  │ │(Validate)│ │go        │ │go        │ │(Output)  │
│          │ │          │ │(Docker)  │ │(Filter)  │ │          │
└──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
                                                  │
                   ┌──────────────────────────────┼──────────┐
                   ▼                              ▼          ▼
            ┌──────────┐                   ┌──────────┐ ┌──────────┐
            │suiteclient│                  │execute.go│ │execute_  │
            │.go       │                  │(Runner)  │ │helpers.go│
            │(HTTP API)│                  │          │ │(Timing)  │
            └──────────┘                   └──────────┘ └──────────┘
```

**Key Files**:
- `conformance/harness/harness_test.go:33` - Main test entry with 8-step orchestration
- `conformance/harness/config.go:8` - Configuration structure with 13 fields
- `conformance/harness/provision.go:15` - Docker Compose provisioning logic
- `conformance/harness/execute.go:58` - Test execution runner
- `conformance/harness/report.go:27` - JSON report and artifact generation

### 2. One-Command Execution Flow

The harness implements a **sequential 8-step pipeline** in `TestConformanceHarness`:

```
Step 1: Configuration Parsing (harness_test.go:38-41)
        └── parseHarnessConfig() validates flags, compiles regexes

Step 2: Context Setup (harness_test.go:43-44)
        └── Creates timeout: ProvisionTimeout + (PlanTimeout * nPlans)

Step 3: Prerequisite Validation (harness_test.go:46-48)
        └── validatePrerequisites() - Linux, DNS, certs, scripts

Step 4: Service Provisioning (harness_test.go:50-61)
        └── ensureProvisioned() - build image, compose up, readiness probe
        └── t.Cleanup() registers composeDown() for automatic cleanup

Step 5: Plan Discovery & Selection (harness_test.go:63-79)
        └── ListAvailablePlans() → selectPlans() filters by profile + regex

Step 6: Test Execution (harness_test.go:81-82)
        └── runner.Execute(ctx, selectedPlans) - runs all selected plans

Step 7: Report Generation (harness_test.go:84-92)
        └── writeReport() - exports ZIPs, writes JSON, redacts sensitive data

Step 8: Failure Propagation (harness_test.go:94-96)
        └── If runReport.Failed → t.Fatalf() → non-zero exit
```

### 3. Profile Selection Implementation

**Three Supported Profiles** (conformance/harness/profiles.go:47-71):
- `oidc-rp` - OIDC Relying Party conformance tests
- `fapi-rp` - FAPI Relying Party conformance tests  
- `all-rp` - Both OIDC and FAPI RP tests

**Pattern Matching** (conformance/harness/profiles.go:10-16):
```go
oidcExplicitPlans = map[string]struct{}{
    "oidcc-client-basic-certification-test-plan": {},
}
oidcFallbackPattern = regexp.MustCompile(`(?i)oidc.*(client|rp)|rp.*oidc|openid.*relying`)
fapiFallbackPattern = regexp.MustCompile(`(?i)fapi.*(client|rp)|rp.*fapi`)
```

**Two-Stage Filtering** (conformance/harness/profiles.go:18-45):
1. **Profile Filter**: Matches plan name/profile against profile-specific patterns
2. **Regex Filter**: Applies optional include/exclude patterns to plan names

**Module Filtering** (conformance/harness/execute.go:247-258):
- Applied during plan execution after plan creation
- Filters individual test modules by name regex
- Supports running specific modules within a plan

### 4. Docker Compose Provisioning

**Service Stack** (conformance/docker-compose.yml:1-37):
```yaml
services:
  mongo:     # MongoDB 6.0.13 - database backend
  suite:     # Conformance suite (custom image) - test orchestrator
  rp:        # Golang 1.25 - relying party test subject
  caddy:     # Caddy 2.10.2 - reverse proxy with TLS
```

**Provisioning Flow** (conformance/harness/provision.go:15-38):
```go
func ensureProvisioned(ctx context.Context, cfg harnessConfig) error {
    // 1. Build suite image if needed (runs conformance/scripts/build_suite.sh)
    // 2. Run docker compose up -d
    // 3. Poll /api/plan/available until suite responds (2s intervals)
    // 4. Return when suite is ready or timeout
}
```

**Cleanup Management** (conformance/harness/harness_test.go:53-61):
- Uses `t.Cleanup()` for guaranteed execution regardless of test outcome
- Conditional cleanup based on `-keep-running` flag
- Calls `composeDown()` which runs `docker compose down -v`

### 5. JSON Report Generation

**Report Structure** (conformance/harness/execute.go:25-56):
```go
type runReport struct {
    RunID         string       `json:"run_id"`      // e.g., "20260223-150405"
    StartedAt     time.Time    `json:"started_at"`
    FinishedAt    time.Time    `json:"finished_at"`
    Failed        bool         `json:"failed"`
    FailureReason string       `json:"failure_reason,omitempty"`
    Plans         []planResult `json:"plans"`       // Nested plan results
}

type planResult struct {
    PlanName      string       `json:"plan_name"`
    PlanID        string       `json:"plan_id,omitempty"`
    StartedAt     time.Time    `json:"started_at"`
    FinishedAt    time.Time    `json:"finished_at"`
    Duration      string       `json:"duration"`    // "1m30s"
    Failed        bool         `json:"failed"`
    FailureReason string       `json:"failure_reason,omitempty"`
    Tests         []testResult `json:"tests"`       // Nested test results
    ArtifactPath  string       `json:"artifact_path,omitempty"`
}
```

**Dual-Output Pattern**:
1. **Console Output** (real-time): Uses `t.Logf` injected into runner
2. **JSON Artifact** (final): Writes to `./artifacts/{RunID}/report.json`

**Artifacts Directory Structure**:
```
./artifacts/
└── {RunID}/                    # e.g., "20260223-150405"
    ├── report.json             # Main JSON report
    └── plan-{name}-{planID}.zip  # Optional ZIP exports per plan
```

### 6. Sensitive Data Redaction

**Redaction Pattern** (conformance/harness/report.go:119):
```go
var redactionKeyPattern = regexp.MustCompile(`(?i)(secret|token|password|assertion|private_key|client_secret)`)
```

**Redaction Logic** (conformance/harness/report.go:142-167):
- Splits text into fields and detects `key=value` patterns
- If key matches pattern, replaces value with `[REDACTED]`
- Also directly matches and replaces `client_secret` and `token` patterns
- Applied to: test summaries, plan failure reasons, run failure reasons

**Configuration**:
- Controlled by `-redact` flag (default: true)
- Can be disabled for debugging: `-redact=false`

### 7. Failure Propagation

**Non-Zero Exit Strategy**:
The harness uses Go's testing framework semantics:
- Any `t.Fatalf()` call marks the test as FAILED
- Go test exits with non-zero status on test failure
- Multiple failure points throughout the pipeline

**Failure Aggregation**:
```go
// Any module failure marks plan as failed (execute.go:115-121)
if moduleFailed(testRes) {
    planRes.Failed = true
}

// Any plan failure marks run as failed (execute.go:65-71)
if planRes.Failed {
    run.Failed = true
}

// Final check triggers t.Fatalf() (harness_test.go:94-96)
if runReport.Failed {
    t.Fatalf("conformance run failed; report: %s", reportPath)
}
```

## Code References

### Entry Points
- `conformance/harness/harness_test.go:33` - `TestConformanceHarness()` - Main entry
- `conformance/harness/harness_test.go:15-31` - Flag definitions
- `conformance/harness/harness_test.go:99-154` - Configuration parsing

### Core Implementation
- `conformance/harness/provision.go:15-38` - `ensureProvisioned()` - Docker orchestration
- `conformance/harness/provision.go:40-60` - `composeUp()` / `composeDown()`
- `conformance/harness/provision.go:70-102` - `waitForSuiteReadiness()` - Health probes
- `conformance/harness/execute.go:58-80` - `runner.Execute()` - Test execution
- `conformance/harness/execute.go:165-209` - `pollTestResult()` - Async polling
- `conformance/harness/profiles.go:18-45` - `selectPlans()` - Plan filtering
- `conformance/harness/report.go:27-82` - `writeReport()` - Report generation
- `conformance/harness/report.go:119-167` - `redactReport()` - Sensitive data redaction

### Configuration and Types
- `conformance/harness/config.go:8-23` - `harnessConfig` struct
- `conformance/harness/suiteclient.go:34-51` - `AvailablePlan`, `PlanModule`, `createdPlan`
- `conformance/harness/execute.go:25-56` - `runReport`, `planResult`, `testResult`

### Docker Infrastructure
- `conformance/docker-compose.yml:1-37` - Full service stack definition
- `conformance/scripts/build_suite.sh:1-48` - Suite image build script
- `conformance/scripts/setup.sh:1-25` - Environment setup script

### Test and Validation
- `conformance/harness/profiles_test.go:1-97` - Profile selection tests
- `conformance/harness/report_test.go:15-73` - Redaction tests
- `conformance/harness/harness_test.go:33-97` - Integration test (main harness)

## Architecture Insights

### Design Patterns
1. **Environment Gating**: Uses `LANYARD_CONFORMANCE=1` to prevent accidental execution
2. **Context Propagation**: All operations accept `context.Context` for cancellation/timeouts
3. **Sequential Execution**: Plans and modules execute serially for determinism
4. **Aggressive Failure Aggregation**: Any non-PASSED result propagates failure upward
5. **Self-Contained Provisioning**: Docker lifecycle managed internally via `t.Cleanup()`
6. **WAITING State Detection**: Detects stuck tests requiring browser interaction
7. **Artifact Preservation**: Reports written even on failure for post-mortem analysis

### Security Considerations
1. **Default Secure Logging**: Loggers default to `io.Discard` to prevent accidental leaks
2. **Automatic Redaction**: Secrets redacted in reports by default (can disable for debugging)
3. **TLS InsecureSkipVerify**: Only in test environments against self-signed certs
4. **Minimal Credential Exposure**: Local-only with placeholder credentials in Docker Compose

### Extensibility Points
- **Profile System**: Easy to add new profiles by updating `matchesProfile()` function
- **Filter System**: Include/exclude/module regexes provide flexible test selection
- **Report Format**: `reportDocument` struct can be extended with additional metadata
- **Docker Services**: Additional services can be added to docker-compose.yml

## Historical Context (from thoughts/)

### Related Research Documents
- `thoughts/research/2026-02-22_basic_rp_conformance_profile.md` - Prior research on basic RP profile implementation
- `thoughts/research/2026-02-22_openid_conformance_local_setup.md` - Local conformance setup research
- `thoughts/research/2026-02-22_oidc_discovery_implementation.md` - OIDC discovery implementation (RP functionality)

### Implementation Timeline
Based on git history and research documents:
- **FEATURE-002**: Initial conformance local setup (completed)
- **FEATURE-003**: Basic RP test profile implementation (completed)
- **FEATURE-004**: This automation ticket (implemented as of commit 8dcce57d)

### Key Decisions Documented
From the ticket and research:
1. **Local-only scope**: CI integration deferred to future ticket
2. **Linux-only**: Cross-platform support out of scope
3. **No retries**: Transient failure handling not implemented
4. **go test surface**: Chosen over standalone binary for consistency with existing tests
5. **Docker Compose**: Selected for service orchestration over Kubernetes/manual setup
6. **JSON artifacts**: Machine-readable output for potential future CI integration

## Usage Examples

### Basic OIDC RP Conformance Run
```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp
```

### Run Specific Plans Only
```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -include-plan-regex="basic"
```

### Run Specific Modules
```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -module-regex="certification"
```

### Keep Services Running for Debugging
```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -keep-running
```

### Disable Redaction for Debugging
```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -redact=false
```

### Custom Artifacts Directory
```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -artifacts-dir=/tmp/conformance-artifacts
```

## Open Questions

1. **CI Integration**: How will this translate to CI environments? The Docker-in-Docker approach may need adaptation.

2. **Windows/macOS Support**: Currently Linux-only. Would require host resolution and Docker Desktop considerations.

3. **Test Parallelization**: Currently sequential. Could plans run in parallel to reduce execution time?

4. **Historical Trend Analysis**: Out of scope for this ticket, but JSON artifacts could be aggregated over time.

5. **External Result Publishing**: Out of scope, but could build on existing artifact infrastructure.

## Related Information

- **Feature Plan**: `thoughts/plans/conformance_suite_execution_automation.md`
- **Ticket**: `thoughts/tickets/feature_conformance_suite_execution_automation.md`
- **Suite API Docs**: `conformance/SUITE_API.md`
- **Conformance README**: `conformance/README.md`
- **Local Endpoints**: https://suite.test and https://rp.test (configured in /etc/hosts)
- **Prior Tickets**: FEATURE-002 (local setup), FEATURE-003 (basic RP profile)
