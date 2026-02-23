# FEATURE-004: Automate Local Conformance Suite Execution Implementation Plan

## Overview

Implement a Linux-only, local-only conformance harness that maintainers run via a `go test` entrypoint. The harness provisions the local conformance stack, selects conformance plans by high-level profile grouping (OIDC + FAPI for RP from day one), executes the selected plan(s) by driving the upstream suite HTTP APIs, writes a machine-readable JSON report under `./artifacts`, and exits non-zero when any selected plan fails.

## Current State Analysis

- Local conformance is documented as a manual workflow with multiple steps in `conformance/README.md:21`.
- Local provisioning relies on scripts and docker compose:
  - TLS + host setup: `conformance/scripts/setup.sh:9`
  - suite image build: `conformance/scripts/build_suite.sh:8`
  - orchestration: `conformance/docker-compose.yml:1`
- Artifacts are currently described as living under `conformance/artifacts/` and ignored by git (`conformance/README.md:93`, `.gitignore:4`), but this ticket requires JSON artifacts under `./artifacts` at repo root.

## Desired End State

Maintainers can run one local command via `go test` that:
1) brings up (and later tears down) the required local conformance services,
2) selects plan(s) based on profile (OIDC RP and FAPI RP), with optional include/exclude filtering,
3) executes all tests for the selected plan(s) deterministically,
4) prints clear progress + final results to the console,
5) writes a JSON report under `./artifacts/<run-id>/report.json` (plus optional exported evidence ZIPs), and
6) returns non-zero if any executed test fails or the run errors.

### Key Discoveries:
- Suite API entrypoints exist for plan discovery, plan creation, test start, polling, and export:
  - available plans: `GET /api/plan/available` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/info/TestPlanApi.java:270`)
  - create plan: `POST /api/plan` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/info/TestPlanApi.java:59`)
  - create test instance: `POST /api/runner` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:214`)
  - poll status/result: `GET /api/info/{id}` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/info/TestInfoApi.java:62`, model in `.../TestInfo.java:33`)
  - export plan results ZIP: `GET /api/plan/exporthtml/{id}` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/logging/LogApi.java:530`)
- RP Basic plan name (example) is `oidcc-client-basic-certification-test-plan` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/openid/client/OIDCCClientBasicTestPlan.java:12`).
- RP tests read static client config from `config.client` and normalize `redirect_uri` into `redirect_uris` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/condition/as/OIDCCGetStaticClientConfigurationForRPTests.java:26`).

## What We're NOT Doing

- CI integration (explicitly out of scope).
- External publishing of results or trend/history reporting.
- Retries for flaky tests.
- Non-Linux support.
- Comprehensive secret management redesign (only minimal log/report redaction).

## Implementation Approach

Use an API-driven runner (no browser automation). The harness runs as an integration test package (so it can be invoked as `go test ...`) and orchestrates docker compose and the suite HTTP APIs.

Core design choices:
- **Entry point**: a `*_test.go` harness that is skipped unless explicitly enabled (pattern similar to `oidc/live_compliance_test.go:18`).
- **Profile-driven plan selection**: `-profile=oidc-rp|fapi-rp|all-rp` expands to a list of suite plan names discovered from `/api/plan/available`.
- **Filtering**: optional `-include-plan-regex` / `-exclude-plan-regex` to trim the expanded set.
- **Execution model**: run plans sequentially; within each plan, create tests sequentially (deterministic alias routing and easier debugging).
- **Reporting**: write `./artifacts/<run-id>/report.json` plus exported ZIP(s) per plan; console shows progress and final pass/fail.
- **Failure propagation**: any failed test or run error makes the Go test fail (non-zero exit).
- **Minimal redaction**: redact obvious sensitive keys in logs and JSON (e.g., `client_secret`, tokens).

## Phase 1: Harness Surface + Flags

### Overview
Create a new Go test package that acts as the single-command harness and defines the configuration surface.

### Changes Required:

#### 1. New harness package
**File**: `internal/conformanceharness/harness_test.go` (new)
**Changes**:
- Add a `TestConformanceHarness(t *testing.T)` skipped by default unless `LANYARD_CONFORMANCE=1` (or similar) is set.
- Parse flags via `flag` (test binary flags) for:
  - `-profile` (required when enabled): `oidc-rp|fapi-rp|all-rp`
  - `-suite-url` default `https://suite.test`
  - `-artifacts-dir` default `./artifacts`
  - `-include-plan-regex`, `-exclude-plan-regex`
  - timeouts: `-provision-timeout`, `-plan-timeout`, `-test-timeout`
  - `-keep-running` (don’t tear down compose)
  - `-export-zip` (default true)
  - `-redact` (default true)

### Success Criteria:

#### Automated Verification:
- [x] `go test ./...` still passes with harness disabled by default.
- [x] `go test ./internal/conformanceharness -run TestConformanceHarness` skips with a clear message when `LANYARD_CONFORMANCE!=1`.

#### Manual Verification:
- [x] Running with `LANYARD_CONFORMANCE=1` prints a clear usage/help message when required flags are missing.

---

## Phase 2: Provisioning (docker compose + prerequisites)

### Overview
Automate local provisioning: verify prerequisites, build suite image if needed, start compose, and wait until suite API is reachable.

### Changes Required:

#### 1. Docker compose orchestration helpers
**File**: `internal/conformanceharness/provision.go` (new)
**Changes**:
- Shell out to `docker compose` (Linux only) using `os/exec`.
- Use `conformance/docker-compose.yml` as the compose file.
- Implement:
  - `composeUp(ctx)` / `composeDown(ctx)`
  - optional build step: invoke `conformance/scripts/build_suite.sh` when suite image is missing or `-rebuild-suite` flag is set.
  - readiness probe: poll `GET https://suite.test/api/plan/available` until success.

#### 2. TLS prerequisites validation
**File**: `internal/conformanceharness/prereqs.go` (new)
**Changes**:
- Validate Linux (`runtime.GOOS == "linux"`).
- Validate that `suite.test` and `rp.test` resolve locally (document requirement; optionally check `/etc/hosts`).
- Validate `mkcert` artifacts exist as expected by `conformance/scripts/setup.sh` (do not reimplement; just validate and point to fix).

### Success Criteria:

#### Automated Verification:
- [x] Harness surfaces a clear error when prerequisites are missing.
- [ ] When prerequisites exist, harness brings up the stack and confirms suite API readiness.

#### Manual Verification:
- [ ] `LANYARD_CONFORMANCE=1 go test ...` starts the suite stack without manual steps.
- [ ] `-keep-running` leaves services up for debugging.

---

## Phase 3: Suite API Client + Plan Discovery/Selection

### Overview
Add a small HTTP client that can query available plans and construct the run plan list from `-profile`.

### Changes Required:

#### 1. Suite API client
**File**: `internal/conformanceharness/suiteclient.go` (new)
**Changes**:
- Implement methods:
  - `ListAvailablePlans(ctx) -> []AvailablePlan`
  - `CreatePlan(ctx, planName, config) -> planID`
  - `CreateTestInstance(ctx, testName, planID, variant, config, alias) -> testID`
  - `GetTestInfo(ctx, testID) -> status/result/etc`
  - `ExportPlanZip(ctx, planID) -> []byte` (or stream to file)

#### 2. Profile-to-plan mapping
**File**: `internal/conformanceharness/profiles.go` (new)
**Changes**:
- Define initial mapping rules:
  - `oidc-rp`: include any available plan whose `profile` indicates RP tests and whose name matches known OIDC RP patterns (start with explicit allowlist + regex fallback).
  - `fapi-rp`: include any available plan whose name/profile matches FAPI RP patterns.
  - `all-rp`: union.
- Apply include/exclude regex filters after expansion.
- Persist the selected plan list into the report.

### Success Criteria:

#### Automated Verification:
- [x] Unit tests for profile expansion/filtering using fixture JSON responses.

#### Manual Verification:
- [ ] `-profile=oidc-rp` selects multiple OIDC RP plans when present.
- [ ] `-include-plan-regex` and `-exclude-plan-regex` behave as expected.

---

## Phase 4: Execution Engine (create plan, run tests, poll)

### Overview
Execute each selected plan end-to-end, gather per-test outcomes, enforce timeouts, and produce deterministic failure behavior.

### Changes Required:

#### 1. Plan execution
**File**: `internal/conformanceharness/execute.go` (new)
**Changes**:
- For each selected plan:
  - Create plan via `POST /api/plan` (`TestPlanApi.java:59`).
  - Determine module list from created plan response (or from available plan definition) and support subset selection by optional module name regex filter.
  - For each module/test:
    - Create test instance via `POST /api/runner` (`TestRunner.java:214`).
    - Poll `GET /api/info/{id}` (`TestInfoApi.java:62`) until finished or timeout.
- Mark plan failed if any test result indicates failure/unknown.

#### 2. Deterministic alias routing
**File**: `internal/conformanceharness/execute.go` (new)
**Changes**:
- Use a stable alias per test instance and enforce sequential execution to avoid alias collisions.

### Success Criteria:

#### Automated Verification:
- [ ] Harness fails the Go test when any test result is failed.
- [ ] Harness returns non-zero exit via `go test` failure semantics.

#### Manual Verification:
- [ ] Console output shows: plan start, per-test progress, per-plan summary, final summary.

---

## Phase 5: Reporting + Artifacts (`./artifacts`)

### Overview
Create a structured report artifact and optional evidence ZIP exports.

### Changes Required:

#### 1. Report schema and writer
**File**: `internal/conformanceharness/report.go` (new)
**Changes**:
- Write `./artifacts/<run-id>/report.json` containing:
  - run metadata (timestamp, git SHA if available, suite URL, profile, selected plans)
  - per-plan results (plan name, plan id, duration)
  - per-test results (test name/module, test id, status, result, summary)
  - artifact paths for exported zips
- Implement minimal redaction for known sensitive keys in captured configs/log fragments.

#### 2. Export evidence ZIP
**File**: `internal/conformanceharness/report.go` (new)
**Changes**:
- Download and store plan ZIP via `/api/plan/exporthtml/{id}` (`LogApi.java:530`) into `./artifacts/<run-id>/plan-<planName>-<planID>.zip`.

#### 3. Artifact directory conventions
**File**: `.gitignore`
**Changes**:
- Add `artifacts/` (repo root) ignore.

### Success Criteria:

#### Automated Verification:
- [ ] A JSON report is written under `./artifacts/.../report.json` for every run.
- [ ] Export ZIP is written when `-export-zip=1`.

#### Manual Verification:
- [ ] Report is readable and contains enough detail to debug a failing plan.
- [ ] Redaction prevents raw `client_secret` and tokens from appearing.

---

## Phase 6: Documentation

### Overview
Document the one-command workflow, flags, profiles, artifacts, and common failure modes.

### Changes Required:

#### 1. Conformance docs update
**File**: `conformance/README.md`
**Changes**:
- Add a new “Automated local run” section showing:
  - prerequisite one-time setup (keep existing setup flow)
  - command examples:
    - `LANYARD_CONFORMANCE=1 go test ./internal/conformanceharness -run TestConformanceHarness -args -profile=oidc-rp`
    - include/exclude plan filters
  - where to find artifacts in `./artifacts` and how to interpret `report.json`.

### Success Criteria:

#### Automated Verification:
- [x] `go test ./...` passes.

#### Manual Verification:
- [ ] Maintainer can follow docs from scratch (after existing one-time setup) and run a profile.

---

## Testing Strategy

### Unit Tests:
- Profile expansion/filtering (`profiles.go`).
- Report writer + redaction (`report.go`).

### Integration Tests:
- Harness itself is the integration test (guarded by `LANYARD_CONFORMANCE=1`).

### Manual Testing Steps:
1. Run `conformance/scripts/setup.sh` once (existing flow).
2. Run OIDC RP profile:
   - `LANYARD_CONFORMANCE=1 go test ./internal/conformanceharness -run TestConformanceHarness -args -profile=oidc-rp`
3. Confirm `./artifacts/<run-id>/report.json` exists and summarizes results.
4. Induce a known failure (e.g., temporarily misconfigure RP) and confirm non-zero exit and failure recorded in report.

## Performance Considerations

- Poll intervals should be modest (e.g., 1-2s) to avoid hammering suite APIs.
- Sequential execution is preferred initially for determinism and debuggability; parallelism can be a follow-up.

## Migration Notes

- Existing documentation and `conformance/artifacts/` can remain for now, but this feature will standardize on `./artifacts` for automation outputs.

## References

- Original ticket: `thoughts/tickets/feature_conformance_suite_execution_automation.md`
- Prior plan (local setup): `thoughts/plans/openid_conformance_local.md`
- Suite APIs:
  - `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/info/TestPlanApi.java:59`
  - `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/info/TestPlanApi.java:270`
  - `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:214`
  - `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/info/TestInfoApi.java:62`
  - `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/logging/LogApi.java:530`
