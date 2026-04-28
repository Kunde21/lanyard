# Conformance Parallel Runner Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate the current local conformance harness and example RP from a serial, shared-state model to an in-process parallel runner with isolated goroutines and per-job RP configuration, then prepare the first `plain_fapi` matrix cases on top of that design.

**Architecture:** Introduce a `RunJob` expansion layer between suite plan discovery and execution, run jobs through a bounded parallel scheduler, and move mutable execution state into per-job envelopes. On the RP side, replace static global profile behavior with an alias-keyed runtime registry and namespaced state storage so one shared RP server can safely emulate distinct conformance clients at the same time.

**Tech Stack:** Go, `go test`, existing conformance harness in `conformance/harness`, example RP in `cmd/example-rp`, standard library concurrency primitives, cookie-backed RP state storage, OpenID conformance suite HTTP API

---

### Task 1: Lock in the new runner shape with failing unit tests

**Files:**
- Create: `conformance/harness/jobs_test.go`
- Modify: `conformance/harness/execute_test.go`
- Modify: `conformance/harness/report_test.go`
- Test: `conformance/harness/jobs_test.go`

**Step 1: Write failing tests for job expansion**

Create `conformance/harness/jobs_test.go` and define table-driven tests for a new `expandRunJobs` helper. Cover these expectations:

- one selected OIDC plan with no matrix expansion yields one `RunJob`
- one selected FAPI RP plan with no explicit matrix mode yields one `RunJob`
- a `plain_fapi` matrix mode yields one `RunJob` per requested combination
- each expanded job carries a unique logical job id and alias seed

Use a small fake `AvailablePlan` payload so the tests stay local.

**Step 2: Write failing tests for per-job execution isolation**

Extend `conformance/harness/execute_test.go` with tests for a future job runner constructor. Assert that two separately constructed job runners do not share:

- front-channel HTTP client pointer
- cookie jar pointer
- artifact subdirectory
- alias

The test should fail until mutable state is moved out of the top-level shared `runner`.

**Step 3: Write a failing report test for job-aware output**

Extend `conformance/harness/report_test.go` to expect report entries to include job identity fields such as `job_id`, `alias`, and `variant`. Keep the existing plan-oriented report shape, but assert those job fields are present in per-test or per-job structures.

**Step 4: Run targeted harness tests**

Run: `go test ./conformance/harness -run 'TestExpandRunJobs|TestJobRunner|TestWriteReport' -count=1`

Expected: FAIL because job expansion, job-local execution state, and job-aware report fields do not exist yet.

**Step 5: Commit**

```bash
git add conformance/harness/jobs_test.go conformance/harness/execute_test.go conformance/harness/report_test.go
git commit -m "test: lock in parallel conformance runner shape"
```

### Task 2: Add job and matrix domain models without changing behavior

**Files:**
- Create: `conformance/harness/jobs.go`
- Create: `conformance/harness/matrix.go`
- Modify: `conformance/harness/config.go`
- Modify: `conformance/harness/harness_test.go`
- Modify: `conformance/harness/variants.go`
- Test: `conformance/harness/jobs_test.go`

**Step 1: Add the `RunJob` model**

Create `conformance/harness/jobs.go` and define small, explicit types:

- `RunJob`
- `JobVariant`
- `RPProfileConfig`
- `JobSelection`

`RunJob` should hold:

- stable `JobID`
- suite `PlanName`
- selected plan/module variants
- `Alias`
- `RPProfileConfig`
- job artifact path suffix

Do not add scheduler logic yet.

**Step 2: Add config fields for matrix and parallel mode**

Update `conformance/harness/config.go` and `conformance/harness/harness_test.go` flag parsing to add placeholders for:

- `MaxParallelRuns int`
- `Parallel bool`
- `Matrix string`
- `FailFast bool`

Parse the flags but keep default behavior equivalent to today: one job per selected plan, serial execution unless explicitly enabled.

**Step 3: Add matrix expansion helpers**

Create `conformance/harness/matrix.go` with helpers that can return requested `plain_fapi` combinations from a named matrix mode. Start small:

- `"off"` or empty means no expansion
- `"fapi2-sp-final-plain-fapi-first4"` returns the first four baseline combinations
- `"fapi2-sp-final-plain-fapi-all16"` returns all 16 combinations

Do not wire them into execution yet.

**Step 4: Implement `expandRunJobs`**

In `conformance/harness/jobs.go`, implement `expandRunJobs(cfg, plans)` to transform selected plans into `RunJob` values.

Rules:

- non-matrix plans yield one job
- matrix mode only expands matching FAPI2 SP Final RP plans
- aliases are generated from run id seed + job index + short variant label
- the function is deterministic for tests

**Step 5: Run targeted tests**

Run: `go test ./conformance/harness -run 'TestExpandRunJobs' -count=1`

Expected: PASS.

**Step 6: Commit**

```bash
git add conformance/harness/jobs.go conformance/harness/matrix.go conformance/harness/config.go conformance/harness/harness_test.go conformance/harness/variants.go
git commit -m "feat: add conformance job and matrix models"
```

### Task 3: Refactor execution into per-job runners while staying serial

**Files:**
- Modify: `conformance/harness/execute.go`
- Create: `conformance/harness/job_runner.go`
- Modify: `conformance/harness/execute_helpers.go`
- Modify: `conformance/harness/execute_test.go`
- Test: `conformance/harness/execute_test.go`

**Step 1: Extract job-local mutable state**

Create `conformance/harness/job_runner.go` and move mutable state currently stored in `runner` into a per-job struct, for example:

- `suiteClient`
- front-channel HTTP client
- cookie jar
- job logger prefix
- artifact subpath

The top-level `runner` should keep only immutable orchestrator config and helper dependencies.

**Step 2: Convert plan execution into job execution**

Refactor `conformance/harness/execute.go` so `Execute` works with `[]RunJob` instead of raw `[]AvailablePlan` once selection is complete.

For now, keep the loop serial:

```go
for _, job := range jobs {
    res := r.executeJob(ctx, job)
    ...
}
```

This keeps behavior easy to compare while isolation work lands first.

**Step 3: Preserve existing front-channel trigger behavior**

Make sure job execution still calls existing trigger helpers for module flows and still builds issuers from suite info, but do it from the job-local runner.

**Step 4: Update tests to assert job-local isolation**

Make the new tests from Task 1 pass and add one more test asserting that executing two jobs in sequence produces different aliases even for the same plan name.

**Step 5: Run targeted tests**

Run: `go test ./conformance/harness -run 'TestJobRunner|TestPollTestResult|TestModuleTriggerEndpoint' -count=1`

Expected: PASS.

**Step 6: Commit**

```bash
git add conformance/harness/execute.go conformance/harness/job_runner.go conformance/harness/execute_helpers.go conformance/harness/execute_test.go
git commit -m "refactor: isolate conformance execution state per job"
```

### Task 4: Introduce bounded parallel job scheduling

**Files:**
- Modify: `conformance/harness/execute.go`
- Create: `conformance/harness/scheduler.go`
- Create: `conformance/harness/scheduler_test.go`
- Modify: `conformance/harness/config.go`
- Modify: `conformance/harness/harness_test.go`
- Test: `conformance/harness/scheduler_test.go`

**Step 1: Write failing scheduler tests**

Create `conformance/harness/scheduler_test.go` and cover:

- max parallelism is respected
- all submitted jobs eventually run
- fail-safe mode lets remaining jobs continue after one job failure
- fail-fast mode cancels queued jobs after first failure

Use fake job functions with channels and sleeps, not real suite calls.

**Step 2: Implement bounded worker scheduling**

Create `conformance/harness/scheduler.go` with a small scheduler using goroutines and either a semaphore channel or worker pool. Keep it simple:

- feed `RunJob` values into a buffered work channel
- each worker executes one job at a time
- results flow back through a result channel

**Step 3: Wire `Execute` to the scheduler**

Update `conformance/harness/execute.go` so parallel mode schedules jobs concurrently and serial mode still uses one worker. Preserve stable final report ordering by sorting results by job id before writing them out.

**Step 4: Run scheduler tests**

Run: `go test ./conformance/harness -run 'TestScheduler' -count=1`

Expected: PASS.

**Step 5: Run broader harness tests**

Run: `go test ./conformance/harness -count=1`

Expected: PASS.

**Step 6: Commit**

```bash
git add conformance/harness/scheduler.go conformance/harness/scheduler_test.go conformance/harness/execute.go conformance/harness/config.go conformance/harness/harness_test.go
git commit -m "feat: add bounded parallel conformance job scheduler"
```

### Task 5: Add job-aware report structures and artifact isolation

**Files:**
- Modify: `conformance/harness/report.go`
- Modify: `conformance/harness/report_test.go`
- Modify: `conformance/harness/execute.go`
- Test: `conformance/harness/report_test.go`

**Step 1: Add report fields for job identity**

Extend report structures so each executed unit records:

- `job_id`
- `alias`
- `plan_name`
- `variant`
- job artifact directory or artifact prefix

Keep existing plan information where it still helps compatibility.

**Step 2: Isolate zip and report artifact paths per job or per plan inside a run dir**

Update `conformance/harness/report.go` so concurrent runs never race on one filename. Use a path pattern such as:

```text
artifacts/<run-id>/jobs/<job-id>/...
```

If plan-level zip export stays shared, keep filenames unique with both `job-id` and `plan-id`.

**Step 3: Update tests for report serialization**

Make the failing report tests pass and add one regression test that two job results with the same plan name serialize to distinct artifact paths.

**Step 4: Run targeted tests**

Run: `go test ./conformance/harness -run 'TestWriteReport|TestRedactReport' -count=1`

Expected: PASS.

**Step 5: Commit**

```bash
git add conformance/harness/report.go conformance/harness/report_test.go conformance/harness/execute.go
git commit -m "feat: add job-aware conformance reporting"
```

### Task 6: Add RP runtime registry tests before changing RP behavior

**Files:**
- Create: `cmd/example-rp/runtime_registry.go`
- Create: `cmd/example-rp/runtime_registry_test.go`
- Modify: `cmd/example-rp/main.go`
- Test: `cmd/example-rp/runtime_registry_test.go`

**Step 1: Write failing registry tests**

Create `cmd/example-rp/runtime_registry_test.go` and lock in the following behavior:

- register runtime config by alias
- resolve runtime config by issuer containing `/test/a/{alias}`
- fail lookup for unknown alias
- unregister runtime config after cleanup

Use explicit structs rather than `map[string]any`.

**Step 2: Write a failing test for state namespace separation**

Add a test that creates two runtime configs with distinct cookie namespaces and asserts they do not produce the same namespace key.

**Step 3: Run RP registry tests**

Run: `go test ./cmd/example-rp -run 'TestRuntimeRegistry|TestRuntimeNamespace' -count=1`

Expected: FAIL because the registry does not exist yet.

**Step 4: Commit**

```bash
git add cmd/example-rp/runtime_registry_test.go
git commit -m "test: lock in rp runtime registry behavior"
```

### Task 7: Implement alias-keyed RP runtime configuration and namespaced state storage

**Files:**
- Modify: `cmd/example-rp/main.go`
- Modify: `cmd/example-rp/runtime_registry.go`
- Create: `cmd/example-rp/state_store_namespace.go`
- Create: `cmd/example-rp/state_store_namespace_test.go`
- Test: `cmd/example-rp/runtime_registry_test.go`
- Test: `cmd/example-rp/state_store_namespace_test.go`

**Step 1: Implement the runtime registry**

Create `cmd/example-rp/runtime_registry.go` with:

- a concurrency-safe registry
- explicit `Register`, `Lookup`, `Delete`, and `LookupByIssuer` methods
- runtime entries containing client id, client secret, redirect URI, scopes, auth mode, and token transport selection

**Step 2: Implement namespaced state-store wrapping**

Create `cmd/example-rp/state_store_namespace.go` and wrap the existing cookie-backed store so state keys are prefixed by a runtime namespace derived from alias or job id.

Keep the implementation minimal: the goal is strict separation, not a generic storage framework.

**Step 3: Change request-time RP construction**

Update `cmd/example-rp/main.go` so `/login`, `/login-userinfo-body`, and `/callback` resolve a runtime entry from the request issuer alias before building the RP client.

Rules:

- if a runtime entry exists, it overrides global env defaults
- if the request includes a suite issuer alias but no runtime exists, return a clear 500 with a deterministic error string for testability
- manual local mode without an issuer alias may still use env defaults

**Step 4: Run RP tests**

Run: `go test ./cmd/example-rp -count=1`

Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/example-rp/main.go cmd/example-rp/runtime_registry.go cmd/example-rp/state_store_namespace.go cmd/example-rp/runtime_registry_test.go cmd/example-rp/state_store_namespace_test.go
git commit -m "feat: add alias-keyed rp runtime isolation"
```

### Task 8: Let the harness register and clean up RP runtimes per job

**Files:**
- Create: `conformance/harness/rpruntime.go`
- Create: `conformance/harness/rpruntime_test.go`
- Modify: `conformance/harness/job_runner.go`
- Modify: `cmd/example-rp/main.go`
- Test: `conformance/harness/rpruntime_test.go`

**Step 1: Define the harness-to-RP runtime contract**

Create `conformance/harness/rpruntime.go` with a small client abstraction for registering and deleting runtime entries against the RP process. If an HTTP admin endpoint is needed, define that contract explicitly and keep it local-only.

Suggested payload fields:

- alias
- client credentials
- redirect URI
- scopes
- token transport mode
- profile flags
- namespace key

**Step 2: Write failing tests for runtime registration lifecycle**

Create `conformance/harness/rpruntime_test.go` with an `httptest` server and assert:

- registration is called before suite execution begins
- cleanup runs on success
- cleanup still runs when job execution fails

**Step 3: Wire job execution to RP runtime registration**

Update `conformance/harness/job_runner.go` so each job:

- registers its runtime before creating the suite plan or before triggering the front channel, whichever is required by the flow
- deletes its runtime during deferred cleanup

**Step 4: Add the RP admin endpoints if needed**

If you choose HTTP registration, add local-only endpoints in `cmd/example-rp/main.go` for register/delete/list debug operations and guard them with local-only assumptions.

**Step 5: Run targeted tests**

Run: `go test ./conformance/harness -run 'TestRPRuntime' -count=1`

Expected: PASS.

**Step 6: Commit**

```bash
git add conformance/harness/rpruntime.go conformance/harness/rpruntime_test.go conformance/harness/job_runner.go cmd/example-rp/main.go
git commit -m "feat: register rp runtimes per conformance job"
```

### Task 9: Migrate existing selected profiles to job-based execution

**Files:**
- Modify: `conformance/harness/profiles.go`
- Modify: `conformance/harness/harness_test.go`
- Modify: `conformance/README.md`
- Modify: `conformance/AGENTS.md`
- Test: `conformance/harness/profiles_test.go`

**Step 1: Keep current profile selection semantics but emit jobs**

Update the selection flow so existing `oidc-rp`, `fapi-rp`, and `all-rp` flags still select the same top-level plans, but downstream execution now always happens through `RunJob` expansion.

This migration should be invisible to current users when matrix mode is off.

**Step 2: Add tests proving backward compatibility**

Extend `conformance/harness/profiles_test.go` to assert that the same plans are still selected for existing profile flags before job expansion occurs.

**Step 3: Update docs for new execution model**

Update `conformance/README.md` and `conformance/AGENTS.md` with:

- new parallel flags
- new matrix flags
- note that current profiles now execute as job expansions
- note that aliases must be unique and are generated automatically

**Step 4: Run tests**

Run: `go test ./conformance/harness -run 'TestSelectPlans' -count=1`

Expected: PASS.

**Step 5: Commit**

```bash
git add conformance/harness/profiles.go conformance/harness/harness_test.go conformance/harness/profiles_test.go conformance/README.md conformance/AGENTS.md
git commit -m "docs: migrate conformance profiles onto job execution model"
```

### Task 10: Prepare the first `plain_fapi` matrix cases

**Files:**
- Modify: `conformance/harness/matrix.go`
- Create: `conformance/harness/matrix_test.go`
- Modify: `thoughts/architecture/2026-03-23_fapi2_sp_final_plain_fapi_rp_test_matrix.md`
- Test: `conformance/harness/matrix_test.go`

**Step 1: Write failing tests for the first matrix subset**

Create `conformance/harness/matrix_test.go` and assert that `fapi2-sp-final-plain-fapi-first4` expands to exactly these combinations:

- `private_key_jwt + mtls + simple + oidc`
- `private_key_jwt + dpop + simple + oidc`
- `mtls + mtls + simple + oidc`
- `mtls + dpop + simple + oidc`

Also assert that each case produces a distinct alias suffix and RP runtime config.

**Step 2: Implement the first matrix subset**

Update `conformance/harness/matrix.go` so the first four combinations are emitted in a stable order and mapped into both suite variant values and RP runtime config values.

**Step 3: Update the architecture reference note**

Append a short note to `thoughts/architecture/2026-03-23_fapi2_sp_final_plain_fapi_rp_test_matrix.md` indicating that the first implementation milestone uses the first four `simple + oidc` combinations as the bring-up subset.

**Step 4: Run matrix tests**

Run: `go test ./conformance/harness -run 'TestPlainFAPIMatrix' -count=1`

Expected: PASS.

**Step 5: Commit**

```bash
git add conformance/harness/matrix.go conformance/harness/matrix_test.go thoughts/architecture/2026-03-23_fapi2_sp_final_plain_fapi_rp_test_matrix.md
git commit -m "feat: prepare first plain fapi matrix cases"
```

### Task 11: Verify end-to-end behavior with parallel local runs

**Files:**
- Modify: `conformance/README.md`
- Modify: `conformance/AGENTS.md`
- Test: `conformance/harness`

**Step 1: Run focused harness unit tests**

Run: `go test ./conformance/harness -count=1`

Expected: PASS.

**Step 2: Run example RP tests**

Run: `go test ./cmd/example-rp -count=1`

Expected: PASS.

**Step 3: Run a local conformance smoke execution for the first four matrix cases**

Run:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -parallel=true \
  -max-parallel-runs=4 \
  -matrix=fapi2-sp-final-plain-fapi-first4
```

Expected:

- four jobs are created
- each gets a unique alias
- the RP logs show distinct runtime registrations
- no alias-conflict interruption occurs
- artifacts are written to distinct job directories

**Step 4: Document the smoke command and known caveats**

Update `conformance/README.md` and `conformance/AGENTS.md` with the exact smoke command and notes about suite resource limits, cleanup behavior, and how to inspect per-job artifacts.

**Step 5: Commit**

```bash
git add conformance/README.md conformance/AGENTS.md
git commit -m "docs: add parallel conformance smoke workflow"
```

### Task 12: Final verification before widening to all 16 `plain_fapi` cases

**Files:**
- Test: `conformance/harness`
- Test: `cmd/example-rp`

**Step 1: Run formatting and targeted verification**

Run: `gofumpt ./conformance/... ./cmd/example-rp/...`

Expected: files are formatted without large mechanical diffs beyond touched code.

**Step 2: Run Go tests for touched packages**

Run: `go test ./conformance/harness ./cmd/example-rp -count=1`

Expected: PASS.

**Step 3: Run the first-four parallel smoke again from a clean stack**

Run:

```bash
docker compose -f conformance/docker-compose.yml down -v
docker compose -f conformance/docker-compose.yml up -d
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -parallel=true \
  -max-parallel-runs=4 \
  -matrix=fapi2-sp-final-plain-fapi-first4
```

Expected: PASS or a failure mode that is clearly attributable to one job, not cross-job interference.

**Step 4: Record widening criteria in the implementation notes**

Before moving from `first4` to `all16`, confirm:

- no shared cookie collisions
- no RP runtime lookup misses
- no suite alias conflict messages
- per-job artifact and report isolation is intact

**Step 5: Commit**

```bash
git add docs/plans/2026-03-23-conformance-parallel-runner-migration.md
git commit -m "chore: verify parallel conformance migration readiness"
```
