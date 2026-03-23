---
date: 2026-03-23T00:00:00Z
repository: lanyard
topic: "Parallel conformance runner with isolated RP configuration"
tags: [architecture, conformance, runner, parallelism, rp, isolation]
last_updated: 2026-03-23
---

# Parallel Conformance Runner with Isolated RP Configuration

## Summary

The conformance harness should be redesigned to execute all selected relying party conformance profiles in parallel within a single Go process. Each run must execute in its own goroutine with isolated test identity, browser session state, artifacts, and relying party configuration so that the local RP behavior matches the exact suite profile under test.

This design keeps the OpenID conformance suite as a shared external system, but treats each profile or profile-variant run as an independent job with its own runtime envelope. The current serial harness is retained conceptually as the orchestration boundary, but its internal execution model changes from sequential plan/module loops to bounded parallel job scheduling.

## Problem Statement

The current harness and local RP setup are not safe for parallel conformance execution.

- The harness executes plans and modules serially in `conformance/harness/execute.go:94`.
- The harness reuses one front-channel HTTP client and one cookie jar across the entire run in `conformance/harness/execute.go:33`.
- The local example RP uses a shared cookie-backed state store in `cmd/example-rp/main.go:25`.
- The suite itself can execute tests concurrently, but alias conflicts can stop in-flight tests, and aliases must be unique per run in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:429`.
- The suite dispatches requests by test id or alias, so alias-based isolation is a primary routing boundary in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestDispatcher.java:69`.

Because of these constraints, simply adding goroutines around the existing runner would create cross-run interference through cookies, callback state, alias reuse, and static RP configuration.

## Goals

- Run all selected conformance profiles in parallel in one process.
- Use isolated goroutines as the execution unit for each profile or profile-variant run.
- Ensure each run uses RP behavior and metadata that match the exact suite profile under test.
- Prevent cross-run interference in cookies, state, aliasing, callback handling, and artifacts.
- Preserve a single aggregated report across the full run.
- Allow bounded concurrency so local machines are not overloaded.

## Non-Goals

- Do not run the suite itself in multiple containers.
- Do not require one OS process per conformance profile.
- Do not require one RP container per profile.
- Do not redesign the upstream suite.
- Do not optimize first for minimal code churn if it compromises isolation.

## Requirements

### Functional Requirements

- The runner must expand selected profiles into an explicit set of executable jobs.
- The runner must start those jobs in parallel using independent goroutines.
- Each job must generate a unique suite alias.
- Each job must use an independent front-channel HTTP client and cookie jar.
- Each job must provision independent RP configuration inputs matching the job's profile and variants.
- The RP must resolve configuration per job at request time rather than from one static global profile.
- The final report must include per-job, per-plan, and per-test outcomes.

### Isolation Requirements

- No shared cookie jar across jobs.
- No shared mutable RP state namespace across jobs.
- No alias reuse across jobs.
- No shared artifact output path across jobs.
- No accidental reuse of one profile's RP metadata in another profile's flow.

### Operational Requirements

- Concurrency must be bounded by configuration.
- Failed jobs must not corrupt other jobs.
- Cancellation must propagate cleanly to in-flight jobs.
- Debugging artifacts must remain attributable to one job.

## Current State Constraints

### Conformance Suite

The suite supports concurrent work internally.

- `TestRunner` uses a cached thread pool in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:133`.
- Test background tasks are scheduled per test in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestExecutionManager.java:130`.
- Alias mappings and running test maps are shared global state in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/InMemoryTestRunnerSupport.java:26`.
- Alias conflicts can stop a running test in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:462`.

The suite is therefore concurrency-capable but not isolation-providing. Isolation is the responsibility of the local runner and RP.

### Local Harness

The harness is currently single-threaded at the plan/module execution level.

- Plans execute in a loop in `conformance/harness/execute.go:101`.
- Modules execute in a loop in `conformance/harness/execute.go:152`.
- One `frontClient` is reused for all test interactions in `conformance/harness/execute.go:26`.

### Local RP

The RP currently behaves like a single shared application instance.

- One shared state store is constructed in `cmd/example-rp/main.go:25`.
- RP configuration is derived from request context plus global env in `cmd/example-rp/main.go:67`.
- Some issuer-derived behavior already depends on the alias path in `cmd/example-rp/main.go:241`.

This is a useful starting point because the RP already sees the issuer URL, but the design must replace implicit global behavior with explicit per-job configuration resolution.

## Proposed Architecture

### Overview

The system should be organized into five layers:

1. `Profile expander` - turns selected suite plans and forced variants into concrete executable jobs.
2. `Parallel scheduler` - runs jobs in isolated goroutines with bounded concurrency.
3. `Job runner` - owns all suite API calls, front-channel browser state, and artifacts for one job.
4. `RP runtime registry` - stores per-job RP configuration keyed by a job identity derived from alias.
5. `Result aggregator` - collects structured results from all jobs into one final report.

### Execution Unit: `RunJob`

The core architectural unit is a `RunJob`. A `RunJob` represents one independently executable conformance profile or profile-variant combination.

Each `RunJob` includes:

- job id
- suite plan name
- plan variant
- module filter or module list
- unique alias
- RP profile configuration
- artifact directory
- timeout settings
- result channel handles

The design assumes that the runner can express the plain profile matrix explicitly. For example, the 16 `plain_fapi` combinations become 16 distinct `RunJob` values, each with its own RP profile inputs.

### Scheduler Model

The top-level runner should:

- discover available plans from the suite
- select plans according to current CLI filters
- expand selected plans into `RunJob` values
- submit jobs to a bounded worker pool
- launch one goroutine per admitted job
- wait on completion through channels or an `errgroup`-style coordinator

Bounded concurrency should be configurable with a new flag such as `-max-parallel-runs`.

The scheduler is responsible for orchestration only. It must not own mutable per-job session state.

### Per-Job Isolation Envelope

Each goroutine must construct and own its own runtime envelope.

Per-job state must include:

- suite client wrapper if it carries mutable request state
- front-channel HTTP client
- cookie jar
- artifact writer
- logger prefix
- cancellation context
- unique alias
- RP registration payload or RP lookup key

No mutable object inside this envelope may be shared with another job.

## RP Configuration Isolation Design

### Core Requirement

The RP must behave as if it were a distinct client instance for each conformance job, even though the server process stays shared.

### RP Runtime Registry

Introduce an in-memory RP runtime registry keyed by alias or a derived job key.

Each entry should include:

- client metadata expected for the run
- auth method selection
- sender constraint mode
- requested scopes
- request type behavior
- DPoP settings
- MTLS settings
- state store namespace
- any profile-specific toggles

The harness registers this configuration before starting a suite test instance, and removes it after completion or timeout.

### Request-Time RP Resolution

The RP handlers should stop treating configuration as primarily process-global. Instead, on each `/login` and `/callback` request, the RP should:

- resolve the `issuer` query parameter
- extract the alias from `/test/a/{alias}` when present
- look up the registered RP runtime entry for that alias
- construct or retrieve an RP client using that entry
- use a state store namespace that belongs only to that alias/job

If no matching runtime entry exists, the RP should fail fast with a clear error indicating that no registered conformance runtime was found for the issuer alias.

### State Store Namespacing

The current shared cookie-backed store is not sufficient as a global singleton for parallel jobs.

The design should introduce one of these patterns:

- per-job state store instances with unique cookie name prefixes, or
- a namespaced wrapper around the cookie store that scopes keys by alias/job id

The required outcome is the same: one job's login and callback state must never satisfy another job's callback.

### RP Config Source of Truth

The harness, not environment variables, becomes the source of truth for conformance-run RP behavior.

Environment variables may remain defaults for manual local use, but automated conformance execution must populate an explicit runtime config object for each job.

## Data Flow

### 1. Discovery and Expansion

- Query `GET /api/plan/available`
- Select plans according to CLI profile filters
- Expand each selected profile into one or more `RunJob` values
- Attach exact variant values and derived RP config to each job

### 2. Job Registration

For each job:

- generate unique alias
- create artifact directory
- register RP runtime config in the RP registry
- build suite plan config using that alias and profile-specific client inputs

### 3. Parallel Execution

For each scheduled goroutine:

- create plan in the suite
- create module instance or instances
- fetch test info to confirm suite alias and issuer
- drive front-channel interactions with its own HTTP client and cookie jar
- poll suite status until terminal or timeout

### 4. Completion and Cleanup

On completion:

- export artifacts
- mark result state
- unregister RP runtime config
- cancel suite test if still running
- close job-local resources if applicable

### 5. Aggregation

- merge job results into one run report
- preserve job identity, alias, plan, module, and profile metadata
- keep failures attributable to one job only

## Concurrency and Safety Rules

### Alias Policy

Alias uniqueness is mandatory.

- Every job alias must be globally unique within a run.
- Alias generation should include run id plus job id or a random suffix.
- No fallback alias such as `lanyard-local` may be used in parallel mode.

### Shared Components

These components may remain shared:

- the suite deployment
- static read-only plan metadata cache
- result aggregation structures protected by channels or mutexes

These components must not be shared across jobs:

- browser cookies
- redirect/login state
- alias value
- RP runtime config object
- temporary artifacts and logs written by the job

### Failure Containment

One job failure must not cancel unrelated jobs by default.

Config should support two modes:

- fail-fast: cancel all remaining jobs on first hard failure
- fail-safe: continue running remaining jobs and report all failures

Default should be fail-safe for matrix execution.

## Proposed Component Changes

### `conformance/harness`

- Add a `RunJob` model.
- Add job expansion from selected plans and variants.
- Replace serial loops with a bounded parallel scheduler.
- Move mutable run state from `runner` into per-job runner instances.
- Add job-scoped artifact output directories.
- Add explicit alias generation service.

### `cmd/example-rp`

- Add a runtime registry keyed by alias.
- Resolve RP config per request from issuer alias.
- Introduce state-store namespacing or per-job state stores.
- Support job-specific DPoP, MTLS, scopes, and client metadata.
- Return precise errors when a request references an unknown or expired runtime.

### Configuration Surface

Add flags or config fields such as:

- `-max-parallel-runs`
- `-parallel-mode` or a boolean equivalent
- `-fail-fast`
- `-job-alias-prefix`

Also add internal config models for:

- RP runtime registration
- per-job client metadata
- job expansion for matrix runs

## Error Handling

### Categories

- discovery errors
- plan creation errors
- alias registration errors
- RP runtime lookup errors
- front-channel interaction errors
- timeout and cancellation errors
- artifact export errors

### Handling Strategy

- Fail before scheduling if discovery or expansion is invalid.
- Fail one job, not the whole run, for per-job suite or RP errors unless fail-fast is enabled.
- Always attempt job cleanup even after test failure.
- Record cleanup failures separately from primary test failures.
- Surface unknown-alias RP requests as explicit configuration isolation errors.

## Reporting and Observability

The final report must evolve from plan-centric to job-centric while preserving compatibility where practical.

Recommended additions:

- job id
- alias
- exact profile/variant map
- RP config summary
- artifact path
- goroutine start and finish timestamps

Logs should prefix every line with a stable job label so concurrent output remains readable.

## Testing Strategy

### Unit Tests

- alias generation uniqueness
- job expansion correctness
- bounded scheduler behavior
- result aggregation under concurrent completion
- RP runtime registry lookup and cleanup
- state store namespacing behavior

### Integration Tests

- two concurrent jobs with different aliases complete without cookie/state collision
- two concurrent jobs using different RP auth modes produce different RP runtime configs
- one failed job does not corrupt another successful job
- artifact outputs remain separated by job

### Conformance Validation

- run the 8-case must-run `plain_fapi` subset in parallel
- run the full 16-case `plain_fapi` matrix in parallel
- verify that each run's RP config matches the intended suite variant
- verify that suite aliases are unique and no alias-conflict interruption occurs

## Rollout Plan

### Phase 1

- Introduce `RunJob` and job expansion without changing execution semantics.
- Add alias service and job-scoped artifact paths.

### Phase 2

- Implement bounded parallel scheduling in the harness.
- Move front-channel state to per-job clients.

### Phase 3

- Add RP runtime registry and request-time config resolution.
- Add namespaced state storage.

### Phase 4

- Enable parallel execution for selected FAPI profile matrices.
- Validate with the `plain_fapi` subset, then full matrix.

### Phase 5

- Generalize the pattern to all supported RP conformance profiles.

## Alternatives Considered

### Separate OS Process Per Run

This gives stronger isolation but adds orchestration complexity and departs from the requirement that parallelism be expressed through isolated goroutines inside one process.

### Dedicated RP Container Per Run

This gives strong application isolation but introduces heavy provisioning overhead and larger changes to local infrastructure. It is not necessary if the RP can resolve runtime config and state by alias safely.

### Keep Serial Runner and Only Parallelize Plan Creation

This does not satisfy the requirement. The primary bottleneck is end-to-end test execution and RP isolation, not just plan creation.

## Recommended Decision

Adopt an in-process parallel runner architecture built around isolated `RunJob` goroutines, a bounded scheduler, and an alias-keyed RP runtime registry.

This is the smallest architecture that satisfies all of the following simultaneously:

- all selected conformance profiles run in parallel
- each run is isolated enough for safe suite interaction
- the shared local RP can still match the exact profile under test
- the implementation remains native to the current Go harness design

## Source References

- Current serial execution: `conformance/harness/execute.go:94`
- Shared front-channel client: `conformance/harness/execute.go:26`
- Current plan config alias behavior: `conformance/harness/execute.go:543`
- Shared RP state store: `cmd/example-rp/main.go:25`
- Request-time RP construction: `cmd/example-rp/main.go:67`
- Alias extraction from issuer path: `cmd/example-rp/main.go:241`
- Suite executor thread pool: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:133`
- Alias conflict behavior: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestRunner.java:429`
- Running test and alias registry: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/InMemoryTestRunnerSupport.java:26`
- Alias-based test dispatch: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/runner/TestDispatcher.java:69`
- FAPI2 RP per-test base URL configuration: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java:337`
