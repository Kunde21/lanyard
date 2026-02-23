---
type: feature
priority: high
created: 2026-02-23T00:00:00Z
status: created
tags: [conformance, oidc, automation, local-dev, browser-automation]
keywords: [conformance suite, OIDC RP Basic, test plan, plan_id, /api/plan, /api/runner, /api/info, WAITING, chromedp, docker compose, suite.test, rp.test]
patterns: [api-driven plan runner, polling with timeouts, docker compose orchestration, headless browser automation, WAITING-state recovery, artifact/report generation]
---

# FEATURE-005: Automate Conformance Plan Execution (API Runner + UI Helpers)

## Description
Build an end-to-end, one-command local automation that (1) provisions the local OpenID conformance stack, (2) creates and executes the OIDC RP Basic conformance test plan via suite HTTP APIs, and (3) handles suite UI-driven "WAITING" prompts via headless Chrome automation (chromedp), producing console progress output + a JSON report.

## Context
Current local conformance runs require manual steps in the suite UI (plan creation, execution, and sometimes actions to resume when tests enter WAITING). This is slow and inconsistent across runs.

This feature targets maintainers running locally on Linux only.

## Requirements

### Functional Requirements
- Provide a single local command entrypoint (Go `go test` harness/wrapper gated by env var) that provisions, runs, and reports a conformance execution.
- Provision local services automatically (docker compose up + readiness probe) against `https://suite.test` and `https://rp.test`.
- Support OIDC RP Basic first (suite plan equivalent of “OpenID Connect Core: Basic Certification Profile Relying Party Tests”).
- Create a plan instance via suite API (`POST /api/plan`) and capture `plan_id`.
- Execute the plan by creating test instances (`POST /api/runner`), starting when necessary, and polling for completion (`GET /api/info/{id}`).
- If a test transitions into `WAITING`, attempt to auto-resume by driving the suite UI headlessly (chromedp) and then continue polling.
- Run all modules/tests in the selected plan even if some fail; final exit is non-zero if any test fails or the run errors.
- Emit console progress (plan start/end, per-test status changes, final summary).
- Write a machine-readable JSON report under `conformance/artifacts/<run-id>/report.json` with per-plan and per-test statuses/IDs/timings.

### Non-Functional Requirements
- Linux-only.
- Headless Chrome by default; provide a debug option to run headed.
- No suite UI/API authentication support (assume local stack is open).
- No CI integration.
- No retries/flakiness mitigation beyond existing timeouts.
- No historical trend reporting.
- Evidence ZIP/package export/download is out of scope.

## Current State
- Local conformance requires manual plan creation/execution through `https://suite.test`.
- Automation exists to provision the stack (scripts/docker compose), but does not reliably create and execute a test plan end-to-end, nor resolve WAITING states automatically.

## Desired State
Maintainers run one command to:
1) (Optionally) clean any prior suite state,
2) start/verify the conformance stack,
3) create + execute the OIDC RP Basic plan,
4) auto-handle WAITING prompts via headless browser automation,
5) produce `conformance/artifacts/<run-id>/report.json`, and
6) exit non-zero if the run fails.

## Research Context

### Keywords to Search
- `GET /api/plan/available` - discover plan names/variants for OIDC RP Basic
- `POST /api/plan` / `plan_id` - create a plan instance to execute
- `POST /api/runner` - create test instances for plan modules
- `GET /api/info/{id}` - poll status/result, detect `WAITING`
- `WAITING` - determine how the suite expects a waiting test to be resumed
- `chromedp` - headless Chrome automation library for suite UI interactions
- `docker compose -f conformance/docker-compose.yml` - provisioning and lifecycle
- `suite.test` / `rp.test` - local endpoints and TLS/trust assumptions
- `conformance/` - existing scripts, docs, compose, and harness/client code

### Patterns to Investigate
- API-driven runner patterns: deterministic, sequential execution; timeouts; failure propagation.
- UI automation patterns for upstream UIs: stable selectors, resilience to minor UI changes, and clear failure diagnostics.
- WAITING-state recovery strategy: what UI action(s) unblocks progress (e.g., clicking “Continue”, “Proceed”, reloading, or opening a specific test instance page).
- TLS handling for headless Chrome with mkcert (trust store, ignoring cert errors, chrome flags).
- Artifact/report schema patterns: minimal but sufficient fields; run-id directory conventions.

### Key Decisions Made
- Local-only; maintainers run this manually on Linux.
- OIDC RP Basic is the first/only required plan for this ticket.
- Core lifecycle uses suite HTTP APIs; chromedp is only for WAITING auto-resume (and not for core execution).
- Headless default; headed is a debug mode.
- Keep services running by default; add a `-clean` option for `docker compose down -v` to force a clean slate.
- Artifacts live under `conformance/artifacts/`.
- Evidence export/download and suite auth are out of scope.

## Success Criteria

### Automated Verification
- [ ] `go test ./...` passes by default (harness gated and skipped unless enabled).
- [ ] `LANYARD_CONFORMANCE=1 go test ./...` fails fast with clear error if prerequisites (linux/docker/mkcert/hosts/certs) are missing.
- [ ] Harness returns non-zero (test failure) when any executed conformance test fails.
- [ ] Harness writes `conformance/artifacts/<run-id>/report.json` on every enabled run (including failing runs).

### Manual Verification
- [ ] From a fresh local setup, running the harness provisions the stack and executes OIDC RP Basic without manual suite UI steps.
- [ ] When a test enters `WAITING`, the harness attempts UI automation and either resumes successfully or fails with actionable diagnostics (URL to open, failing selector/action).
- [ ] Default behavior leaves compose services running; `-clean` wipes state and supports a clean re-run.

## Related Information
- Existing local conformance docs: `conformance/README.md`
- Existing local provisioning scripts: `conformance/scripts/setup.sh`, `conformance/scripts/build_suite.sh`
- Compose stack: `conformance/docker-compose.yml`
- Related ticket/plan history: `thoughts/tickets/feature_conformance_suite_execution_automation.md`, `thoughts/plans/conformance_suite_execution_automation.md`

## Notes
- The most uncertain piece is WAITING handling: research should identify the minimal, robust UI interaction that unblocks a WAITING test and how to map it to a specific test instance (test ID -> suite UI URL).
- Consider adding a “safety valve” timeout for WAITING recovery and a debug artifact (screenshot + HTML dump) even if the main report remains statuses/IDs only.
