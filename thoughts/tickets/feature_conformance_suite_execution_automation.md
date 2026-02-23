---
type: feature
priority: high
created: 2026-02-23T00:00:00Z
status: implemented
tags: [conformance, oidc, automation, local-dev, go-test, reporting]
keywords: [conformance suite, OpenID Connect RP, go test wrapper, local automation, subset profiles, artifacts, JSON report, suite.test, rp.test, non-zero exit]
patterns: [test harness wrapper, docker compose orchestration, profile selection flags, structured reporting, log redaction, local-only workflow]
---

<!--
Plan: thoughts/plans/conformance_suite_execution_automation.md
-->

# FEATURE-004: Automate Local Conformance Suite Execution

## Description
Automate execution of the local OpenID Connect RP conformance suite so maintainers can run it with a single command through a Go-based `go test` target/wrapper.

The automation should provision required local services, execute selected conformance profile subsets, and emit both console output and a JSON artifact under `./artifacts`.

## Context
Maintainers currently rely on a multi-step/manual workflow for local conformance runs (environment setup, service startup, suite interaction, and artifact capture). This slows iteration and creates inconsistent execution across runs.

Primary goal is developer productivity for maintainers through repeatable local automation.

Scope boundaries confirmed during discovery:
- In scope: local execution only, Linux only, no retries, one-run artifact output, minimal secret redaction.
- Out of scope: CI integration, external result publishing, historical trend reporting.

## Requirements

### Functional Requirements
- Provide a one-command local execution path using a Go implementation exposed via a `go test` target/wrapper.
- Automatically provision required dependencies/services for a run (instead of assuming services are already up).
- Support minimal configuration inputs required to execute runs (e.g., key runtime parameters only).
- Support selecting conformance subset/profile(s) instead of only running a fixed full default.
- Produce human-readable console output for developer feedback.
- Produce machine-readable JSON report artifact in `./artifacts`.
- Return a non-zero exit status when conformance execution fails.
- Include developer documentation with usage examples and report interpretation guidance.

### Non-Functional Requirements
- Platform scope is Linux-only for this ticket.
- Local-only execution model; no CI workflow changes in this ticket.
- No built-in retry logic for flaky/transient failures.
- Apply minimal credential/secret redaction in logs/output.
- Keep implementation aligned with existing repository conventions and tooling.

## Current State
The repository has local conformance infrastructure and documentation for setup/build/run flows, but execution is not fully automated as a single maintainable `go test`-driven command.

## Desired State
Maintainers can run a single local command that:
1) prepares/provisions needed conformance services,
2) executes selected RP conformance subset(s),
3) prints clear console results,
4) writes a JSON artifact to `./artifacts`, and
5) exits non-zero on failure.

## Research Context
This ticket is intended to guide research/planning for implementation details and integration points.

### Keywords to Search
- `conformance` - Existing local conformance setup and scripts.
- `go test` - Required command surface for the automation wrapper.
- `docker-compose.yml` - Service provisioning/orchestration entrypoint.
- `build_suite.sh` - Existing suite build path to integrate or wrap.
- `setup.sh` - Existing environment/TLS setup flow.
- `suite.test` - Local suite endpoint assumptions.
- `rp.test` - Local RP endpoint assumptions.
- `artifacts` - Expected output location for JSON reports.
- `profile` / `subset` - Existing profile selection and run segmentation patterns.
- `redaction` - Existing logging patterns for sensitive values.

### Patterns to Investigate
- Go-based test harness/wrapper patterns that orchestrate external processes.
- Local provisioning patterns for Docker Compose from tests/scripts.
- Configuration injection patterns (minimal flags/env) used elsewhere in repo.
- Report generation patterns for dual-output (console + JSON).
- Failure propagation patterns ensuring non-zero exit behavior in wrappers.
- Documentation patterns for runbook-style local developer workflows.

### Key Decisions Made
- Local-only execution for this ticket; CI integration is out of scope.
- Primary users are maintainers; focus is developer productivity.
- Command surface should be Go-based and invoked through a `go test` target/wrapper.
- Automation should provision dependencies/services as part of execution.
- Minimal runtime configuration is required (not full configuration matrix).
- Subset/profile selection must be supported.
- Output must include console logs and JSON artifact in `./artifacts`.
- Failures must produce non-zero exit.
- No retries in scope.
- Security requirement is minimal redaction (not full secret-management redesign).
- Linux-only compatibility for this ticket.
- External publishing and trend/history reporting are out of scope.

## Success Criteria
Ticket is complete when local maintainers can reliably trigger automated conformance execution via one command and obtain deterministic pass/fail + artifact outputs within defined scope.

### Automated Verification
- [ ] One-command entrypoint executes from a clean local environment and provisions required services.
- [ ] Command supports selecting at least one conformance subset/profile.
- [ ] Failed conformance run returns a non-zero process exit code.
- [ ] JSON report artifact is produced under `./artifacts` for each run.
- [ ] Existing repository tests continue to pass (`go test ./...`).

### Manual Verification
- [ ] Maintainer can follow updated docs to run automation without ad-hoc manual steps.
- [ ] Console output is understandable and useful during execution.
- [ ] JSON artifact includes sufficient details to inspect run outcome locally.
- [ ] Logs avoid exposing raw sensitive credential values (minimal redaction present).
- [ ] Workflow functions on Linux as documented.

## Related Information
- Existing local conformance docs and scripts in `conformance/`.
- Local endpoints currently used: `https://suite.test` and `https://rp.test`.
- Prior conformance setup and profile implementation tickets: `FEATURE-002` and `FEATURE-003`.

## Notes
- Implementation may require choosing between test-native orchestration and a thin Go wrapper that shells out to existing scripts.
- If research finds subset/profile selection cannot be reliably automated via current suite interfaces, capture fallback behavior and propose a follow-up ticket.
