# Conformance Suite Agent Guidelines

This document provides guidance for working with the OpenID Connect RP conformance suite automation and test output analysis.

## Quick Reference

### One-Command Execution (Recommended)

Run the full conformance suite (OIDC basic + FAPI2 SP all16 + FAPI2 MS all32) using a preset:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full
```

This runs 49 plans (1 OIDC + 16 FAPI2-SP + 32 FAPI2-MS matrix variants) with all tests in parallel.

### Available Profiles

- `oidc-rp` - OIDC Relying Party conformance tests
- `fapi-rp` - FAPI Relying Party conformance tests
- `all-rp` - Both OIDC and FAPI RP tests

### Available Matrices

Matrices expand a single plan into multiple variants with different configurations:

| Matrix | Plan | Variants | Description |
|--------|------|----------|-------------|
| `fapi2-sp-final-plain-fapi-all16` | fapi2-security-profile-final | 16 | Full matrix: all auth types, constrains, request types, client types |
| `fapi2-sp-final-plain-fapi-first4` | fapi2-security-profile-final | 4 | Smoke test: first 4 variants only |
| `fapi2-sp-final-plain-fapi-mtls` | fapi2-security-profile-final | 2 | MTLS-only variants |
| `fapi2-ms-final-plain-fapi-jar4` | fapi2-message-signing-final | 4 | JAR only: signed request objects, plain response |
| `fapi2-ms-final-plain-fapi-jarm4` | fapi2-message-signing-final | 4 | JARM: signed request objects + signed JARM response |
| `fapi2-ms-final-plain-fapi-all32` | fapi2-message-signing-final | 32 | Full matrix: all auth, constrain, request, client, response modes |
| `fapi1-adv-final-first4` | fapi1-advanced-final | 4 | Smoke test: first 4 variants only |
| `fapi1-adv-final-all16` | fapi1-advanced-final | 16 | Full matrix: all auth types, request methods, client types, response modes |

The all16 security-profile matrix covers:
- Client auth: `private_key_jwt`, `mtls`
- Sender constrain: `mtls`, `dpop`
- Authorization request: `simple`, `rar`
- Client type: `oidc`, `plain_oauth`

The all32 message-signing matrix adds:
- Request method: `signed_non_repudiation` (JAR)
- Response mode: `plain_response`, `jarm`

The all16 FAPI1 Advanced matrix covers:
- Client auth: `private_key_jwt`, `mtls`
- Sender constrain: `mtls` (fixed — always assumed in FAPI1 Advanced)
- Auth request method: `by_value`, `pushed`
- Client type: `oidc`, `plain_oauth`
- Response mode: `plain_response`, `jarm`

### Presets

Presets bundle profile + matrices + parallel settings for common configurations. Explicit flags override preset values.

| Preset | Profile | Matrices | Parallel | Total Jobs |
|--------|---------|----------|----------|------------|
| `all-rp-full` | all-rp | fapi2-sp-all16 + fapi2-ms-all32 | 8 | 49 (1 OIDC + 16 SP + 32 MS) |
| `all-rp-smoke` | all-rp | fapi2-sp-first4 + fapi2-ms-jar4 | 4 | 9 (1 OIDC + 4 SP + 4 MS) |
| `fapi2-sp-full` | fapi-rp | fapi2-sp-all16 | 8 | 16 |
| `fapi2-ms-full` | fapi-rp | fapi2-ms-all32 | 8 | 32 |
| `fapi1-adv-full` | fapi-rp | fapi1-adv-all16 | 8 | 16 |
| `fapi1-adv-smoke` | fapi-rp | fapi1-adv-first4 | 4 | 4 |

### Common Flags

| Flag                  | Default                   | Description                                        |
|-----------------------|---------------------------|----------------------------------------------------|
| `-profile`            | (required)                | Conformance profile: oidc-rp, fapi-rp, or all-rp   |
| `-suite-url`          | `https://suite.localhost` | Base URL for conformance suite                     |
| `-artifacts-dir`      | `./artifacts`             | Directory for run artifacts                        |
| `-include-plan-regex` | ""                        | Regex for plan names to include                    |
| `-exclude-plan-regex` | ""                        | Regex for plan names to exclude                    |
| `-module-regex`       | ""                        | Regex for module names to include                  |
| `-provision-timeout`  | `5m`                      | Max time to provision services                     |
| `-plan-timeout`       | `30m`                     | Max time for a single plan                         |
| `-test-timeout`       | `60s`                     | Max time for harness to wait for test before calling stop API |
| `-suite-wait-timeout` | `5s`                      | Suite waitTimeoutSeconds sent to test configuration |
| `-cleanup`            | `false`                   | Tear down services after test                      |
| `-export-zip`         | `true`                    | Export plan result ZIP artifacts                   |
| `-redact`             | `true`                    | Redact sensitive keys in output                    |
| `-rebuild-suite`      | `false`                   | Force rebuild suite image                          |
| `-parallel`           | `false`                   | Run expanded jobs in parallel                      |
| `-max-parallel-runs`  | `1`                       | Maximum concurrent jobs                            |
| `-matrix`             | `""`                      | Named matrix expansion (repeatable; each matched to its plan automatically) |
| `-preset`             | `""`                      | Named preset bundling profile + matrices + parallel (all-rp-full, all-rp-smoke, fapi2-sp-full, fapi2-ms-full, fapi1-adv-full, fapi1-adv-smoke) |
| `-fail-fast`          | `false`                   | Stop launching queued jobs after the first failure |

## Setup Requirements

### Prerequisites

1. **Linux only** - The conformance harness only supports Linux
2. **Docker and Docker Compose** - Required for service provisioning
3. **Bash** - Required for setup and build scripts
4. **Git** - Required for fetching upstream conformance suite
5. **Go 1.25+** - Required for building the RP test subject
6. **DNS Resolution** - `*.localhost` domains resolve automatically to 127.0.0.1 (no hosts file edits needed)

### Initial Setup

Run the setup script to generate certificates and prepare the environment:

```bash
bash conformance/scripts/setup.sh
```

This will:
- Export the local `mkcert` root CA to `conformance/certs/mkcert-rootCA.pem`
- Generate TLS certificates for `suite.localhost` and `rp.localhost`
- Create required directories
- Verify prerequisites

### Build Suite Image

The conformance suite image is built automatically on first run, or manually:

```bash
bash conformance/scripts/build_suite.sh
```

This downloads the upstream OpenID conformance suite and builds a Docker image.

When the compose stack starts, local wrapper images import `conformance/certs/mkcert-rootCA.pem` into OS trust for all services (`suite`, `rp`, `mongo`, `caddy`). The suite wrapper also imports it into JVM `cacerts` for Java HTTPS trust.

## Running Conformance Tests

### Run with Plan Filtering

Run only specific plans:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -include-plan-regex="basic"
```

### Run Specific Modules

Run specific test modules within plans:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -module-regex="certification"
```

### Smoke Test (Fast)

Run a quick smoke test with just 4 FAPI2 variants:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -matrix=fapi2-sp-final-plain-fapi-first4 \
  -parallel \
  -max-parallel-runs=4
```

### Run All Profiles in One Batch

Run OIDC + FAPI2-SP + FAPI2-MS together using a preset:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full
```

Or use explicit flags for more control:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=all-rp \
  -matrix=fapi2-sp-final-plain-fapi-all16 \
  -matrix=fapi2-ms-final-plain-fapi-all32 \
  -parallel -max-parallel-runs=8
```

### OIDC Basic Only

Run just the OIDC basic certification tests:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp
```

### FAPI2 All16 Matrix Only

Run all 16 FAPI2 matrix variants in parallel:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -matrix=fapi2-sp-final-plain-fapi-all16 \
  -parallel \
  -max-parallel-runs=8
```

### FAPI2 Message Signing JAR4 (Smoke Test)

Run 4 message-signing variants with plain response (JAR only):

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-jar4 \
  -parallel \
  -max-parallel-runs=4
```

### FAPI2 Message Signing JARM4

Run 4 message-signing variants with JARM signed responses:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-jarm4 \
  -parallel \
  -max-parallel-runs=4
```

### FAPI2 Message Signing All32

Run all 32 message-signing matrix variants:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-all32 \
  -parallel \
  -max-parallel-runs=8
```

### FAPI1 Advanced Smoke Test (Fast)

Run a quick smoke test with 4 FAPI1 Advanced variants:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi1-adv-smoke
```

### FAPI1 Advanced Full Matrix

Run all 16 FAPI1 Advanced matrix variants in parallel:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi1-adv-full
```

Or use explicit flags:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi1-advanced-final-client-test-plan' \
  -matrix=fapi1-adv-final-all16 \
  -parallel \
  -max-parallel-runs=8
```

### Debug Mode

Keep services running and disable redaction for debugging:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -cleanup=false -redact=false
```

Services will remain running after the test. Access them at:
- Suite: https://suite.localhost
- RP: https://rp.localhost

To clean up afterward:

```bash
cd conformance && docker compose down -v
```

### Custom Artifacts Directory

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -artifacts-dir=/tmp/conformance-artifacts
```

## Analyzing Test Output

### Console Output

During execution, the harness logs progress to the console:

```
plan start: oidcc-client-basic-certification-test-plan
  test start: plan=oidcc-client-basic-certification-test-plan module=oidcc-client-test ...
  test done: module=oidcc-client-test status=FINISHED result=PASSED
plan done: oidcc-client-basic-certification-test-plan tests=8 failed=false
final summary: plans=2 failed=false
wrote conformance report to ./artifacts/20260223-150405/report.json
```

Key indicators:
- `result=PASSED` - Test completed successfully
- `result=FAILED` - Test failed conformance requirements
- `status=WAITING` - Test requires browser interaction (may timeout)
- `final summary: failed=false` - Overall run passed

### JSON Report Structure

Reports are generated at `./artifacts/{RunID}/report.json`:

```json
{
  "run_id": "20260223-150405",
  "timestamp": "2026-02-23T15:04:05Z",
  "git_sha": "8dcce57d4097ec956de6adb85ae45dfcb67c739d",
  "suite_url": "https://suite.localhost",
  "profile": "all-rp",
  "matrices": ["fapi2-sp-final-plain-fapi-all16", "fapi2-ms-final-plain-fapi-all32"],
  "selected_plans": ["oidcc-client-basic-certification-test-plan", "fapi2-security-profile-final-client-test-plan", "fapi2-message-signing-final-client-test-plan"],
  "failed": false,
  "plans": [
    {
      "plan_name": "oidcc-client-basic-certification-test-plan",
      "plan_id": "plan-abc123",
      "started_at": "2026-02-23T15:04:10Z",
      "finished_at": "2026-02-23T15:08:20Z",
      "duration": "4m10s",
      "failed": false,
      "tests": [
        {
          "job_id": "job-001",
          "module_name": "oidcc-client-test",
          "test_id": "test-xyz789",
          "status": "FINISHED",
          "result": "PASSED",
          "summary": "Test completed successfully",
          "duration": "45s",
          "alias": "20260323-150405-001",
          "variant": {
            "client_registration": "static_client"
          }
        }
      ],
      "artifact_path": "./artifacts/20260223-150405/jobs/job-001/plan-oidcc-client-basic-certification-test-plan-plan-abc123.zip"
    }
  ]
}
```

In parallel mode, each plan entry in the report corresponds to one isolated job execution. Multiple entries may share the same `plan_name` when a matrix expansion is active.

### Analyzing Failures

When `failed: true`, examine the `failure_reason` fields:

1. **Run-level failure**: Check top-level `failure_reason`
2. **Plan-level failure**: Check `plans[].failure_reason`
3. **Test-level failure**: Check `plans[].tests[].summary` for test details

Common failure patterns:
- `"test entered WAITING state"` - Browser interaction required, check suite UI
- `"create plan failed"` - Suite API error, check suite logs
- `"poll test result failed"` - Test timeout or suite connectivity issue

### ZIP Artifacts

Each plan generates a ZIP export at `./artifacts/{RunID}/plan-{name}-{planID}.zip` containing:
- Detailed test logs
- HTTP request/response traces
- Test configuration
- Evidence files for certification submission

Extract and examine for detailed failure analysis:

```bash
unzip ./artifacts/20260223-150405/plan-oidcc-client-basic-certification-test-plan-*.zip -d /tmp/plan-analysis
```

### Viewing Suite UI

When running with `-cleanup=false`, access the suite UI for interactive debugging:

1. Open https://suite.localhost in a browser
2. Navigate to the test plan
3. Review test details and logs
4. Complete any WAITING tests that require browser interaction

### Log Analysis

Check Docker service logs for underlying issues:

```bash
# View suite logs
docker logs conformance-suite-1

# View RP logs
docker logs conformance-rp-1

# View Caddy logs
docker logs conformance-caddy-1

# View MongoDB logs
docker logs conformance-mongo-1
```

## Troubleshooting

### "conformance harness only supports linux"

The harness validates the operating system. Run only on Linux.

### "missing prerequisite" / "missing suite build script"

Run setup first:

```bash
bash conformance/scripts/setup.sh
```

### "suite readiness probe failed"

The suite failed to start. Check:
1. Docker is running: `docker ps`
2. Port 443 is available: `sudo lsof -i :443`
3. DNS resolution works: `curl -k https://suite.localhost/api/plan/available`
4. View suite logs: `docker logs conformance-suite-1`

### "no plans selected for profile"

The profile filter excluded all available plans. Check:
1. Suite is running and accessible: `curl -k https://suite.localhost/api/plan/available`
2. Profile name is correct: `oidc-rp`, `fapi-rp`, or `all-rp`
3. Regex filters are not too restrictive

### Tests stuck in WAITING state

Some tests require browser interaction. Either:
1. Access the suite UI with `-cleanup=false`
2. Exclude those modules: `-module-regex="^(?!.*waiting-required)"`
3. Accept the timeout and review which tests need manual completion

When a timeout needs to be adjusted for only specific plan modules, the upstream suite supports per-module plan config overrides via an `override` object keyed by module name. For example:

```json
{
  "waitTimeoutSeconds": 10,
  "override": {
    "fapi2-security-profile-final-client-test-invalid-missing-exp": {
      "waitTimeoutSeconds": 3
    }
  }
}
```

This works because plan-based test creation reads module config from the saved plan config and merges `override.<moduleName>` into the base config. It does not work by sending a config body when starting an individual test from an existing plan.

For FAPI happy-path tests, `WAITING` can also mean the suite is expecting the RP to call the exported resource endpoint after login completes. The example RP now does this by calling the suite `accounts_endpoint` once the callback succeeds.

The harness also reports each visited front-channel browser URL back to the suite with the browser visit API while following redirects. Keep that behavior intact when changing redirect handling, or the suite may remain in `WAITING` even when the RP flow succeeds.

### Certificate errors

If you see TLS/certificate errors:
1. Re-run setup: `bash conformance/scripts/setup.sh`
2. Verify certificates exist: `ls conformance/certs/`
3. Check Caddy is running: `docker ps | grep caddy`

## File References

### Core Implementation
- `conformance/harness/harness_test.go:33` - Main test entry point
- `conformance/harness/config.go:8` - Configuration structure
- `conformance/harness/provision.go:15` - Docker provisioning
- `conformance/harness/execute.go:58` - Test execution
- `conformance/harness/suiteclient.go` - Suite browser visit reporting
- `conformance/harness/profiles.go:18` - Plan selection
- `conformance/harness/report.go:27` - Report generation

### RP Conformance Behavior
- `cmd/example-rp/main.go` - Calls the exported FAPI `accounts_endpoint` after successful callback handling
- `rp/callback.go` - Returns the access token needed for post-login conformance resource calls

### Configuration
- `conformance/docker-compose.yml` - Service definitions
- `conformance/Caddyfile` - Reverse proxy configuration
- `conformance/scripts/setup.sh` - Environment setup
- `conformance/scripts/build_suite.sh` - Suite image build

### Documentation
- `conformance/README.md` - General conformance documentation
- `conformance/SUITE_API.md` - Conformance suite API documentation
