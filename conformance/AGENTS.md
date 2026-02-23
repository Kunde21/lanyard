# Conformance Suite Agent Guidelines

This document provides guidance for working with the OpenID Connect RP conformance suite automation and test output analysis.

## Quick Reference

### One-Command Execution

Run the full conformance suite with a single command:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp
```

### Available Profiles

- `oidc-rp` - OIDC Relying Party conformance tests
- `fapi-rp` - FAPI Relying Party conformance tests
- `all-rp` - Both OIDC and FAPI RP tests

### Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-profile` | (required) | Conformance profile: oidc-rp, fapi-rp, or all-rp |
| `-suite-url` | `https://suite.test` | Base URL for conformance suite |
| `-artifacts-dir` | `./artifacts` | Directory for run artifacts |
| `-include-plan-regex` | "" | Regex for plan names to include |
| `-exclude-plan-regex` | "" | Regex for plan names to exclude |
| `-module-regex` | "" | Regex for module names to include |
| `-provision-timeout` | `5m` | Max time to provision services |
| `-plan-timeout` | `30m` | Max time for a single plan |
| `-test-timeout` | `5m` | Max time for a single test instance |
| `-cleanup` | `false` | Tear down services after test |
| `-export-zip` | `true` | Export plan result ZIP artifacts |
| `-redact` | `true` | Redact sensitive keys in output |
| `-rebuild-suite` | `false` | Force rebuild suite image |

## Setup Requirements

### Prerequisites

1. **Linux only** - The conformance harness only supports Linux
2. **Docker and Docker Compose** - Required for service provisioning
3. **Bash** - Required for setup and build scripts
4. **Git** - Required for fetching upstream conformance suite
5. **Go 1.25+** - Required for building the RP test subject
6. **Hosts file entries** - Must resolve `suite.test` and `rp.test` to 127.0.0.1:

```bash
# Add to /etc/hosts
127.0.0.1 suite.test rp.test
```

### Initial Setup

Run the setup script to generate certificates and prepare the environment:

```bash
bash conformance/scripts/setup.sh
```

This will:
- Export the local `mkcert` root CA to `conformance/certs/mkcert-rootCA.pem`
- Generate TLS certificates for `suite.test` and `rp.test`
- Create required directories
- Verify prerequisites

### Build Suite Image

The conformance suite image is built automatically on first run, or manually:

```bash
bash conformance/scripts/build_suite.sh
```

This downloads the upstream OpenID conformance suite and builds a Docker image.

When the compose stack starts, local wrapper images import `conformance/certs/mkcert-rootCA.pem` into
OS trust for all services (`suite`, `rp`, `mongo`, `caddy`). The suite wrapper also imports it into JVM
`cacerts` for Java HTTPS trust.

## Running Conformance Tests

### Basic Run

Run OIDC RP conformance tests:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp
```

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

### Debug Mode

Keep services running and disable redaction for debugging:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -cleanup=false -redact=false
```

Services will remain running after the test. Access them at:
- Suite: https://suite.test
- RP: https://rp.test

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
  "suite_url": "https://suite.test",
  "profile": "oidc-rp",
  "selected_plans": ["oidcc-client-basic-certification-test-plan"],
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
          "module_name": "oidcc-client-test",
          "test_id": "test-xyz789",
          "status": "FINISHED",
          "result": "PASSED",
          "summary": "Test completed successfully",
          "duration": "45s",
          "alias": "lanyard-1-1"
        }
      ],
      "artifact_path": "./artifacts/20260223-150405/plan-oidcc-client-basic-certification-test-plan-plan-abc123.zip"
    }
  ]
}
```

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

1. Open https://suite.test in a browser
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
3. Hosts file is configured: `cat /etc/hosts | grep test`
4. View suite logs: `docker logs conformance-suite-1`

### "no plans selected for profile"

The profile filter excluded all available plans. Check:
1. Suite is running and accessible: `curl -k https://suite.test/api/plan/available`
2. Profile name is correct: `oidc-rp`, `fapi-rp`, or `all-rp`
3. Regex filters are not too restrictive

### Tests stuck in WAITING state

Some tests require browser interaction. Either:
1. Access the suite UI with `-cleanup=false`
2. Exclude those modules: `-module-regex="^(?!.*waiting-required)"`
3. Accept the timeout and review which tests need manual completion

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
- `conformance/harness/profiles.go:18` - Plan selection
- `conformance/harness/report.go:27` - Report generation

### Configuration
- `conformance/docker-compose.yml` - Service definitions
- `conformance/Caddyfile` - Reverse proxy configuration
- `conformance/scripts/setup.sh` - Environment setup
- `conformance/scripts/build_suite.sh` - Suite image build

### Documentation
- `conformance/README.md` - General conformance documentation
- `conformance/SUITE_API.md` - Conformance suite API documentation
