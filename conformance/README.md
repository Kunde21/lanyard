# Local OpenID Conformance Setup

Run the OpenID Foundation conformance suite locally behind trusted HTTPS at:

- `https://suite.test` (conformance suite UI)
- `https://rp.test` (example RP service in this repo)

This setup is Linux-focused and is intended to run and pass:

- `OpenID Connect Core: Basic Certification Profile Relying Party Tests`

The example RP now implements Authorization Code + PKCE, ID token validation, and UserInfo validation for this profile.

## Prerequisites

- Linux
- Docker Engine
- Docker Compose plugin (`docker compose`)
- `mkcert`

## 1) TLS setup

Run:

```bash
bash conformance/scripts/setup.sh
```

The script:

- verifies `mkcert` is installed
- generates certs in `conformance/certs/`
- prints required `/etc/hosts` entries

Add the printed host entries manually if needed.

## 2) Build the upstream suite image locally

Run:

```bash
bash conformance/scripts/build_suite.sh
```

By default this builds upstream tag `release-v5.1.39` into:

- `lanyard-conformance-suite:release-v5.1.39`

Override the tag/image if needed:

```bash
UPSTREAM_TAG=release-v5.1.39 SUITE_IMAGE=lanyard-conformance-suite:release-v5.1.39 \
  bash conformance/scripts/build_suite.sh
```

## 3) Start the stack

Run:

```bash
docker compose -f conformance/docker-compose.yml up -d
```

Open:

- `https://suite.test`
- `https://rp.test`

Stop and clean all state:

```bash
docker compose -f conformance/docker-compose.yml down -v
```

MongoDB data is ephemeral by default.

## 4) Create a Basic RP run in the suite UI

In `https://suite.test`:

1. Create a new test plan: `OpenID Connect Core: Basic Certification Profile Relying Party Tests`.
2. Configure the RP redirect URI as `https://rp.test/callback`.
3. For RP metadata fields, use values supported by the RP implementation:
   - Client type: confidential
   - Redirect URIs: `https://rp.test/callback`
   - Response type: `code`
   - Grant type: `authorization_code`
   - Token endpoint auth: `client_secret_basic`
4. Start the plan.

Expected result: tests run to passing final states for the target profile.

## 5) Capture evidence artifacts

When the run finishes:

1. Keep the suite UI page open.
2. Use the suite publish/certification package flow to export the results ZIP.
3. Save the ZIP under `conformance/artifacts/` (local only, gitignored).
4. Record the following into a local notes file under `conformance/artifacts/`:
   - profile name
   - plan ID
   - test IDs and final statuses

Example local record file:

```text
conformance/artifacts/basic-rp-run-YYYYMMDD.txt
```

## Logs and troubleshooting

Tail logs:

```bash
docker compose -f conformance/docker-compose.yml logs -f caddy suite rp
```

Common issues:

- TLS warning in browser: run `mkcert -install` and trust the local CA, then retry.
- Hostname routing fails: ensure `/etc/hosts` includes `suite.test` and `rp.test` mapped to `127.0.0.1`.
- Suite container fails to start: ensure `bash conformance/scripts/build_suite.sh` completed and the expected local image exists.

## Cleanup and data lifecycle

- MongoDB data is ephemeral in this setup (tmpfs) and is removed when containers stop.
- Use `docker compose -f conformance/docker-compose.yml down -v` after each run to avoid stale suite state between attempts.
- Export evidence ZIP files before cleanup; they are not retained inside the suite container.

## Automated local run

After one-time setup (`setup.sh`, hosts entries, and trusted mkcert CA), you can run the automation harness directly:

```bash
LANYARD_CONFORMANCE=1 go test ./internal/conformanceharness -run TestConformanceHarness -args -profile=oidc-rp
```

Common variants:

```bash
# Run all RP plans discovered from the suite API
LANYARD_CONFORMANCE=1 go test ./internal/conformanceharness -run TestConformanceHarness -args -profile=all-rp

# Filter plans by regex
LANYARD_CONFORMANCE=1 go test ./internal/conformanceharness -run TestConformanceHarness -args -profile=oidc-rp -include-plan-regex='basic|implicit'

# Exclude plans by regex
LANYARD_CONFORMANCE=1 go test ./internal/conformanceharness -run TestConformanceHarness -args -profile=all-rp -exclude-plan-regex='private_key_jwt'
```

Selected flags:

- `-suite-url` (default `https://suite.test`)
- `-artifacts-dir` (default `./artifacts`)
- `-include-plan-regex` and `-exclude-plan-regex`
- `-module-regex` for module/test name filtering inside selected plans
- `-provision-timeout`, `-plan-timeout`, `-test-timeout`
- `-keep-running` to avoid teardown for local debugging
- `-export-zip` to save suite evidence ZIPs per plan
- `-redact` to redact obvious sensitive values in report fields

Artifacts are written to:

```text
./artifacts/<run-id>/report.json
./artifacts/<run-id>/plan-<planName>-<planID>.zip
```

`report.json` contains run metadata, selected plans, per-plan timing/outcome, per-test status/result, and ZIP paths.
The harness exits non-zero through `go test` failure semantics when a selected test fails or execution errors.
