# Local OpenID Conformance Setup

Run the OpenID Foundation conformance suite locally behind trusted HTTPS at:

- `https://suite.localhost` (conformance suite UI)
- `https://rp.localhost` (example RP service in this repo)

Note: `*.localhost` domains resolve automatically to 127.0.0.1 (no /etc/hosts edits needed)

This setup is Linux-focused and is intended to run the full local RP verification stack, including:

- `OpenID Connect Core: Basic Certification Profile Relying Party Tests`
- `OpenID Connect Core: Config Certification Profile Relying Party Tests`
- `OpenID Connect Core: Form Post Basic Certification Profile Relying Party Tests`
- `FAPI 1.0 Advanced Final: Relying Party Tests`
- `FAPI 2.0 Security Profile Final: Relying Party Tests`
- `FAPI 2.0 Message Signing Final: Relying Party Tests`
- `OpenID Connect Core: Dynamic Certification Profile Relying Party Tests` (preset `oidcc-dynamic-full`; the two request-uri signing modules are excluded — see `thoughts/research/2026-08-29-dcr-conformance-wiring.md`)

Latest verified full-suite result:

- preset: `all-rp-full`
- result: `104/104` plans passed, `1180/1180` tests passed
- artifact: `artifacts/20260410-232441/report.json`

Dynamic client registration (Dynamic RP profile):

- preset: `oidcc-dynamic-full`
- result: `1/1` plan passed, `10/10` modules passed (the two request-uri signing modules are excluded by the preset; see
  `thoughts/research/2026-08-29-dcr-conformance-wiring.md`)
- artifact: `artifacts/20260904-134941/report.json`

The example RP implements Authorization Code + PKCE, ID token validation, UserInfo validation,
PAR, JAR, JARM, RAR, DPoP, mTLS, and RP-hosted `request_uri` support. It uses the supported
cookie-backed RP state store (`rp/store/cookie`) so login and callback state is bound to the
browser session. A grant management demo is available outside the certified flows:
`/login?grant_management_action=create` (or `merge`/`replace` + `grant_id`), and
`GET`/`DELETE /grants/{grant_id}` with a `grant_management_query`/`grant_management_revoke`
access token supplied via the `Authorization: Bearer` header.

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
- exports `mkcert` root CA to `conformance/certs/mkcert-rootCA.pem` for container trust
- generates certs in `conformance/certs/` for `suite.localhost` and `rp.localhost`

No hosts file edits needed - `*.localhost` resolves automatically.

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

If another host service holds TCP 443 on a specific interface (e.g. tailscaled HTTPS),
Docker's wildcard bind fails; use the loopback-only override instead:

```bash
docker compose -f conformance/docker-compose.yml -f conformance/docker-compose.override.yml up -d
```

(`*.localhost` resolves to 127.0.0.1, so host-side traffic is unaffected; containers reach each other via network aliases.)

Open:

- `https://suite.localhost`
- `https://rp.localhost`

The compose stack builds local wrapper images for `suite`, `rp`, `mongo`, and `caddy` that import
`conformance/certs/mkcert-rootCA.pem` into system trust. The suite wrapper also imports the CA into JVM
`cacerts` so Java HTTPS calls trust local certs.

Stop and clean all state:

```bash
docker compose -f conformance/docker-compose.yml down -v
```

MongoDB data is ephemeral by default.

## 4) Create a Run in the Suite UI

In `https://suite.localhost`:

1. Create a new test plan such as `OpenID Connect Core: Basic Certification Profile Relying Party Tests`.
2. Configure the RP redirect URI as `https://rp.localhost/callback`.
3. For RP metadata fields, use values supported by the RP implementation:
   - Client type: confidential
   - Redirect URIs: `https://rp.localhost/callback`
   - Response type: `code`
   - Grant type: `authorization_code`
   - Token endpoint auth: `client_secret_basic`
4. Optional cookie-store env vars for the example RP:
   - `RP_STATE_COOKIE_AUTH_KEY` (32+ byte signing key)
   - `RP_STATE_COOKIE_ENC_KEY` (16/24/32 byte encryption key)
   - `RP_STATE_COOKIE_INSECURE=true` (only for non-HTTPS local debugging)
5. Start the plan.

Expected result: the selected tests run to passing final states for the target profile.

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
- Hostname routing fails: `*.localhost` domains resolve automatically to 127.0.0.1 (no hosts file needed)
- Suite container fails to start: ensure `bash conformance/scripts/build_suite.sh` completed and the expected local image exists.

## Cleanup and data lifecycle

- MongoDB data is ephemeral in this setup (tmpfs) and is removed when containers stop.
- Use `docker compose -f conformance/docker-compose.yml down -v` after each run to avoid stale suite state between attempts.
- Export evidence ZIP files before cleanup; they are not retained inside the suite container.

## Automated local run

After one-time setup (`setup.sh` and trusted mkcert CA), you can run the automation harness directly:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full
```

Common variants:

```bash
# Run the full verified preset
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full

# Run the smoke preset
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-smoke

# Filter plans by regex
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -args -profile=oidc-rp -include-plan-regex='basic|implicit'

# Exclude plans by regex
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -args -profile=all-rp -exclude-plan-regex='private_key_jwt'

# Run jobs in parallel
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -args -profile=fapi-rp -parallel=true -max-parallel-runs=4

# Expand the first plain_fapi matrix subset
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -args \
  -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -parallel=true \
  -max-parallel-runs=4 \
  -matrix=fapi2-sp-final-plain-fapi-first4

# Run the full OIDC config matrix
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=oidcc-config-full

# Run the full FAPI 1.0 Advanced matrix
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi1-adv-full
```

Selected flags:

- `-suite-url` (default `https://suite.localhost`)
- `-artifacts-dir` (default `./artifacts`)
- `-include-plan-regex` and `-exclude-plan-regex`
- `-module-regex` for module/test name filtering inside selected plans
- `-provision-timeout`, `-plan-timeout`, `-test-timeout`
- `-cleanup` (default `false`) to tear down compose services after tests
- `-cleanup=false` to keep services running for local debugging
- `-export-zip` to save suite evidence ZIPs per plan
- `-redact` to redact obvious sensitive values in report fields
- `-parallel` to execute expanded jobs concurrently
- `-max-parallel-runs` to bound job concurrency
- `-matrix` to expand a selected plan into a named job matrix
- `-preset` to run a named verified bundle of profile + matrices + parallelism
- `-fail-fast` to stop launching queued jobs after the first failure

Artifacts are written to:

```text
./artifacts/<run-id>/report.json
./artifacts/<run-id>/jobs/<job-id>/plan-<planName>-<planID>.zip
```

`report.json` contains run metadata, selected plans, per-job plan timing/outcome, per-test status/result, variant metadata, and ZIP paths.
The harness exits non-zero through `go test` failure semantics when a selected test fails or execution errors.

## Parallel runner notes

- The runner expands selected plans into isolated jobs before execution.
- Each job gets a unique alias, independent cookie jar, independent RP runtime registration, and job-scoped artifacts.
- Matrix modes currently include:
  - `oidcc-config-cert-first2`
  - `oidcc-config-cert-all42`
  - `fapi1-adv-final-first4`
  - `fapi1-adv-final-all12`
  - `fapi2-sp-final-plain-fapi-first4`
  - `fapi2-sp-final-plain-fapi-mtls`
  - `fapi2-sp-final-plain-fapi-all16`
  - `fapi2-ms-final-plain-fapi-jar4`
  - `fapi2-ms-final-plain-fapi-jarm4`
  - `fapi2-ms-final-plain-fapi-all32`
- The RP exposes a local-only runtime registration endpoint used by the harness to align client behavior with each suite profile.
