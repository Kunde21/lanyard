# FEATURE-002: Run OpenID Conformance Suite Locally (Docker Compose + mkcert) Implementation Plan

## Overview

Add a repo-local, Linux-focused developer environment to run the OpenID Foundation conformance suite behind trusted HTTPS at `https://suite.test`, alongside a minimal example RP service at `https://rp.test`. This plan intentionally targets a first conformance run of `OpenID Connect Core: Basic Certification Profile Relying Party Tests` that is expected to fail until protocol features are implemented (tracked in a separate ticket).

## Current State Analysis

- No conformance infrastructure exists yet (no `conformance/` directory, compose stack, mkcert scripts, or docs) (`thoughts/tickets/feature_openid_conformance_local.md:55`).
- The Go library is discovery + JWKS only; it does not implement RP protocol flows needed to pass conformance tests (PKCE, auth code exchange, ID token validation, etc.) (`oidc/discovery.go:14`, `oidc/jwks.go:10`, `jwks/remote_keyset.go:25`).

## Desired End State

After completing this plan:

1. `./conformance/scripts/setup.sh` generates mkcert certificates for `suite.test` and `rp.test` and prints required `/etc/hosts` entries.
2. `docker compose -f conformance/docker-compose.yml up` starts:
   - Caddy terminating TLS for both hostnames and routing by Host header
   - the conformance suite reachable at `https://suite.test`
   - the example RP reachable at `https://rp.test`
3. A developer can create and start the `OpenID Connect Core: Basic Certification Profile Relying Party Tests` plan in the suite UI and observe expected failures due to missing RP protocol features.

### Verification

#### Automated Verification
- [x] Setup script runs successfully: `bash conformance/scripts/setup.sh`
- [x] Stack starts cleanly: `docker compose -f conformance/docker-compose.yml up -d --build`
- [x] Stack stops/cleans ephemerally: `docker compose -f conformance/docker-compose.yml down -v`

#### Manual Verification
- [x] `https://suite.test` loads in a browser with no certificate warnings after trusting mkcert CA.
- [x] `https://rp.test` loads (even if it only renders a placeholder page).
- [ ] Suite UI allows creating + starting `OpenID Connect Core: Basic Certification Profile Relying Party Tests` and shows test results/failures.
- [x] `conformance/README.md` is sufficient for a new developer to reproduce the setup.

## Key Discoveries

- The suite must be told its external URL via `fintechlabs.base_url` (commonly configured by `BASE_URL` in docker) so it generates links/callbacks consistent with `https://suite.test`.
- Upstream does not appear to provide official pre-built images; we will build locally from a pinned upstream tag into a local Docker image.
- Caddy must reverse-proxy to Compose services (not the host), so the example RP will run as a Compose service using a bind-mounted checkout.

## What We're NOT Doing

- Implementing RP protocol features required to pass conformance (PKCE, authorization requests, token exchange, ID token validation, UserInfo, PAR, DCR).
- Persisting suite state by default (MongoDB data and suite results are ephemeral; developers can opt in later).
- CI integration.
- Windows/macOS support.

## Implementation Approach

- Create a `conformance/` directory containing:
  - `docker-compose.yml` for suite + mongo + caddy + rp
  - `Caddyfile` for HTTPS termination and host routing
  - `scripts/` for mkcert and suite build automation
  - `README.md` as the runbook
- Pin upstream by Git tag (default: latest known `release-v5.1.x`) and build locally into an image tag recorded in docs.
- Keep generated artifacts gitignored (certs, upstream checkout, local build outputs).

## Phase 1: Conformance Scaffolding + TLS Bootstrap

### Overview

Add the `conformance/` directory, mkcert setup script, and gitignore rules. No suite build yet.

### Changes Required

#### 1. Directory structure
**Files**:
- `conformance/README.md`
- `conformance/Caddyfile`
- `conformance/docker-compose.yml`
- `conformance/scripts/setup.sh`

#### 2. mkcert setup script
**File**: `conformance/scripts/setup.sh`
**Changes**:
- Verify `mkcert` exists and print a helpful error if missing.
- Generate (or regenerate) certs for `suite.test` and `rp.test` into `conformance/certs/`.
- Print (do not edit) required `/etc/hosts` entries.

Suggested output files:
- `conformance/certs/suite.test.pem`
- `conformance/certs/suite.test-key.pem`
- `conformance/certs/rp.test.pem`
- `conformance/certs/rp.test-key.pem`

#### 3. Caddy config
**File**: `conformance/Caddyfile`
**Changes**:
- Terminate TLS using the mkcert files mounted into the container.
- Route by hostname:
  - `suite.test` -> `suite:8080`
  - `rp.test` -> `rp:8080`

#### 4. Compose skeleton
**File**: `conformance/docker-compose.yml`
**Changes**:
- Define services:
  - `mongo` pinned by tag (ephemeral storage by default)
  - `suite` (image placeholder for now)
  - `rp` running from `golang:1.25` with bind-mounted repo
  - `caddy` pinned by tag

### Success Criteria

#### Automated Verification
- [x] `bash conformance/scripts/setup.sh` creates `conformance/certs/*`.
- [x] `docker compose -f conformance/docker-compose.yml config` succeeds.

#### Manual Verification
- [x] Caddy starts and serves HTTPS for both hostnames (even if upstreams aren’t ready yet).

---

## Phase 2: Local Build of Upstream Conformance Suite (Pinned)

### Overview

Automate fetching and building the upstream suite from a pinned tag into a local Docker image consumed by our compose stack.

### Changes Required

#### 1. Build script
**File**: `conformance/scripts/build_suite.sh`
**Changes**:
- Clone upstream into `conformance/.upstream/conformance-suite/` if missing; otherwise fetch + checkout pinned tag.
- Run upstream `builder-compose.yml` to build the jar.
- Build a local image tag (example: `lanyard-conformance-suite:<tag>`).
- Print the resolved upstream tag and built image name.

#### 2. Wire suite image into compose
**File**: `conformance/docker-compose.yml`
**Changes**:
- Configure `suite` to use the locally built image.
- Configure suite external URL:
  - `BASE_URL=https://suite.test`
  - Ensure mongodb URI/host matches our `mongo` service.

#### 3. Ephemeral Mongo
**File**: `conformance/docker-compose.yml`
**Changes**:
- Use `tmpfs` or an anonymous volume so state is not persisted by default.

### Success Criteria

#### Automated Verification
- [x] Local suite image builds: `bash conformance/scripts/build_suite.sh`
- [x] Stack starts: `docker compose -f conformance/docker-compose.yml up -d`
- [x] Cleanup removes state: `docker compose -f conformance/docker-compose.yml down -v`

#### Manual Verification
- [x] `https://suite.test` loads the suite UI.

---

## Phase 3: Example RP as a Compose Service (Bind-Mounted)

### Overview

Add a minimal RP HTTP service that can be reached at `https://rp.test` through Caddy. It does not implement conformance-required protocol behavior yet.

### Changes Required

#### 1. RP entrypoint
**File**: `cmd/example-rp/main.go`
**Changes**:
- Minimal HTTP server listening on `:8080`.
- Endpoints:
  - `/` health/info page
  - `/callback` placeholder handler (required for suite configuration)
- Avoid logging secrets (none expected yet).

#### 2. Compose wiring
**File**: `conformance/docker-compose.yml`
**Changes**:
- Add `rp` service:
  - `image: golang:1.25`
  - bind-mount repo into container
  - `working_dir` set to repo root
  - command runs `go run ./cmd/example-rp`

### Success Criteria

#### Automated Verification
- [x] RP container starts and listens: `docker compose -f conformance/docker-compose.yml up -d rp`
- [x] `docker compose -f conformance/docker-compose.yml logs rp` shows it started.

#### Manual Verification
- [x] `https://rp.test/` returns a page.
- [x] `https://rp.test/callback` returns a placeholder response.

---

## Phase 4: Documentation for a First (Failing) Basic RP Plan Run

### Overview

Document the exact UI steps and configuration values to start the Basic RP plan and collect results/logs.

### Changes Required

#### 1. Runbook
**File**: `conformance/README.md`
**Changes**:
- Prereqs: Docker, docker compose plugin, mkcert, Linux.
- Setup:
  - run `conformance/scripts/setup.sh`
  - add printed `/etc/hosts` entries
  - trust mkcert CA in browser/OS
- Build suite:
  - run `conformance/scripts/build_suite.sh`
- Run:
  - `docker compose -f conformance/docker-compose.yml up -d`
  - open `https://suite.test`
- Suite UI steps:
  - create plan: `OpenID Connect Core: Basic Certification Profile Relying Party Tests`
  - configure redirect URI(s): `https://rp.test/callback`
  - set RP metadata fields required by the UI (document the values we support today)
  - start the run and expect failures
- Logs & troubleshooting:
  - `docker compose -f conformance/docker-compose.yml logs -f caddy suite rp`
  - common TLS errors (mkcert CA not trusted)
  - common host routing errors (`/etc/hosts` missing)

### Success Criteria

#### Automated Verification
- [x] README commands execute as written.

#### Manual Verification
- [ ] A developer can start the Basic RP plan and capture the resulting failures and logs.

## Testing Strategy

### Automated
- `bash conformance/scripts/setup.sh`
- `bash conformance/scripts/build_suite.sh`
- `docker compose -f conformance/docker-compose.yml up -d --build`
- `docker compose -f conformance/docker-compose.yml down -v`

### Manual
1. Trust mkcert CA; verify `https://suite.test` loads without warnings.
2. Verify `https://rp.test` serves content.
3. Create and start `OpenID Connect Core: Basic Certification Profile Relying Party Tests`; confirm failures are visible and logs are obtainable.

## Performance Considerations

- Suite build can be slow (Maven). The build script should keep a local Maven cache directory under `conformance/.cache/` (gitignored) to speed up subsequent builds.

## Migration Notes

N/A (new tooling and docs).

## References

- Original ticket: `thoughts/tickets/feature_openid_conformance_local.md`
- Research: `thoughts/research/2026-02-22_openid_conformance_local_setup.md`
- Upstream suite: `https://gitlab.com/openid/conformance-suite/`

## Deviations from Plan

### Phase 2: Local Build of Upstream Conformance Suite (Pinned)
- **Original Plan**: Configure suite with `BASE_URL=https://suite.test` and Mongo host/URI wiring.
- **Actual Implementation**: Added placeholder `OIDC_GOOGLE_CLIENTID`, `OIDC_GOOGLE_SECRET`, `OIDC_GITLAB_CLIENTID`, and `OIDC_GITLAB_SECRET` environment variables in Compose.
- **Reason for Deviation**: Upstream suite failed startup with Spring validation (`Client id of registration 'gitlab' must not be empty`) unless non-empty OAuth client registration values are provided.
- **Impact Assessment**: Keeps Phase 2/4 success criteria achievable by allowing suite startup and UI access; does not alter RP protocol scope or later protocol implementation work.
- **Date/Time**: 2026-02-22
