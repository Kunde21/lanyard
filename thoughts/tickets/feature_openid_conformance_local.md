---
type: feature
priority: medium
created: 2026-02-22T00:00:00Z
status: implemented
tags: [conformance, oidc, oauth2, docker, docker-compose, mkcert, caddy, tls, local-dev]
keywords: [OpenID Conformance Suite, conformance-suite, GitLab, docker compose, mkcert, Caddy, TLS, suite.test, rp.test, fintechlabs.base_url, OAuth 2.1, PKCE, PAR, Dynamic Client Registration]
patterns: [docker-compose.yml, Caddyfile, mkcert certificate generation, container image pinning, base_url configuration, example RP app, DCR flow, PAR client flow]
---

# FEATURE-002: Run OpenID Conformance Suite Locally (Docker Compose + mkcert)

## Description

Provide a local developer setup to run the OpenID Foundation conformance suite on Linux using Docker Compose, with trusted HTTPS via mkcert and host-based routing via Caddy.

This setup targets testing a relying party (RP / OAuth2 client) implementation, using a local example RP app in this repo. The conformance suite stack should be runnable with a single command and accessible at a stable local domain.

## Context

We want a repeatable local conformance environment for rapid iteration on OAuth/OIDC client behavior. Upstream conformance instructions exist (GitLab), but we want a repo-local, documented workflow with predictable domains and TLS so developers can run tests consistently.

Key constraints/choices gathered:
- Linux-only support.
- Local-only workflow (no CI integration).
- Ephemeral suite state (no persisted DB/results by default).
- Use mkcert for local TLS cert generation (do not automate browser trust installation).
- Use a reverse proxy (Caddy) to terminate TLS.
- Use published container images (no upstream source checkout).
- Pin upstream by tag (not by digest).
- Domains: `suite.test` (suite UI) and `rp.test` (RP example).

## Requirements

### Functional Requirements
- Provide a repo-local `docker compose` stack that starts the conformance suite at `https://suite.test`.
- Provide an automated setup script to generate local certs for `suite.test` and `rp.test` via mkcert.
- Setup script prints (not edits) required `/etc/hosts` entries.
- Configure the conformance suite `base_url` to match `https://suite.test` (proxy-terminated TLS).
- Provide a local example RP app in this repo intended to be run on the host (outside compose).
- Document how to:
  - start/stop the suite stack
  - create a test plan in the suite UI
  - configure and run the RP example against the suite (issuer, redirect URIs, client credentials)
  - choose OAuth 2.0/2.1 RP testing (not OP testing)

### Non-Functional Requirements
- **Reproducibility**: pin container images by tag.
- **Ergonomics**: one command to start suite stack; minimal manual steps.
- **Security**: no secrets committed; generated certs/keys are gitignored.
- **Isolation**: ephemeral state by default; simple cleanup command.

## Current State

This repo does not currently contain a conformance suite setup (no `docker-compose.yml` / mkcert scripts / conformance docs found).

## Desired State

1) `./conformance/scripts/setup.sh` generates local cert/key material for the chosen domains and prepares any required local files.

2) `docker compose -f conformance/docker-compose.yml up` starts a stack that serves the suite UI at `https://suite.test` with a locally-generated certificate.

3) `go run ...` starts an example RP app on `https://rp.test` (or `http://rp.test` behind the proxy, depending on final routing), and the docs show how to connect it to the suite.

4) A developer can complete at least one end-to-end OAuth 2.0/2.1 RP test run locally.

## Research Context

### Upstream References (Initial)
- GitLab repo: `https://gitlab.com/openid/conformance-suite/`
- Developer run docs (to align with): `https://gitlab.com/openid/conformance-suite/wikis/Developers/Build-&-Run`

### Keywords to Search
- `conformance-suite` - Upstream project name and docs.
- `fapi-test-suite.jar` - Common server artifact referenced by upstream.
- `fintechlabs.base_url` - Suite setting for external URL (must match `https://suite.test`).
- `docker-compose-dev.yml` / `docker-compose.yml` - Upstream compose patterns to mirror.
- `localhost.emobix.co.uk` - Upstream default hostname; replace with `suite.test`.
- `Caddyfile` - Host-based routing and TLS termination config.
- `mkcert` - Local CA and certificate generation.
- `PAR` / `pushed_authorization_request_endpoint` - RP client behavior to implement.
- `Dynamic Client Registration` / `registration_endpoint` - Optional RP registration flow.

### Patterns to Investigate
- How the suite is typically deployed (apache+java vs all-in-one) and what published images exist.
- What environment variables / command-line flags the suite supports for external base URL, dev mode, and proxy awareness.
- Container images/registries available for the suite (GitLab registry vs Docker Hub) and whether tagged releases exist.
- Reverse proxy patterns for local conformance setups (host routing for `suite.test` and `rp.test`).
- Example RP patterns in this repo (if any) vs creating a new minimal app.

### Key Decisions Made
- **Role**: RP testing only (not OP testing).
- **Domains**: `suite.test` + `rp.test`.
- **TLS**: mkcert-generated certs; do not automate trust store installation.
- **Proxy**: Caddy terminates TLS; suite runs behind it.
- **State**: ephemeral volumes by default.
- **Workflow**: local-only; no CI.
- **Images**: use published images only; pin by tag.
- **OAuth scope**: OAuth 2.0/2.1 focus; implement PAR client with fallback; RAR explicitly out of scope.
- **Explicitly out of scope**: CIBA, device flow, OIDC logout.

## Success Criteria

### Automated Verification
- [ ] Stack starts cleanly: `docker compose -f conformance/docker-compose.yml up -d`
- [ ] Stack stops/cleans: `docker compose -f conformance/docker-compose.yml down -v`
- [ ] RP example builds/runs: `go test ./...` (and/or `go run ...` per docs)

### Manual Verification
- [ ] `https://suite.test` loads in a browser with no certificate warnings after user trusts mkcert CA.
- [ ] Developer can create an OAuth 2.0/2.1 RP test plan in the suite UI.
- [ ] RP example can be configured with issuer/client credentials and complete at least one end-to-end test run.
- [ ] Docs at `conformance/README.md` are sufficient for a new developer to reproduce the setup.

## Related Information

- Docs location decision: `conformance/README.md`
- Local domains: `suite.test` (suite) and `rp.test` (RP)

## Notes

- Open question for research/planning: confirm that appropriate published container images exist for the upstream suite (and what tags map to versions). If not, we may need to revisit the "images only" constraint or treat upstream build as a separate step.
- RP example scope: implement OAuth 2.1 best-practice authorization code flow with PKCE, plus PAR client behavior with fallback. Support both manual credentials and dynamic client registration when possible.
