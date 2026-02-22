# Local OpenID Conformance Setup

Run the OpenID Foundation conformance suite locally behind trusted HTTPS at:

- `https://suite.test` (conformance suite UI)
- `https://rp.test` (example RP service in this repo)

This setup is Linux-focused and is intended to get to a first run of:

- `OpenID Connect Core: Basic Certification Profile Relying Party Tests`

The initial run is expected to fail because protocol features are not implemented yet.

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

## 4) Create a first Basic RP run in the suite UI

In `https://suite.test`:

1. Create a new test plan: `OpenID Connect Core: Basic Certification Profile Relying Party Tests`.
2. Configure the RP redirect URI as `https://rp.test/callback`.
3. For RP metadata fields, use values the placeholder RP can support today:
   - Client type: confidential or public (either is fine for initial failing run)
   - Redirect URIs: `https://rp.test/callback`
   - Response type: `code`
   - Grant type: `authorization_code`
   - Token endpoint auth: select a simple default supported by the UI (e.g. `client_secret_basic`)
4. Start the plan.

Expected result: tests run and fail due to missing RP protocol features (PKCE, auth code flow, token exchange, ID token validation, and related logic).

## Logs and troubleshooting

Tail logs:

```bash
docker compose -f conformance/docker-compose.yml logs -f caddy suite rp
```

Common issues:

- TLS warning in browser: run `mkcert -install` and trust the local CA, then retry.
- Hostname routing fails: ensure `/etc/hosts` includes `suite.test` and `rp.test` mapped to `127.0.0.1`.
- Suite container fails to start: ensure `bash conformance/scripts/build_suite.sh` completed and the expected local image exists.
