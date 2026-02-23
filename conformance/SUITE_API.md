# Conformance Suite API Notes

This document records the API discovery results from the locally running conformance suite at `https://suite.test`.

## Swagger / OpenAPI endpoints

- Swagger UI: `https://suite.test/swagger-ui/index.html`
- OpenAPI JSON: `https://suite.test/v3/api-docs`
- OpenAPI YAML: `https://suite.test/v3/api-docs.yaml`

## API metadata

From `GET /v3/api-docs`:

- Title: `OpenID Conformance Suite REST APIs`
- Version: `5.1.39`
- Description includes a note about token management at `/tokens.html` and a reference script:
  - `https://gitlab.com/openid/conformance-suite/-/blob/master/scripts/run-test-plan.py`

Observed locally in this stack: `GET /api/plan/available` is accessible without providing a bearer token.

## Documented path inventory

OpenAPI currently reports 31 paths. The `/api/*` paths are:

- `/api/currentuser`
- `/api/info`
- `/api/info/{id}`
- `/api/info/{id}/publish`
- `/api/lastconfig`
- `/api/log`
- `/api/log/exporthtml/{id}`
- `/api/log/export/{id}`
- `/api/log/{id}`
- `/api/log/{id}/images`
- `/api/log/{id}/images/{placeholder}`
- `/api/plan`
- `/api/plan/available`
- `/api/plan/exporthtml/{id}`
- `/api/plan/export/{id}`
- `/api/plan/{id}`
- `/api/plan/{id}/certificationpackage`
- `/api/plan/{id}/makemutable`
- `/api/plan/{id}/publish`
- `/api/plan/info/{planName}`
- `/api/runner`
- `/api/runner/available`
- `/api/runner/browser/{id}`
- `/api/runner/browser/{id}/visit`
- `/api/runner/{id}`
- `/api/runner/running`
- `/api/server`
- `/api/token`
- `/api/token/{id}`
- `/api/ui/spec_links`

## Key endpoint contracts for automation

### `GET /api/plan/available`

- Summary: list available plans and attributes.
- Local observation: returns plan objects with keys including `planName`, `profile`, `modules`, `variants`, `configurationFields`.
- Current local count: 71 plans.

### `POST /api/plan`

- Summary: create test plan.
- Required query parameter: `planName`.
- Optional query parameter: `variant`.
- Body content type: `application/json`.
- Important behavior observed:
  - Sending `planName` in JSON body only returns `400` (missing request parameter).
  - Supplying only `planName` may return `500` if required plan variants are not provided.
  - For `oidcc-client-basic-certification-test-plan`, the available-plan metadata indicates required variants like `client_registration` and `request_type`.

### `POST /api/runner`

- Summary: create a test module instance.
- Required query parameter: `test`.
- Optional query parameters: `plan`, `variant`.
- Body content type: `application/json`.
- Useful note from OpenAPI description: after creation, poll `/api/info/{testid}` and wait for `WAITING` before interacting with a test.

### `GET /api/info/{id}`

- Summary: get test information by test id.
- Path parameter: `id`.
- Optional query parameter: `public` (default `false`).

### `GET /api/plan/exporthtml/{id}`

- Summary: export full plan results (HTML + JSON in a ZIP).
- Path parameter: `id`.
- Optional query parameter: `public`.
- Response content type: `application/zip`.

## Quick probe commands

```bash
# Swagger UI and OpenAPI docs
curl -skI https://suite.test/swagger-ui/index.html
curl -sk https://suite.test/v3/api-docs | jq '.info'

# Available plans
curl -sk https://suite.test/api/plan/available | jq 'length'

# One plan's metadata
curl -sk https://suite.test/api/plan/available \
  | jq '.[] | select(.planName=="oidcc-client-basic-certification-test-plan")'
```

## Notes for harness implementation

- `POST /api/plan` and `POST /api/runner` depend on query parameters for core identifiers (`planName`, `test`), not JSON field names alone.
- Required variant values are plan-specific; derive them from `/api/plan/available` (fields: `variants`, `modules`, `configurationFields`) before attempting plan creation.
- `GET /api` is not an API index endpoint in this deployment (returns HTML 404).
