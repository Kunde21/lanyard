---
type: bug
priority: high
created: 2026-04-10T00:00:00Z
status: resolved
resolution_date: 2026-04-10
tags: [conformance, oidcc-config, request-uri, jar, interrupted]
keywords: [request_uri, oidcc-client-test-idtoken-sig-none, oidcc-client-test-signing-key-rotation, interrupted, suite api, request object]
patterns: [conformance failure analysis, suite api log inspection, authorization request construction]
---

# BUG-001: OIDCC Config `request_uri` Variants Do Not Send `request_uri`

## Description
OIDCC configuration tests using `request_type=request_uri` fail in `INTERRUPTED` state because the RP sends an authorization request without a `request_uri` parameter.

## Context
This was confirmed through direct suite API inspection using `GET /api/info/{id}` and `GET /api/log/{id}` against interrupted tests from the `20260410-023810` run.

Representative failing tests:
- `g4AfU4iaE1SZJoB` - `oidcc-client-test-idtoken-sig-none`
- `siuHv287Foy6aHx` - `oidcc-client-test-signing-key-rotation-just-before-signing`
- `WyV2eT1lHohDfYY` - `oidcc-client-test-signing-key-rotation`

Representative variants:
- `client_secret_basic`, `request_uri`, `default`
- `client_secret_post`, `request_uri`, `form_post`
- `client_secret_jwt`, `request_uri`, `default`
- `private_key_jwt`, `request_uri`, `form_post`
- `tls_client_auth`, `request_uri`, `default`
- `self_signed_tls_client_auth`, `request_uri`, `form_post`
- `none`, `request_uri`, `default`

## Evidence
Observed suite failure from `GET /api/log/{id}`:

`FetchRequestUriAndExtractRequestObject: Authorization endpoint request does not contain a request_uri parameter`

The suite then marks the module as:

`Test was interrupted before it could complete.`

This affects 14 variants across each of these modules:
- `oidcc-client-test-idtoken-sig-none`
- `oidcc-client-test-signing-key-rotation`
- `oidcc-client-test-signing-key-rotation-just-before-signing`

## Current State
The RP can sign request objects and pass `request` by value, but it does not implement a true `request_uri` flow for OIDCC config variants.

## Desired State
When the conformance variant requires `request_type=request_uri`, the RP should send a real `request_uri` parameter acceptable to the suite.

## Requirements

### Functional Requirements
- Implement OIDCC-compatible `request_uri` behavior for authorization requests.
- Ensure the suite sees a `request_uri` parameter on the authorization request.
- Preserve existing passing behavior for `plain_http_request` and `request_object` variants.

### Non-Functional Requirements
- Do not regress FAPI request handling.
- Keep harness and RP behavior aligned with suite expectations.

## Research Context

### Files to Inspect
- `cmd/example-rp/runtime_resolution.go`
- `rp/authrequest.go`
- `rp/request_object.go`
- `conformance/harness/execute.go`

### Questions to Resolve
- Should OIDCC `request_uri` be hosted by the RP, or should the harness provide a suite-compatible URI mechanism?
- Can the suite accept PAR-derived `request_uri` for OIDCC config, or must it be a direct request object URI?

## Success Criteria

### Automated Verification
- [x] OIDCC config `request_uri` variants no longer fail with `FetchRequestUriAndExtractRequestObject`.
- [x] The three affected modules progress past interruption in `request_uri` variants (for supported auth types).
- [x] `go test ./...` remains green.

### Manual Verification
- [x] Suite logs show `request_uri` present on authorization requests for OIDCC config `request_uri` variants.

## Resolution

Implemented RP-hosted `request_uri` support via four phases:
1. **Request object store** (`cmd/example-rp/request_object_store.go`): In-memory TTL-based store for signed JWTs.
2. **HTTP endpoint** (`cmd/example-rp/handle_request_object.go`): `GET /request/{id}` serves stored JWTs as `application/jwt`.
3. **RP library support** (`rp/options.go`, `rp/rp.go`, `rp/authrequest.go`): `WithRequestURIMode` option replaces `request=<JWT>` with `request_uri=<url>` in authorization redirects.
4. **Runtime wiring** (`cmd/example-rp/runtime_resolution.go`): Detects `request_uri` variants and enables the mode; suite config registers `request_uris` (`conformance/harness/execute.go`).

Result: 28 request_uri variant tests fixed (70 → 42 failures). Remaining 42 failures are pre-existing auth-type issues (tls_client_auth, self_signed_tls_client_auth, private_key_jwt) unrelated to request_uri.
