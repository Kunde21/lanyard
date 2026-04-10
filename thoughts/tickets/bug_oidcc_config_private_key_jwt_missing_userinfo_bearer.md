---
type: bug
priority: high
created: 2026-04-10T00:00:00Z
status: implemented
tags: [conformance, oidcc-config, private-key-jwt, userinfo, bearer-token, interrupted]
keywords: [private_key_jwt, userinfo, bearer token, interrupted, oidcc-client-test-idtoken-sig-none, signing-key-rotation]
patterns: [suite api log inspection, callback flow debugging, userinfo request validation]
---

# BUG-002: OIDCC Config `private_key_jwt` Flow Reaches UserInfo Without Bearer Token

## Description
OIDCC configuration tests using `client_auth_type=private_key_jwt` fail in `INTERRUPTED` state because the suite receives a `/userinfo` request without a bearer access token.

## Context
Confirmed through suite API log inspection of interrupted tests from the `20260410-023810` run.

Representative failing tests:
- `ujJmcdvVFRJGQv4` - `oidcc-client-test-idtoken-sig-none`
- `l9BI0nFd67pAhnl` - `oidcc-client-test-signing-key-rotation-just-before-signing`
- `a33q89zCOdRMyDN` - `oidcc-client-test-signing-key-rotation`

Representative variants:
- `private_key_jwt`, `plain_http_request`, `default`
- `private_key_jwt`, `plain_http_request`, `form_post`
- `private_key_jwt`, `request_object`, `default`
- `private_key_jwt`, `request_object`, `form_post`

## Evidence
Observed suite failure from `GET /api/log/{id}`:

`OIDCCExtractBearerAccessTokenFromRequest: Couldn't find a bearer token in request`

The suite log shows the RP reached:

`Incoming HTTP request to /userinfo`

which means the flow advanced far enough to call userinfo, but the request did not contain the expected bearer token.

## Current State
`private_key_jwt` flows complete enough to hit userinfo, but token propagation or userinfo authorization header/body handling is incorrect for these OIDCC config variants.

## Desired State
The RP should call userinfo with a valid bearer access token for `private_key_jwt` OIDCC config variants.

## Requirements

### Functional Requirements
- Ensure access tokens are preserved and sent on userinfo requests for `private_key_jwt` variants.
- Verify this works for both `plain_http_request` and `request_object` variants.
- Ensure `idtoken-sig-none` and both signing-key-rotation modules complete instead of interrupting.

### Non-Functional Requirements
- Do not regress FAPI1 Advanced or FAPI2 private key JWT behavior.

## Research Context

### Files to Inspect
- `rp/callback.go`
- `cmd/example-rp/main.go`
- `cmd/example-rp/runtime_resolution.go`
- any userinfo transport selection paths in `rp/`

### Questions to Resolve
- Is the access token missing from callback results, or dropped before the userinfo call?
- Is the wrong userinfo token transport selected for these OIDCC config runs?

## Success Criteria

### Automated Verification
- [ ] `private_key_jwt` OIDCC config variants no longer fail with missing bearer token on userinfo.
- [ ] `idtoken-sig-none`, `signing-key-rotation`, and `signing-key-rotation-just-before-signing` progress past interruption for those variants.
- [ ] `go test ./...` remains green.

### Manual Verification
- [ ] Suite logs show a bearer access token on incoming `/userinfo` requests for affected variants.
