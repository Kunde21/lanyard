---
type: bug
priority: high
created: 2026-04-10T00:00:00Z
status: created
tags: [conformance, oidcc-config, self-signed-tls-client-auth, mtls, certificate, interrupted]
keywords: [self_signed_tls_client_auth, invalid certificate, interrupted, oidcc-client-test-idtoken-sig-none, signing-key-rotation]
patterns: [suite api log inspection, self-signed mtls validation, static client certificate debugging]
---

# BUG-004: OIDCC Config `self_signed_tls_client_auth` Certificate Is Rejected by Suite

## Description
OIDCC configuration tests using `client_auth_type=self_signed_tls_client_auth` fail in `INTERRUPTED` state because the suite rejects the client certificate as invalid.

## Context
Confirmed through suite API log inspection of interrupted tests from the `20260410-023810` run.

Representative failing tests:
- `qjZFCHZ06RvNHRL` - `oidcc-client-test-idtoken-sig-none`
- `uF4gyXmZwvAyBXA` - `oidcc-client-test-signing-key-rotation-just-before-signing`
- `pjijS9nA7xOlyzk` - `oidcc-client-test-signing-key-rotation`

Representative variants:
- `self_signed_tls_client_auth`, `plain_http_request`, `default`
- `self_signed_tls_client_auth`, `plain_http_request`, `form_post`
- `self_signed_tls_client_auth`, `request_object`, `default`
- `self_signed_tls_client_auth`, `request_object`, `form_post`

## Evidence
Observed suite failure from `GET /api/log/{id}`:

`ValidateClientCertificateForSelfSignedTlsClientAuth: Invalid certificate`

The suite sees the request reach the MTLS token endpoint and confirms that a client certificate is present before rejecting it.

## Current State
The RP presents a certificate for `self_signed_tls_client_auth`, but the suite does not consider it valid for this authentication mode.

## Desired State
The RP should present and register a certificate chain/metadata combination that passes `self_signed_tls_client_auth` validation.

## Requirements

### Functional Requirements
- Ensure the self-signed client certificate is valid for the suite's `self_signed_tls_client_auth` checks.
- Align registered client metadata and actual presented certificate.
- Allow the three affected modules to progress beyond interruption.

### Non-Functional Requirements
- Do not regress FAPI MTLS support.
- Reuse existing conformance certificate material where possible.

## Research Context

### Files to Inspect
- `cmd/example-rp/conformance_keys.go`
- `conformance/certs/`
- `conformance/harness/execute.go`
- any runtime/client registration payload builders

### Questions to Resolve
- Does the suite expect a different certificate than the one currently loaded from `client-mtls.pem`?
- Does `self_signed_tls_client_auth` require a distinct registration shape from `tls_client_auth`?

## Success Criteria

### Automated Verification
- [ ] `self_signed_tls_client_auth` OIDCC config variants no longer fail with `ValidateClientCertificateForSelfSignedTlsClientAuth: Invalid certificate`.
- [ ] The three affected modules progress past interruption for those variants.
- [ ] `go test ./...` remains green.

### Manual Verification
- [ ] Suite logs show successful self-signed TLS client auth certificate validation for affected variants.
