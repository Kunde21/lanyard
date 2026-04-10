---
type: bug
priority: high
created: 2026-04-10T00:00:00Z
status: implemented
tags: [conformance, oidcc-config, tls-client-auth, mtls, client-metadata, interrupted]
keywords: [tls_client_auth, client certificate, metadata validation, interrupted, oidcc-client-test-idtoken-sig-none, signing-key-rotation]
patterns: [suite api log inspection, mtls metadata validation, static client configuration]
---

# BUG-003: OIDCC Config `tls_client_auth` Client Metadata Fails Suite Validation

## Description
OIDCC configuration tests using `client_auth_type=tls_client_auth` fail in `INTERRUPTED` state because the registered client metadata presents invalid TLS client auth certificate binding fields.

## Context
Confirmed through suite API log inspection of interrupted tests from the `20260410-023810` run.

Representative failing tests:
- `36VeRHITvCyCkrb` - `oidcc-client-test-idtoken-sig-none`
- `dlWy2fV9fWlx5Op` - `oidcc-client-test-signing-key-rotation-just-before-signing`
- `CxfIM7C9ozhTYsO` - `oidcc-client-test-signing-key-rotation`

Representative variants:
- `tls_client_auth`, `plain_http_request`, `default`
- `tls_client_auth`, `plain_http_request`, `form_post`
- `tls_client_auth`, `request_object`, `default`
- `tls_client_auth`, `request_object`, `form_post`

## Evidence
Observed suite failure from `GET /api/log/{id}`:

`ValidateClientCertificateForTlsClientAuth: Client must have only one of tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip and tls_client_auth_san_email metadata values set(cannot have more than one set)`

The suite confirms it receives a client certificate, then interrupts because the registered metadata is invalid.

## Current State
The RP/harness registers enough information for the suite to identify `tls_client_auth`, but the metadata values do not satisfy suite rules for a valid `tls_client_auth` client.

## Desired State
The registered client metadata should include exactly one valid TLS client auth binding method and pass suite validation.

## Requirements

### Functional Requirements
- Register `tls_client_auth` metadata in a way the suite accepts.
- Ensure the presented client certificate matches the selected binding metadata.
- Allow the three affected modules to progress beyond interruption.

### Non-Functional Requirements
- Do not break existing MTLS behavior for FAPI profiles.
- Keep static client metadata minimal and precise.

## Research Context

### Files to Inspect
- `conformance/harness/execute.go`
- `cmd/example-rp/conformance_keys.go`
- `cmd/example-rp/runtime_resolution.go`
- any suite/client registration payload builders

### Questions to Resolve
- Which `tls_client_auth_*` metadata field should be set for the current generated certificate?
- Is the harness implicitly setting multiple SAN/subject fields?

## Success Criteria

### Automated Verification
- [ ] `tls_client_auth` OIDCC config variants no longer fail with `ValidateClientCertificateForTlsClientAuth`.
- [ ] The three affected modules progress past interruption for those variants.
- [ ] `go test ./...` remains green.

### Manual Verification
- [ ] Suite logs show successful TLS client auth certificate validation for affected variants.
