---
type: feature
priority: high
created: 2026-02-22T16:15:24Z
status: implemented
tags: [oidc, conformance, rp, basic-profile, userinfo, discovery]
keywords: [OpenID Connect Core Basic Certification Profile Relying Party Tests, cmd/example-rp/main.go, /callback, conformance suite, authorization code flow, ID token validation, UserInfo endpoint, discovery, jwks_uri, local conformance report]
patterns: [minimal RP endpoint wiring, authorization code exchange flow, ID token signature and claims validation, UserInfo access token usage, discovery metadata consumption, conformance negative test handling, deterministic test execution, report artifact capture]
---


# FEATURE-003: Implement Basic RP Test Profile and Verify Against Conformance Suite

## Description

Implement a basic relying party (RP) conformance-capable profile in this repository and verify it against the OpenID conformance suite profile `OpenID Connect Core: Basic Certification Profile Relying Party Tests`.

This work must move the current example RP from placeholder callbacks to protocol behavior required to run and pass the selected profile, including negative/failure coverage required by that profile set.

## Context

Local conformance infrastructure is already in place (`conformance/` and `https://suite.test` + `https://rp.test` workflow), but the current RP endpoint is a placeholder and currently expected to fail protocol tests.

Primary goal is to unblock downstream integration work by providing a known-good baseline RP profile validated with local conformance evidence.

Primary users are both maintainers and external integrators using this library/setup.

## Requirements

### Functional Requirements
- Implement RP behavior for Authorization Code flow only (no PKCE/hybrid in this ticket).
- Support ID Token validation and UserInfo usage needed by the selected basic RP profile.
- Support OP discovery usage in test flow; JWKS rotation handling is explicitly not required in this ticket.
- Keep UI surface minimal (single callback page/endpoint behavior only).
- Verify against the OpenID conformance suite using the existing local setup.
- Include negative/failure profile coverage needed for the full selected test set (not just happy-path checks).
- Produce local conformance verification evidence including report details and exact profile/test IDs passed.
- Provide runbook-level documentation for running the profile and collecting evidence.

### Non-Functional Requirements
- Prioritize OIDC spec correctness/compliance over performance optimization.
- Keep conformance runs deterministic and reduce timing-related flakiness where feasible.
- Avoid logging or leaking sensitive test credentials/secrets.
- New dependencies are allowed if they are minimal and justified.

### Out of Scope
- Advanced profiles/specs (PAR, JAR, JARM, FAPI-related requirements).
- RP-initiated logout/session management.
- Refresh token grant coverage.
- Dynamic client registration.
- CI integration (blocking or non-blocking conformance jobs).
- New containerized setup work (use existing conformance environment as-is).

## Current State

- `cmd/example-rp/main.go` provides placeholder handlers (`/` and `/callback`) and does not implement RP protocol flow logic.
- `conformance/README.md` documents how to start and run the basic profile but notes expected failures due to missing RP features.
- Existing conformance setup is local-first; completion gate for this ticket is local pass evidence.

## Desired State

The repository includes a basic RP implementation that can complete and pass the targeted OpenID Core basic RP conformance profile locally, with reproducible run instructions and captured local conformance report artifacts.

## Research Context

Research should focus on identifying exact profile requirements and mapping those requirements to concrete code changes in the current RP entrypoint and supporting library code.

### Keywords to Search
- `OpenID Connect Core: Basic Certification Profile Relying Party Tests` - target profile and expected behaviors.
- `cmd/example-rp/main.go` - current RP entrypoint to evolve from placeholder logic.
- `/callback` - redirect endpoint behavior and response handling.
- `authorization_code` - required flow mechanics and token exchange points.
- `id_token` - validation requirements (signature, issuer, audience, nonce, timestamps as applicable).
- `userinfo_endpoint` - access token usage and response handling in profile tests.
- `openid-configuration` - discovery metadata retrieval requirements.
- `jwks_uri` - key material retrieval for token validation.
- `conformance/README.md` - existing operational runbook to extend with pass workflow.
- `conformance report` - artifact capture format and traceability for pass evidence.

### Patterns to Investigate
- Minimal RP request/response routing patterns that satisfy conformance harness expectations.
- Token exchange implementation patterns in Go with clear error propagation.
- ID token validation patterns aligned with OIDC Core and current library primitives.
- UserInfo fetch + claim handling patterns needed by RP profile assertions.
- Deterministic conformance-run patterns (timeouts, stable config, predictable callback behavior).
- Negative test handling patterns (proper rejection/error behavior rather than permissive handling).
- Local artifact capture patterns for preserving test IDs/results.

### Key Decisions Made
- Ticket type is `feature` because this adds net-new RP conformance capability.
- Primary business goal is to unblock integration.
- Scope is Authorization Code only.
- Include both ID Token and UserInfo validation behavior in v1.
- Discovery is in scope; JWKS rotation is deferred.
- Dynamic registration is out of scope.
- Include full negative/failure coverage required by selected profile set.
- Minimal UI is a single callback page/endpoint.
- Docs depth is runbook-level only.
- Completion gate is local pass evidence, plus saved conformance report details.
- CI conformance automation is out of scope.
- Breaking API/config changes are acceptable if needed to reach conformance.

## Success Criteria

Ticket is complete when local execution against the targeted basic RP profile passes with captured evidence, and runbook docs enable another engineer to reproduce the same result.

### Automated Verification
- [ ] `go test ./...` passes after RP changes.
- [ ] `go vet ./...` passes.
- [ ] `gofumpt ./...` produces no diffs.

### Manual Verification
- [ ] Using existing `conformance/` setup, run the basic RP profile against `https://rp.test/callback` and obtain passing results for targeted tests.
- [ ] Capture and store/report conformance output including profile name and exact test IDs/statuses.
- [ ] Verify required negative/failure scenarios in the selected profile set are satisfied.
- [ ] Follow documented runbook steps end-to-end on a clean local environment.

## Related Information

- Existing local conformance setup ticket: `thoughts/tickets/feature_openid_conformance_local.md`
- Existing local setup plan: `thoughts/plans/openid_conformance_local.md`
- Current runbook: `conformance/README.md`
- Current RP entrypoint: `cmd/example-rp/main.go`

## Notes

- Scope boundary was intentionally tightened by excluding advanced OIDC/FAPI features and CI integration.
- Because breaking changes are allowed, planning should still document migration impact before implementation begins.
