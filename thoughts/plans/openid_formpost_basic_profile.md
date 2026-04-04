# OpenID Connect Form Post Basic Profile Implementation Plan

## Overview

Implement support for the OpenID Connect Core Form Post Basic Certification Profile in the existing example RP and conformance harness.

The target certification plan is `oidcc-client-formpost-basic-certification-test-plan`, which is an official OIDC RP plan in the upstream suite. The implementation should be a narrow extension of the already-supported Basic code flow, not a new standalone RP mode.

The upstream suite derives the form-post plan directly from the Basic RP plan by changing the response handling to form post (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/openid/client/OIDCCClientFormPostBasicTestPlan.java:17`). That makes this work primarily about:

- requesting `response_mode=form_post` when needed
- accepting authorization responses delivered via HTTP POST form bodies
- keeping the existing GET/query callback path fully intact

This plan is written TDD-first: each phase starts with failing tests, followed by the minimum implementation needed to make them pass.

## Current State Analysis

- OIDC conformance selection currently only includes `oidcc-client-basic-certification-test-plan` in `conformance/harness/profiles.go:11`.
- The example RP callback routes already accept `/callback` and `/callback/{alias}`, but the handler only reads authorization response parameters from the query string in `cmd/example-rp/main.go:117`.
- Core callback processing in `rp/callback.go:27` also reads only `req.URL.Query()` for `code`, `state`, and `iss`.
- The current example RP already supports POST endpoints elsewhere, so no router-level limitation prevents form-post support.
- The project explicitly does not support implicit flow, so this work should remain strictly code-flow-based (`SPECIFICATIONS.md:611`).
- Existing conformance runtime plumbing already resolves per-run RP settings via alias and is the right place to inject form-post-specific behavior (`cmd/example-rp/runtime_resolution.go`, `conformance/harness/rpruntime.go`).

## Desired End State

After completing this plan:

- The RP can initiate the Basic authorization code flow with either the default response mode or `response_mode=form_post`.
- The RP callback can consume authorization response parameters from either:
  - query parameters on GET callbacks, or
  - URL-encoded POST form bodies on form-post callbacks.
- The example RP handles form-post success and error responses without duplicating protocol logic.
- The conformance harness can discover/select the official OIDC form-post basic plan and run it directly.
- Running the harness with `-include-plan-regex='formpost-basic'` can exercise the profile in isolation.

### Success Criteria

#### Automated Verification
- [ ] `go test ./rp ./cmd/example-rp ./conformance/harness`
- [ ] `go test ./...`
- [ ] `gofumpt ./...`
- [ ] `go vet ./...`

#### Manual / Conformance Verification
- [ ] The RP issues authorization requests with `response_mode=form_post` when the form-post profile is active.
- [ ] A form-post callback reaches `/callback` or `/callback/{alias}` as HTTP POST and completes the normal Basic RP flow.
- [ ] `LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v -args -profile=oidc-rp -include-plan-regex='formpost-basic'` completes successfully, or produces focused failures directly tied to the uncovered form-post work.
- [ ] Existing Basic OIDC conformance coverage remains intact.

## Key Discoveries

- The upstream form-post plan reuses the Basic RP modules and only changes the response mode to form post (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/openid/client/OIDCCClientFormPostBasicTestPlan.java:17`).
- The existing Basic plan hardcodes `response_type=code` and `client_secret_basic`, so this effort should not alter flow shape, token auth, or userinfo behavior (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/openid/client/OIDCCClientBasicTestPlan.java:24`).
- The current callback stack has a single clear gap: it does not normalize callback parameters across query and form sources (`rp/callback.go:27`, `cmd/example-rp/main.go:118`).
- The conformance harness test fixtures already acknowledge the form-post plan name in `conformance/harness/profiles_test.go:15`, but production plan selection does not include it yet.

## What We're NOT Doing

- Implementing implicit, hybrid, or fragment-based OIDC response handling.
- Adding support for `form_post.jwt`, JARM, or any JWT-wrapped authorization response mode.
- Reworking the RP public API unless required by an internal clean abstraction.
- Implementing new FAPI behavior as part of this task.
- Broadening OIDC plan selection beyond the official Basic and Form Post Basic profiles.

## Implementation Approach

- Treat form-post as an alternate callback transport for the existing Basic code flow.
- Normalize authorization response parameter extraction in one shared place close to callback processing.
- Keep HTTP handlers thin; protocol validation should remain in `rp/`.
- Prefer conformance-runtime-driven configuration for `response_mode=form_post` rather than introducing a large new public option surface up front.
- Preserve compatibility with existing manual local usage and the current Basic conformance runs.

## Phase 1: Define Callback Parameter Normalization (TDD)

### Overview

Introduce a small internal abstraction that extracts authorization response parameters from either the query string or a POST form body, with deterministic precedence and minimal coupling.

### Changes Required

#### 1. Add callback parameter extraction tests
**Files**:
- `rp/callback_test.go`
- optionally `cmd/example-rp/main_test.go` for handler-level coverage

**Tests first**:
- GET callback with `code` and `state` in query still works.
- POST callback with `application/x-www-form-urlencoded` body containing `code` and `state` works.
- POST callback with `error` in form body is detected.
- POST callback to `/callback/{alias}` works the same as `/callback`.
- Empty POST body still fails with the existing missing state / missing code errors.
- Unsupported methods or malformed form parsing return a deterministic error path.

#### 2. Add shared callback parameter helper
**Files**:
- `rp/callback.go`
- optionally new internal helper file such as `rp/callback_params.go`

**Implementation**:
- Add an internal helper that returns normalized values for:
  - `code`
  - `state`
  - `iss`
  - `error`
  - optionally `error_description`
- The helper should:
  - use query parameters for existing GET behavior
  - parse POST form data for form-post callbacks
  - avoid changing state-store semantics or callback validation rules
- Be careful not to consume the body in a way that breaks later handler behavior.

### Success Criteria

#### Automated Verification
- [ ] New callback parsing tests are red first, then green.
- [ ] Existing callback tests continue to pass unchanged.

#### Manual Verification
- [ ] A local POST to `/callback` with a URL-encoded form body reaches the same callback validation path as the existing GET route.

---

## Phase 2: Extend RP Callback Processing to Use Normalized Params (TDD)

### Overview

Refactor `rp.HandleCallback` so protocol logic consumes normalized callback parameters instead of directly reading only `req.URL.Query()`.

### Changes Required

#### 1. Refactor callback flow to use extracted parameters
**File**: `rp/callback.go`

**Implementation**:
- Replace direct `req.URL.Query()` reads with the new helper.
- Preserve all existing validation semantics:
  - state is required
  - code is required for success path
  - FAPI authorization response `iss` checks remain unchanged
  - state-store consume behavior remains unchanged
- Keep all downstream logic identical after parameter normalization.

#### 2. Add regression tests for existing behavior
**File**: `rp/callback_test.go`

**Tests first**:
- invalid state still maps to `ErrInvalidState`
- missing code still maps to `ErrMissingCode`
- invalid issuer handling remains the same
- userinfo and token exchange behavior remain unaffected when callback params come from POST

### Success Criteria

#### Automated Verification
- [ ] `go test ./rp`
- [ ] No existing `rp` callback behavior regresses.

#### Manual Verification
- [ ] POST and GET callback transports behave identically after normalization.

---

## Phase 3: Update Example RP HTTP Handler for Form Post (TDD)

### Overview

Ensure the top-level example RP handler properly accepts and surfaces form-post authorization responses, especially authorization errors that arrive in the POST body.

### Changes Required

#### 1. Add handler tests
**File**: `cmd/example-rp/main_test.go`

**Tests first**:
- POST `/callback` with form body `error=access_denied` returns `400`.
- POST `/callback` with valid `code` and `state` calls the flow callback path.
- POST `/callback/alias-a` works with runtime alias resolution.
- GET callback behavior remains unchanged.

#### 2. Update handler logic
**File**: `cmd/example-rp/main.go`

**Implementation**:
- Replace direct query-only authorization error detection in `handleCallback` and `handleCallbackWithFlow` with the shared callback parameter extraction path or an equivalent request-level helper.
- Ensure `POST` is accepted naturally by the handler with no method gate that would block form-post.
- Keep response behavior unchanged:
  - authorization errors => `400`
  - RP validation failures => current status mapping
  - success => same HTML success page

### Success Criteria

#### Automated Verification
- [ ] `go test ./cmd/example-rp`
- [ ] POST form-post handler tests are red first, then green.

#### Manual Verification
- [ ] A browser-like form POST to the callback path is handled without custom route changes or duplicated logic.

---

## Phase 4: Request `response_mode=form_post` When the Profile Requires It (TDD)

### Overview

The RP must not only accept form-post callbacks; it must also ask for them when running the form-post certification profile.

### Changes Required

#### 1. Identify the cleanest configuration seam
**Files to inspect/update**:
- `rp/authrequest.go`
- `cmd/example-rp/runtime_resolution.go`
- `conformance/harness/rpruntime.go`
- any request-time runtime config structs used by the example RP

**Design goal**:
- introduce a small internal configuration value for response mode, ideally one that can be driven by conformance runtime registration.

#### 2. Add auth request tests
**File**: `rp/authrequest_test.go`

**Tests first**:
- default Basic authorization request does not change unexpectedly.
- when form-post mode is enabled, the outgoing authorization URL includes `response_mode=form_post`.
- other required auth request parameters remain unchanged.

#### 3. Thread runtime config through the example RP
**Implementation**:
- extend RP runtime config to carry the desired response mode for conformance jobs.
- when the selected plan is `oidcc-client-formpost-basic-certification-test-plan`, register runtime config that causes the example RP to request `response_mode=form_post`.
- ensure manual local defaults remain unchanged unless explicitly configured.

### Success Criteria

#### Automated Verification
- [ ] `go test ./rp ./cmd/example-rp ./conformance/harness`
- [ ] Authorization URL tests verify `response_mode=form_post` only when enabled.

#### Manual Verification
- [ ] During a form-post conformance run, the authorization request seen by the suite contains `response_mode=form_post`.

---

## Phase 5: Expand Harness Plan Selection and Runtime Modeling (TDD)

### Overview

Teach the harness to treat the official OIDC form-post basic plan as a supported OIDC RP plan and to register the right RP runtime settings for it.

### Changes Required

#### 1. Update plan-selection tests
**File**: `conformance/harness/profiles_test.go`

**Tests first**:
- `oidc-rp` selection includes:
  - `oidcc-client-basic-certification-test-plan`
  - `oidcc-client-formpost-basic-certification-test-plan`
- `all-rp` selection includes the same OIDC additions.
- filters like `-include-plan-regex='formpost'` isolate the new plan as expected.

#### 2. Update OIDC plan selection
**File**: `conformance/harness/profiles.go`

**Implementation**:
- add `oidcc-client-formpost-basic-certification-test-plan` to the explicit OIDC RP plan allowlist.
- do not add implicit or hybrid plans.

#### 3. Update runtime-profile derivation
**Files**:
- `conformance/harness/rpruntime.go`
- possibly `conformance/harness/execute.go`
- any related tests in `conformance/harness/rpruntime_test.go`

**Implementation**:
- derive or inject `response_mode=form_post` for the form-post plan.
- keep existing Basic RP runtime values unchanged.
- ensure alias-based request resolution continues to work for form-post callbacks.

### Success Criteria

#### Automated Verification
- [ ] `go test ./conformance/harness`
- [ ] Form-post plan appears in supported OIDC profile expansion.

#### Manual Verification
- [ ] `-include-plan-regex='formpost-basic'` selects the expected single OIDC plan.

---

## Phase 6: End-to-End Verification Against the Conformance Suite

### Overview

Run focused verification of the form-post profile and confirm that the new work does not regress the existing Basic profile.

### Changes Required

#### 1. Focused automated runs
**Commands**:

```bash
go test ./rp ./cmd/example-rp ./conformance/harness
gofumpt ./...
go vet ./...
```

#### 2. Focused conformance run
**Command**:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -include-plan-regex='formpost-basic'
```

#### 3. Regression run for existing OIDC basic
**Command**:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp -include-plan-regex='basic'
```

### Success Criteria

#### Automated Verification
- [ ] Focused unit and harness tests pass.
- [ ] Targeted form-post conformance run passes or isolates only residual infrastructure issues.
- [ ] Existing basic conformance run remains green.

#### Manual Verification
- [ ] Save the conformance artifact ZIP and note the exact plan name and final result.
- [ ] Confirm the suite observed a form-post callback rather than a query-mode callback.

---

## Implementation Notes and Design Constraints

- Prefer a single source of truth for callback parameter extraction. Do not duplicate query/form parsing in multiple handlers if a shared helper can be used safely.
- Keep form-post parsing limited to standard URL-encoded form bodies unless the suite proves multipart is necessary.
- Avoid broadening public API surface unless internal configuration plumbing becomes too awkward; the first target is conformance-driven behavior, not a generalized response-mode product feature.
- Preserve existing callback error-to-status mapping in `cmd/example-rp/main.go:183`.
- Do not relax any validation behavior merely to accommodate form-post transport.

## Risks and Mitigations

### Risk: callback parsing diverges between handler and RP logic
Mitigation:
- centralize parameter extraction and add both handler-level and RP-level tests.

### Risk: form-post callback body parsing interferes with state store or later request use
Mitigation:
- use standard `ParseForm`/`PostForm` patterns and keep extraction close to request handling.

### Risk: outgoing auth request never actually asks for form-post
Mitigation:
- add explicit authorization URL tests and conformance-runtime assertions for `response_mode=form_post`.

### Risk: expanding `oidc-rp` selection unintentionally pulls in unsupported OIDC profiles later
Mitigation:
- keep OIDC plan selection as a small explicit allowlist rather than broad name-based inference.

## File-by-File Expected Touch Points

- `rp/callback.go` - normalize callback parameter extraction and use it in `HandleCallback`.
- `rp/callback_test.go` - add query vs form-post callback coverage.
- `rp/authrequest.go` - optionally add `response_mode=form_post` support.
- `rp/authrequest_test.go` - add response-mode coverage.
- `cmd/example-rp/main.go` - accept auth errors from form-post payloads and preserve current success/error handling.
- `cmd/example-rp/main_test.go` - add POST callback tests, including alias paths.
- `cmd/example-rp/runtime_resolution.go` - carry response-mode or profile-specific callback behavior from runtime config.
- `conformance/harness/profiles.go` - include the form-post basic plan.
- `conformance/harness/profiles_test.go` - update expected plan expansion.
- `conformance/harness/rpruntime.go` - encode runtime behavior needed for the form-post plan.
- `conformance/harness/rpruntime_test.go` - verify the derived runtime config for the form-post plan.

## Recommended Execution Order

1. Add callback normalization tests in `rp/` and implement shared extraction.
2. Add example handler POST/error tests and update `cmd/example-rp/main.go`.
3. Add auth request response-mode tests and runtime config plumbing.
4. Expand harness OIDC plan selection.
5. Run focused package tests.
6. Run targeted form-post conformance.
7. Run Basic OIDC regression conformance.

## Definition of Done

This plan is complete when:

- the example RP can both request and process `response_mode=form_post` for the official OIDC Form Post Basic profile
- `oidc-rp` profile expansion includes the official Basic and Form Post Basic plans, but not unsupported implicit/hybrid plans
- targeted unit/harness tests pass
- the form-post conformance profile is runnable in isolation and validated with saved evidence
