# FAPI 2.0 Message Signing Final RP Implementation Plan

## Overview

Implement support for the official final OpenID Foundation relying party profile `fapi2-message-signing-final-client-test-plan` in the example RP and conformance harness.

This work should build directly on the existing FAPI 2.0 Security Profile Final implementation already present in the repo. The main missing capabilities are the message-signing pieces called out explicitly in the repo status docs:

- JAR / signed request objects
- JARM / signed authorization responses

The implementation should focus first on the official final `plain_fapi` profile, not the implementer's-draft `id1` / `id2` plans and not ecosystem-specific variants like UK OB, AU CDR, Brazil, ConnectID, or CBUAE.

This plan is written TDD-first: every phase starts by adding failing tests, followed by the minimum implementation needed to make them pass.

## Current State Analysis

- The repo already supports the core FAPI 2.0 Security Profile Final building blocks:
  - PAR is implemented in `rp/par.go`.
  - private key JWT and mTLS client auth are implemented in `rp/token_exchange.go`, `rp/par.go`, and `rp/auth_method.go`.
  - DPoP and mTLS sender constraining are implemented in `rp/dpop.go` and the FAPI request paths.
  - rich authorization requests are already modeled via `WithAuthorizationDetails` in `rp/options.go:171`.
  - request-time response mode plumbing exists through `WithResponseMode` in `rp/options.go:228` and runtime config in `cmd/example-rp/runtime_resolution.go:50`.
- Discovery metadata already exposes the fields needed for message signing:
  - `request_object_signing_alg_values_supported` in `oidc/metadata_provider.go:19`
  - `authorization_signing_alg_values_supported` in `oidc/metadata_provider.go:37`
- The RP currently builds plain authorization request parameters in `rp/par.go:41`; there is no request object construction or signing.
- The RP callback currently understands plain authorization response parameters plus the FAPI `iss` parameter; it does not parse or validate a JARM `response` JWT in `rp/callback.go:27`.
- The repo still marks FAPI 2.0 Message Signing as not implemented and specifically calls out JAR and JARM as missing in `SPECIFICATIONS.md:529`.
- The current conformance matrices only model the security-profile final `plain_fapi` variants in `conformance/harness/matrix.go:28`; there is no message-signing-final matrix.
- Harness variant preference logic already prefers `signed_non_repudiation` when that variant is exposed (`conformance/harness/execute.go:688`), but it still prefers `plain_response` over `jarm` (`conformance/harness/execute.go:696`) and does not model message-signing coverage explicitly.
- `fapi-rp` plan tests in `conformance/harness/profiles_test.go:37` still center draft-era `id1` / `id2` fixtures and do not mention the final message-signing RP plan.

## Desired End State

After completing this plan:

- The RP can generate signed authorization request objects for FAPI 2.0 Message Signing Final.
- Signed request objects can be sent through the existing PAR path, while preserving current FAPI client authentication and sender-constraining behavior.
- The RP can receive and validate signed JARM authorization responses when `fapi_response_mode=jarm`.
- The RP continues to support plain FAPI final security-profile behavior with no regression.
- The conformance harness can run focused official-final message-signing matrices for `plain_fapi`.
- The implementation includes an incremental bring-up path:
  - JAR with `plain_response` first
  - then JARM
  - then the broader `rar` / `plain_oauth` matrix

### Success Criteria

#### Automated Verification
- [ ] `go test ./rp ./cmd/example-rp ./conformance/harness`
- [ ] `go test ./...`
- [ ] `gofumpt ./...`
- [ ] `go vet ./...`

#### Manual / Conformance Verification
- [ ] A targeted message-signing-final run can be executed in isolation against `plain_fapi`.
- [ ] The RP sends signed request objects when the message-signing-final profile is active.
- [ ] The RP successfully handles both `plain_response` and `jarm` modes for the official final `plain_fapi` profile.
- [ ] Existing `fapi2-security-profile-final-client-test-plan` coverage remains intact.

## Official Final Scope

This plan intentionally targets the official final message-signing profile for the generic final FAPI 2.0 profile:

- plan: `fapi2-message-signing-final-client-test-plan`
- initial sub-profile: `fapi_profile=plain_fapi`

Out of scope for the first implementation wave:

- `fapi2-message-signing-id1-client-test-plan`
- `fapi2-security-profile-id2-client-test-plan`
- `openbanking_uk`
- `consumerdataright_au`
- `openbanking_brazil`
- `connectid_au`
- `cbuae`

## Key Discoveries

- The upstream final message-signing RP plan is `fapi2-message-signing-final-client-test-plan` in `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2MessageSigningFinalClientTestPlan.java:14`.
- The final message-signing client plan reuses the same base client modules as the final security profile and adds JARM-capable variants rather than a whole new response-processing architecture.
- The upstream final plan varies across these axes:
  - `client_auth_type`
  - `sender_constrain`
  - `authorization_request_type`
  - `fapi_client_type`
  - `fapi_request_method`
  - `fapi_response_mode`
  - `fapi_profile`
- For the official-final `plain_fapi` message-signing target, the strategically relevant request-method value is `signed_non_repudiation` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/variant/FAPI2AuthRequestMethod.java:8`).
- JARM support in the suite is driven by `fapi_response_mode=jarm`; plain responses remain available under `fapi_response_mode=plain_response` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/variant/FAPIResponseMode.java:8`).
- The upstream suite adds JARM metadata by publishing signed authorization-response support in discovery via `AddJARMToServerConfiguration` (`conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/sequence/as/AddJARMToServerConfiguration.java:8`).
- The current RP already supports provider-metadata parsing for both request-object signing algorithms and authorization-response signing algorithms, so the discovery layer is not the blocker.

## Recommended Coverage Strategy

Start with official-final `plain_fapi` only and add a dedicated message-signing matrix family.

### Phase 0 Matrix Goal

Fix these values:

- `fapi_profile=plain_fapi`
- `fapi_request_method=signed_non_repudiation`

Vary these values:

- `client_auth_type`: `private_key_jwt`, `mtls`
- `sender_constrain`: `mtls`, `dpop`
- `authorization_request_type`: `simple`, `rar`
- `fapi_client_type`: `oidc`, `plain_oauth`
- `fapi_response_mode`: `plain_response`, `jarm`

That yields `2 x 2 x 2 x 2 x 2 = 32` meaningful official-final `plain_fapi` message-signing combinations.

### Recommended Bring-Up Order

1. `signed_non_repudiation + plain_response + simple + oidc` x all auth/sender combinations = 4 runs
2. `signed_non_repudiation + jarm + simple + oidc` x all auth/sender combinations = 4 runs
3. expand to `rar` and `plain_oauth`
4. complete the full 32-case matrix

This keeps JAR and JARM bring-up separate and reduces first-wave debugging scope.

## What We're NOT Doing

- Implementing the draft `id1` or `id2` profiles.
- Implementing ecosystem-specific final profiles in the first wave.
- Implementing JWE-encrypted JARM unless the suite proves signed-only JARM is insufficient.
- Reworking unrelated OAuth client-credentials or server-side conformance flows.
- Broadly changing FAPI plan-selection semantics beyond what is needed to support official final message signing cleanly.

## Implementation Approach

- Treat message signing as an extension of the existing FAPI 2.0 browser flow rather than a parallel RP implementation.
- Add a focused internal model for signed authorization requests and JARM response handling.
- Reuse existing PAR, state-store, DPoP, mTLS, and private key JWT primitives.
- Keep conformance configuration request-time and alias-scoped, following the current runtime-registry pattern.
- Make the harness explicit about official final message-signing matrices instead of relying only on ad hoc variant defaults.

## Phase 1: Add Runtime and RP Modeling for Message Signing (TDD)

### Overview

Introduce the minimal internal configuration surface needed to tell the RP when to use signed request objects and when to expect JARM.

### Changes Required

#### 1. Add runtime/config tests
**Files**:
- `conformance/harness/rpruntime_test.go`
- `cmd/example-rp/main_test.go` and/or `cmd/example-rp/runtime_registry_test.go`
- `rp/authrequest_test.go`

**Tests first**:
- runtime config can carry `fapi_request_method=signed_non_repudiation`
- runtime config can carry `fapi_response_mode=jarm`
- resolved RP request enables signed request object behavior when message-signing config is active
- resolved RP request enables JARM callback handling when response mode is `jarm`

#### 2. Extend runtime models
**Files**:
- `conformance/harness/rpruntime.go`
- `cmd/example-rp/runtime_registry.go`
- `cmd/example-rp/runtime_resolution.go`
- `rp/options.go`
- `rp/rp.go`

**Implementation**:
- add a runtime field for request method / signed-request mode
- thread it from harness runtime registration into the example RP
- add a small internal RP option or field to enable signed authorization requests
- keep existing plain FAPI behavior unchanged by default

### Success Criteria

#### Automated Verification
- [ ] runtime-model tests are red first, then green
- [ ] no existing form-post or security-profile runtime behavior regresses

#### Manual Verification
- [ ] a runtime registration for message-signing-final can be inspected and shows explicit request-method / response-mode values

---

## Phase 2: Build and Sign Authorization Request Objects (JAR) (TDD)

### Overview

Implement signed request-object generation for authorization requests, using the existing client key provider and FAPI-friendly signing algorithms.

### Changes Required

#### 1. Add request-object builder tests
**Files**:
- new `rp/request_object_test.go`
- `rp/authrequest_test.go`
- `rp/par_test.go`

**Tests first**:
- a signed request object is created when message-signing mode is enabled
- the request object includes the expected core claims / parameters:
  - `iss`
  - `aud`
  - `client_id`
  - `response_type=code`
  - `redirect_uri`
  - `scope`
  - `state`
  - `nonce` when OpenID is in scope
  - `code_challenge`
  - `code_challenge_method=S256`
  - `authorization_details` when RAR is active
- the JOSE header includes the configured `kid`
- unsupported or non-FAPI signing algorithms are rejected in message-signing mode
- message-signing request objects use current time claims such as `iat`, `nbf`, `exp`, and `jti`

#### 2. Add request-object builder implementation
**Files**:
- new `rp/request_object.go`
- `rp/par.go`
- `rp/authrequest.go`
- optionally `rp/errors.go`

**Implementation**:
- add a helper to build a request-object claims set from the existing authorization parameters
- sign the request object using the client key provider and `go-jose`
- validate or constrain signing algorithms for message-signing mode
- use provider metadata where useful for supported request-object algorithms

### Design Notes

- Prefer constructing the request object from the same normalized parameter source already used for plain auth requests, so there is one source of truth for nonce, state, PKCE, scopes, and RAR data.
- Keep signed request generation independent from PAR transport logic so it can be tested directly.

### Success Criteria

#### Automated Verification
- [ ] request-object unit tests are red first, then green
- [ ] signed request objects are deterministic enough for structural assertions in tests

#### Manual Verification
- [ ] request objects generated in local debugging contain the expected claims and are signed with the client key

---

## Phase 3: Send Signed Request Objects Through PAR (TDD)

### Overview

Integrate JAR with the existing PAR flow so message-signing-final requests are transmitted in the FAPI 2.0 pattern the suite expects.

### Changes Required

#### 1. Add PAR integration tests
**Files**:
- `rp/par_test.go`
- possibly `cmd/example-rp/main_test.go`

**Tests first**:
- PAR request sends a `request` parameter containing the signed request object when message-signing mode is active
- PAR request still includes current client authentication behavior:
  - private key JWT client assertion when configured
  - mTLS behavior when configured
- DPoP nonce retry behavior still works with signed PAR requests
- RAR still survives in the signed request object under `authorization_request_type=rar`
- plain security-profile requests continue to send plain form parameters when message-signing mode is not active

#### 2. Update PAR construction
**Files**:
- `rp/par.go`
- possibly `rp/authrequest.go`

**Implementation**:
- when signed request mode is active, build a request object from authorization parameters and send it to PAR as `request`
- keep `client_assertion` / `client_assertion_type` behavior unchanged
- ensure the post-PAR browser redirect remains `client_id + request_uri`
- avoid leaking duplicate plain authorization parameters outside the request object unless specifically required by the suite or spec

### Success Criteria

#### Automated Verification
- [ ] `go test ./rp`
- [ ] message-signing PAR tests are red first, then green

#### Manual Verification
- [ ] the suite sees signed request objects at the PAR endpoint for message-signing-final runs

---

## Phase 4: Parse and Validate JARM Authorization Responses (TDD)

### Overview

Extend callback processing to support signed JWT authorization responses under `fapi_response_mode=jarm`.

### Changes Required

#### 1. Add JARM parsing and validation tests
**Files**:
- new `rp/jarm_test.go`
- `rp/callback_test.go`
- `cmd/example-rp/main_test.go`

**Tests first**:
- callback recognizes a `response` JWT when JARM mode is enabled
- signed JARM response is verified using provider signing keys
- required claims are validated, at minimum:
  - `iss`
  - `aud`
  - `exp`
  - `state` when present / required by current flow
  - `code` for success path
- invalid JARM signature is rejected
- missing required JARM claims are rejected
- `alg=none` is rejected
- plain-response mode remains unchanged
- POST form-post callback parsing and existing plain query parsing continue to work

#### 2. Implement JARM handling
**Files**:
- new `rp/jarm.go`
- `rp/callback.go`
- optionally a shared callback parameter extraction helper if form-post work did not already centralize this

**Implementation**:
- extend callback normalization so it can interpret either:
  - plain callback params, or
  - a signed JARM `response` parameter
- verify signed JARM responses using the provider JWKS and authorization signing metadata when available
- normalize validated JARM claims into the same callback-processing path used by plain responses
- keep existing state-store, token exchange, and userinfo logic downstream of normalization

### Success Criteria

#### Automated Verification
- [ ] `go test ./rp`
- [ ] JARM tests are red first, then green

#### Manual Verification
- [ ] the RP completes JARM callback handling without any special route differences from plain callbacks

---

## Phase 5: Add Message-Signing-Final Matrices to the Harness (TDD)

### Overview

Make the conformance harness capable of running explicit official-final message-signing subsets and the full `plain_fapi` matrix.

### Changes Required

#### 1. Add matrix-expansion tests
**Files**:
- `conformance/harness/matrix_test.go`
- possibly `conformance/harness/jobs_test.go`

**Tests first**:
- new message-signing-final subset matrix expands to the expected 4 runs
- new JARM subset matrix expands to the expected 4 runs
- full `plain_fapi` message-signing matrix expands to 32 runs
- all message-signing-final variants fix `fapi_request_method=signed_non_repudiation`
- response mode varies appropriately across plain and JARM subsets

#### 2. Implement matrix expansion
**Files**:
- `conformance/harness/matrix.go`
- optionally `conformance/harness/AGENTS.md`

**Suggested matrix names**:
- `fapi2-ms-final-plain-fapi-jar4`
- `fapi2-ms-final-plain-fapi-jarm4`
- `fapi2-ms-final-plain-fapi-all32`

**Implementation**:
- add message-signing-final matrix builders parallel to the existing security-profile matrices
- derive RP runtime config fields for:
  - `fapi_request_method=signed_non_repudiation`
  - `fapi_response_mode=plain_response|jarm`
  - `authorization_request_type`
  - `fapi_client_type`
  - auth method and sender constraint

### Success Criteria

#### Automated Verification
- [ ] `go test ./conformance/harness`
- [ ] matrix tests are red first, then green

#### Manual Verification
- [ ] a focused harness command can select only official-final message-signing variants

---

## Phase 6: Align Harness Plan Selection, Docs, and Final-First Workflow

### Overview

Update harness tests and docs so final official message-signing support is visible and repeatable.

### Changes Required

#### 1. Update plan-selection tests and documentation
**Files**:
- `conformance/harness/profiles_test.go`
- `conformance/AGENTS.md`
- `conformance/README.md`
- `SPECIFICATIONS.md`

**Implementation**:
- add test fixtures that include `fapi2-message-signing-final-client-test-plan`
- document official-final message-signing as the next supported FAPI target rather than draft-era plans
- add recommended commands for the new subset matrices and the full `all32` matrix
- update `SPECIFICATIONS.md` status once implementation is complete and verified

#### 2. Keep draft profiles de-emphasized
**Implementation**:
- do not remove draft profile support if the suite still exposes it, but ensure docs and recommended commands steer toward final official plans

### Success Criteria

#### Automated Verification
- [ ] harness profile tests pass with final-plan fixtures included

#### Manual Verification
- [ ] docs show a clear official-final execution path for message-signing-final

---

## Phase 7: End-to-End Verification and Regression Testing

### Overview

Run a staged conformance verification plan, starting from the smallest official-final subset and widening only after the prior wave is stable.

### Commands

#### Local tests

```bash
go test ./rp ./cmd/example-rp ./conformance/harness
gofumpt ./...
go vet ./...
```

#### First-wave JAR-only subset

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-jar4 \
  -parallel \
  -max-parallel-runs=4
```

#### Second-wave JARM subset

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-jarm4 \
  -parallel \
  -max-parallel-runs=4
```

#### Full official-final `plain_fapi` message-signing matrix

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-message-signing-final-client-test-plan' \
  -matrix=fapi2-ms-final-plain-fapi-all32 \
  -parallel \
  -max-parallel-runs=8
```

#### Regression against existing security profile final

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=fapi-rp \
  -include-plan-regex='fapi2-security-profile-final-client-test-plan' \
  -matrix=fapi2-sp-final-plain-fapi-all16 \
  -parallel \
  -max-parallel-runs=8
```

### Success Criteria

#### Automated Verification
- [ ] JAR-only subset passes or isolates only message-signing-specific failures
- [ ] JARM subset passes after callback/JARM work lands
- [ ] full `all32` matrix is runnable
- [ ] existing security-profile final matrix remains green

#### Manual Verification
- [ ] save evidence ZIPs for at least the JAR subset, JARM subset, and one full-matrix run
- [ ] record exact plan names, matrix names, and failing modules if any remain

## Risks and Mitigations

### Risk: signed request objects duplicate or conflict with plain authorization parameters
Mitigation:
- centralize authorization-parameter generation and explicitly define what is placed inside the request object versus outside it.

### Risk: callback logic becomes fragmented across plain, form-post, and JARM transports
Mitigation:
- normalize callback inputs into a single internal callback-parameter struct before state validation and token exchange.

### Risk: algorithm handling is too permissive for message-signing-final
Mitigation:
- add explicit tests for FAPI-friendly signing algorithms and reject unsupported / insecure values in message-signing mode.

### Risk: JARM verification uses the wrong metadata or key source
Mitigation:
- use provider discovery metadata and the existing JWKS resolution path, with targeted tests for algorithm allowlists and signature failures.

### Risk: harness defaults accidentally test `plain_response` only and leave JARM unexercised
Mitigation:
- add explicit JARM matrices and document them as a required second-wave verification step.

## File-by-File Expected Touch Points

- `rp/rp.go` - add internal message-signing configuration fields.
- `rp/options.go` - add internal or public options needed to enable signed request objects / JARM expectations.
- `rp/authrequest.go` - thread message-signing authorization-request behavior.
- `rp/par.go` - send signed request objects through PAR.
- `rp/callback.go` - normalize callback handling for JARM.
- `rp/idtoken.go` - likely no direct structural change required, but ensure no regressions in existing FAPI validation.
- `rp/request_object.go` - new signed request-object builder.
- `rp/jarm.go` - new JARM parsing and validation logic.
- `rp/request_object_test.go` - new JAR tests.
- `rp/jarm_test.go` - new JARM tests.
- `cmd/example-rp/runtime_registry.go` - store message-signing runtime fields.
- `cmd/example-rp/runtime_resolution.go` - translate runtime fields into RP options.
- `conformance/harness/matrix.go` - add message-signing-final matrix expansion.
- `conformance/harness/matrix_test.go` - add subset and full-matrix coverage.
- `conformance/harness/rpruntime.go` - include request-method and response-mode in runtime registration.
- `conformance/harness/rpruntime_test.go` - verify runtime request content.
- `conformance/harness/profiles_test.go` - add official-final message-signing fixtures.
- `conformance/AGENTS.md` - document execution commands for official-final message-signing.
- `conformance/README.md` - add focused run examples.
- `SPECIFICATIONS.md` - update status after implementation and verification.

## Recommended Execution Order

1. Add runtime/request-method modeling for message signing.
2. Build and test the signed request-object helper.
3. Integrate signed request objects into PAR.
4. Add and test JARM callback parsing and validation.
5. Add official-final message-signing matrices to the harness.
6. Run `jar4` subset.
7. Run `jarm4` subset.
8. Run full `all32` matrix.
9. Run security-profile final regression.

## Definition of Done

This plan is complete when:

- the RP can send signed authorization request objects for `fapi2-message-signing-final-client-test-plan`
- the RP can validate signed JARM responses for `fapi_response_mode=jarm`
- the harness can run official-final `plain_fapi` message-signing subsets and the full 32-case matrix
- docs and tests reflect a final-first workflow rather than draft-first coverage
- existing security-profile final conformance remains intact
