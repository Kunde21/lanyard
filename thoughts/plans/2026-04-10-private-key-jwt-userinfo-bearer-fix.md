# BUG-002 Private Key JWT UserInfo Bearer Fix Implementation Plan

## Overview

Fix OIDCC config flows where `client_auth_type=private_key_jwt` reaches `/userinfo` with `Authorization: DPoP ...` instead of a bearer token when no sender constraint was requested. The implementation should make DPoP opt-in through explicit `sender_constrain=dpop`, preserving bearer UserInfo requests for ordinary OIDC config runs while keeping explicit DPoP and mTLS behavior intact.

## Current State Analysis

The callback flow is carrying the access token correctly into UserInfo. `HandleCallback` exchanges the code, rejects empty `access_token` values, and passes `tokenResp.AccessToken` directly into `fetchUserInfo`: `rp/callback.go:133-170`.

The regression happens inside UserInfo request construction. `buildUserInfoRequest` correctly builds a bearer-header request for header transport and an `access_token` form body for body transport: `rp/userinfo.go:73-95`. But `fetchUserInfo` later overwrites the header with `Authorization: DPoP <token>` whenever `shouldUseDPoP()` returns true: `rp/userinfo.go:16-29`.

The current DPoP decision is too broad. `shouldUseDPoP()` returns true when a `clientKeyProvider` exists and the resolved auth method is `private_key_jwt` or `tls_client_auth`, even if `sender_constrain` was never configured: `rp/dpop.go:194-196`, `rp/dpop.go:252-257`. For OIDCC config `private_key_jwt` runs, the example RP loads a signing key provider for client assertions but usually leaves `sender_constrain` empty: `cmd/example-rp/conformance_keys.go:119-173`, `cmd/example-rp/runtime_resolution.go:149-185`. That implicitly enables DPoP on UserInfo and causes the suite to report a missing bearer token.

The codebase already models token-endpoint auth and sender constraining as separate concerns. `WithAuthMethod` and `WithSenderConstrain` are separate options, and the example RP wires them separately in `buildRPFromResolvedRequest`: `rp/options.go:181-229`, `cmd/example-rp/runtime_resolution.go:317-336`. Existing tests currently encode the old implicit-DPoP default and will need to be updated to the explicit-only semantics: `rp/dpop_usage_test.go:9-27`.

## Desired End State

`private_key_jwt` remains a token-endpoint client authentication method only. DPoP is used only when the caller explicitly configures `sender_constrain=dpop`. As a result:

- OIDCC config `private_key_jwt` runs without sender constraint send `Authorization: Bearer <token>` to UserInfo.
- Explicit `sender_constrain=dpop` flows still send `Authorization: DPoP <token>` plus a DPoP proof.
- Explicit `sender_constrain=mtls` flows continue to avoid DPoP and use the mTLS UserInfo alias when available.
- The affected OIDCC modules progress past the interrupted UserInfo step.

### Key Discoveries:
- `HandleCallback` preserves and passes the access token into UserInfo, so the token is not dropped before the call: `rp/callback.go:133-170`.
- `fetchUserInfo` is where bearer authorization is replaced with DPoP authorization: `rp/userinfo.go:16-29`.
- `shouldUseDPoP()` currently treats `private_key_jwt` plus any key provider as sufficient for DPoP, even without explicit sender constraint: `rp/dpop.go:252-257`.
- The runtime wiring already separates `authMethod` from `senderConstrain`, so explicit-only DPoP aligns with the surrounding configuration model: `cmd/example-rp/runtime_resolution.go:161-167`, `cmd/example-rp/runtime_resolution.go:325-335`, `rp/options.go:181-229`.

## What We're NOT Doing

- We are not changing token propagation in `HandleCallback`; the access token is already present there.
- We are not redesigning UserInfo body transport; existing header/body transport support remains as-is.
- We are not adding conformance-only special cases in the example RP to mask library behavior.
- We are not broadening this work into JWKS plan-config fixes or other unrelated OIDCC conformance issues.

## Implementation Approach

Make the smallest behavior change at the DPoP decision point. The plan should change `shouldUseDPoP()` so DPoP is enabled only for explicit `sender_constrain=dpop`, not inferred from `private_key_jwt` alone. Then update tests to assert the new default and confirm explicit DPoP still works for UserInfo. Finally, verify the example RP/runtime wiring still passes through explicit sender constraints unchanged and document conformance reruns for the affected OIDCC modules and the private-key-jwt FAPI guardrails.

## Phase 1: DPoP Semantics Correction

### Overview

Change the library default so sender constraining is explicit. This fixes the root cause without adding per-endpoint exceptions.

### Changes Required:

#### 1. DPoP decision logic
**File**: `rp/dpop.go`
**Changes**: Narrow `shouldUseDPoP()` so it returns true only when `sender_constrain` is explicitly `dpop` and the RP has the required key material for a DPoP-capable auth method.

```go
func (r *RP) shouldUseDPoP() bool {
	return r.senderConstrain == SenderConstrainDPoP &&
		r.clientKeyProvider != nil &&
		isDPoPSupported(r.resolvedAuthMethod)
}
```

This removes the fallback branch that currently turns `private_key_jwt` into implicit DPoP when `sender_constrain` is unset.

#### 2. UserInfo authorization behavior coverage
**File**: `rp/userinfo_test.go`
**Changes**: Add or adjust tests to assert that:

- `private_key_jwt` without explicit sender constraint keeps `Authorization: Bearer <token>` on UserInfo.
- `private_key_jwt` with `sender_constrain=dpop` still sends `Authorization: DPoP <token>` plus a DPoP proof.
- existing DPoP nonce-retry coverage remains valid for explicit DPoP flows.

```go
r, err := New(...,
	WithAuthMethod(AuthMethodPrivateKeyJWT),
	WithClientKeyProvider(...),
)

_, err = r.fetchUserInfo(ctx, ts.URL, "access-token", "sub-123", UserInfoTokenTransportHeader)

if diff := cmp.Diff("Bearer access-token", gotAuth); diff != "" {
	t.Fatalf("Authorization header mismatch (-want +got):\n%s", diff)
}
```

#### 3. Unit test expectation update for default semantics
**File**: `rp/dpop_usage_test.go`
**Changes**: Replace the current expectation that `private_key_jwt` implies DPoP by default. The updated test should assert:

- default with no explicit sender constraint: `false`
- explicit `mtls`: `false`
- explicit `dpop`: `true`

### Success Criteria:

#### Automated Verification:
- [x] `go test ./rp/...`
- [x] `go test ./...`
- [x] `rp/dpop_usage_test.go` asserts `private_key_jwt` without explicit sender constraint does not enable DPoP.
- [x] `rp/userinfo_test.go` asserts UserInfo uses `Bearer` by default and `DPoP` only for explicit `dpop`.

#### Manual Verification:
- [x] Code inspection confirms no implicit DPoP path remains when `sender_constrain` is unset.
- [x] The default OIDC `private_key_jwt` code path is still easy to understand and follows the option model already exposed by `WithAuthMethod` and `WithSenderConstrain`.

---

## Phase 2: Example RP / Runtime Validation

### Overview

Confirm the example RP still maps runtime configuration into the library correctly after the semantic change.

### Changes Required:

#### 1. Runtime wiring audit
**File**: `cmd/example-rp/runtime_resolution.go`
**Changes**: Verify no code changes are required beyond tests and documentation, because the runtime already passes `authMethod`, `senderConstrain`, and `keyProvider` independently into `rp.New(...)`: `cmd/example-rp/runtime_resolution.go:317-336`.

If gaps are found during implementation, only add minimal assertions or tests rather than new runtime behavior.

#### 2. Example RP behavior coverage
**Files**: `cmd/example-rp/runtime_resolution_test.go`, `cmd/example-rp/main_test.go`
**Changes**: Add or adjust tests that exercise representative runtime combinations:

- `client_auth_type=private_key_jwt` with empty `sender_constrain` results in an RP that does not use DPoP.
- `client_auth_type=private_key_jwt` with `sender_constrain=dpop` still enables DPoP.
- `client_auth_type=tls_client_auth` or explicit `sender_constrain=mtls` behavior remains unchanged.

```go
resolved := resolvedRPRequest{
	authMethod:      rp.AuthMethodPrivateKeyJWT,
	hasAuthMethod:   true,
	keyProvider:     provider,
	senderConstrain: "",
}

client, err := buildRPFromResolvedRequest(req, resolved)
if diff := cmp.Diff(false, client.ShouldUseDPoP()); diff != "" { ... }
```

### Success Criteria:

#### Automated Verification:
- [x] `go test ./cmd/example-rp/...`
- [x] Example RP tests cover `private_key_jwt` with and without explicit sender constraint.
- [x] Existing mTLS- and DPoP-related example RP tests still pass without modification to runtime behavior.

#### Manual Verification:
- [x] Review of `buildRPFromResolvedRequest` confirms the example RP still exposes explicit sender-constrain behavior cleanly.
- [x] No conformance-only workaround was added to override library semantics only for OIDCC runs.

---

## Phase 3: Conformance Verification

### Overview

Verify the changed semantics solve the interrupted OIDCC modules without regressing private-key-jwt behavior in FAPI profiles that explicitly request sender constraining.

### Changes Required:

#### 1. Targeted OIDCC reruns
**Files**: no production code changes; use existing conformance harness commands and artifact review.
**Changes**: Re-run the affected OIDCC config variants from the ticket and inspect suite logs for UserInfo authorization shape.

Representative modules from the ticket:

- `oidcc-client-test-idtoken-sig-none`
- `oidcc-client-test-signing-key-rotation`
- `oidcc-client-test-signing-key-rotation-just-before-signing`

Representative variant axes from the ticket:

- `client_auth_type=private_key_jwt`
- `request_type=plain_http_request|request_object`
- `response_mode=default|form_post`

#### 2. FAPI regression guardrail reruns
**Files**: no production code changes; validate through existing test and conformance coverage.
**Changes**: Run the targeted private-key-jwt FAPI flows that explicitly use sender constraint values so the new default does not regress explicit DPoP or mTLS operation.

### Success Criteria:

#### Automated Verification:
- [x] `go test ./...`
- [ ] A targeted OIDCC conformance rerun for the affected modules no longer reports `OIDCCExtractBearerAccessTokenFromRequest: Couldn't find a bearer token in request`.
- [ ] Targeted FAPI private-key-jwt runs that explicitly use `sender_constrain=dpop` or `sender_constrain=mtls` still complete their protected-resource or sender-constrained flows.

#### Manual Verification:
- [ ] Suite logs for affected OIDCC runs show `/userinfo` requests carrying `Authorization: Bearer <token>` when no sender constraint is configured.
- [ ] Suite logs for explicit DPoP scenarios still show `Authorization: DPoP <token>` plus a `DPoP` proof header.
- [ ] Interrupted status is cleared for the representative modules called out in the ticket.

---

## Testing Strategy

### Unit Tests:
- Verify `shouldUseDPoP()` returns false when `sender_constrain` is unset, even with `private_key_jwt` and a key provider.
- Verify explicit `sender_constrain=dpop` still produces `Authorization: DPoP ...` plus proof headers.
- Verify explicit `sender_constrain=mtls` still suppresses DPoP.
- Verify UserInfo bearer header behavior for `private_key_jwt` without sender constraint.

### Integration Tests:
- Example RP runtime construction tests covering `private_key_jwt` plus empty, `dpop`, and `mtls` sender-constrain combinations.
- Existing RP/UserInfo integration-style tests for DPoP nonce retries should continue to pass for explicit DPoP.

### Manual Testing Steps:
1. Run the targeted OIDCC `private_key_jwt` modules from the ticket.
2. Inspect the suite log or RP request dump for the `/userinfo` request headers.
3. Confirm the authorization header is `Bearer` for runs without explicit sender constraint.
4. Re-run an explicit DPoP scenario and confirm the authorization header is `DPoP` and the `DPoP` proof header is present.
5. Re-run an mTLS scenario and confirm DPoP is absent while the mTLS alias is still used where applicable.

## Performance Considerations

This change should have no measurable performance impact. It removes accidental DPoP proof generation from non-DPoP OIDC config flows, which may slightly reduce CPU work and request complexity in those paths.

## Migration Notes

This is a behavior change to library defaults, not a data migration. Any caller currently relying on implicit DPoP through `private_key_jwt` without setting `sender_constrain=dpop` will need to set sender constraining explicitly. The example RP runtime model already supports that configuration shape.

## References

- Original ticket: `thoughts/tickets/bug_oidcc_config_private_key_jwt_missing_userinfo_bearer.md`
- Related plan: `thoughts/plans/oidcc-client-test-fixes.md`
- Root-cause callback path: `rp/callback.go:133-170`
- UserInfo authorization override: `rp/userinfo.go:16-29`
- UserInfo transport behavior: `rp/userinfo.go:73-95`
- Current DPoP default logic: `rp/dpop.go:252-257`
- Existing default-semantics test to update: `rp/dpop_usage_test.go:9-27`
- Explicit runtime wiring of auth method vs sender constraint: `cmd/example-rp/runtime_resolution.go:317-336`
