# OIDCC Client Test Plan Failure Remediation Checklist

## Scope

Address failures from the full forced-variant run:

- Run report: `artifacts/20260224-042104/report.json`
- Expanded logs: `artifacts/20260224-042104/expanded/`
- Plan: `oidcc-client-test-plan` with `client_auth_type=client_secret_post`

Failed modules (11):

1. `oidcc-client-test-client-secret-basic`
2. `oidcc-client-test-scope-userinfo-claims`
3. `oidcc-client-test-userinfo-bearer-body`
4. `oidcc-client-test-invalid-sig-hs256`
5. `oidcc-client-test-distributed-claims`
6. `oidcc-client-test-discovery-openid-config`
7. `oidcc-client-test-discovery-jwks-uri-keys`
8. `oidcc-client-test-discovery-issuer-mismatch`
9. `oidcc-client-test-signing-key-rotation`
10. `oidcc-client-test-discovery-webfinger-acct`
11. `oidcc-client-test-discovery-webfinger-url`

## Root-Cause Buckets

- Harness orchestration gaps (module-specific trigger behavior, WAITING retries, test cleanup on timeout).
- Conformance static secret too short for HS256 suite signing.
- RP missing/insufficient capabilities for some modules (userinfo bearer body mode, distributed claims, webfinger).
- Discovery/auth-method freshness issues in long-lived RP process under mutable suite metadata.

## Delivery Strategy

Implement in small PR-sized chunks, each with explicit acceptance criteria and retest commands.

---

## Chunk 1: Harness WAITING + Timeout Cleanup Hardening

### Goal

Stop alias-conflict cascades and support multi-step modules that need more than one front-channel trigger.

### Files

- `conformance/harness/execute.go`
- `conformance/harness/*_test.go` (new/updated tests)

### Checklist

- [ ] Allow multiple front-channel trigger attempts while test remains in `WAITING`.
- [ ] Add bounded retry policy (count + interval).
- [ ] On WAITING timeout/failure, cancel/terminate test instance before starting next module.
- [ ] Keep polling until terminal state after cancellation.
- [ ] Improve log output to include suite alias and module/test IDs clearly.

### Acceptance Criteria

- [ ] `go test ./conformance/harness/...` passes.
- [ ] No "Stopping test due to alias conflict" in reruns of long-running modules.

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^(oidcc-client-test-distributed-claims|oidcc-client-test-signing-key-rotation)$'
```

---

## Chunk 2: Harness Module-Aware Front-Channel Triggering

### Goal

Avoid using `/login` universally for discovery-focused modules that should run discovery/webfinger/jwks flows without full auth/token progression.

### Files

- `conformance/harness/execute.go`
- `cmd/example-rp/main.go`
- RP HTTP handler tests for new conformance trigger endpoints

### Checklist

- [ ] Add module-to-trigger mapping in harness (default remains `/login`).
- [ ] Add RP conformance-only endpoints for:
  - [ ] discovery-only
  - [ ] discovery + jwks fetch
  - [ ] webfinger acct resource
  - [ ] webfinger url resource
- [ ] Route modules:
  - `oidcc-client-test-discovery-openid-config`
  - `oidcc-client-test-discovery-jwks-uri-keys`
  - `oidcc-client-test-discovery-issuer-mismatch`
  - `oidcc-client-test-discovery-webfinger-acct`
  - `oidcc-client-test-discovery-webfinger-url`

### Acceptance Criteria

- [ ] Discovery modules no longer fail with `Illegal test state change: FINISHED -> RUNNING`.
- [ ] `go test ./conformance/harness/... && go test ./cmd/example-rp/...` passes.

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^oidcc-client-test-discovery-(openid-config|jwks-uri-keys|issuer-mismatch|webfinger-acct|webfinger-url)$'
```

---

## Chunk 3: Conformance Static Secret Length Fix (HS256)

### Goal

Unblock `oidcc-client-test-invalid-sig-hs256` by using a >=256-bit client secret in suite static config.

### Files

- `conformance/harness/execute.go` (plan config defaults)
- `cmd/example-rp/main.go` (default secret/env docs)
- `conformance/docker-compose.yml` (if needed for explicit RP env)

### Checklist

- [ ] Set static `client_secret` and `client2.client_secret` to at least 32 bytes.
- [ ] Ensure RP uses matching secret defaults/env values.
- [ ] Verify no mismatch between harness-provisioned static client config and RP runtime config.

### Acceptance Criteria

- [ ] HS256 module reaches RP validation path (no suite-side key length exception).

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^oidcc-client-test-invalid-sig-hs256$'
```

---

## Chunk 4: Discovery/Auth-Method Freshness for Mutable Suite Metadata

### Goal

Prevent auth method drift across modules (`client_secret_basic` vs `client_secret_post`) in a long-lived RP process.

### Files

- `oidc/discovery.go`
- `oidc/options.go`
- `cmd/example-rp/main.go`
- `rp/callback.go` (only if needed for explicit refresh semantics)
- new/updated tests in `oidc/*_test.go` and/or `rp/*_test.go`

### Checklist

- [ ] Add conformance mode to force fresh/blocking discovery reads (or equivalent no-stale behavior).
- [ ] Wire conformance RP startup to use this mode.
- [ ] Keep production defaults unchanged.

### Acceptance Criteria

- [ ] `oidcc-client-test-client-secret-basic` uses Basic in token request.
- [ ] `oidcc-client-test-scope-userinfo-claims` uses Post in token request.

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^(oidcc-client-test-client-secret-basic|oidcc-client-test-scope-userinfo-claims)$' \
  -force-variant='client_auth_type=client_secret_post' \
  -force-variant='response_type=code' \
  -force-variant='response_mode=default'
```

---

## Chunk 5: UserInfo Bearer Body Mode + Module Control

### Goal

Support modules that require `access_token` in UserInfo body parameters rather than Authorization header.

### Files

- `rp/userinfo.go`
- `rp/options.go` (or new userinfo transport option)
- `rp/userinfo_test.go`
- `cmd/example-rp/main.go`
- `conformance/harness/execute.go` (set mode for `userinfo-bearer-body` module)

### Checklist

- [ ] Add userinfo token transport mode: header (default) vs body.
- [ ] Implement body mode request shape (`POST` form with `access_token`).
- [ ] Keep header mode behavior unchanged.
- [ ] Add module-specific mode switching during harness execution.

### Acceptance Criteria

- [ ] `oidcc-client-test-userinfo-bearer-body` passes.
- [ ] `oidcc-client-test-userinfo-bearer-header` still passes.

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^oidcc-client-test-userinfo-bearer-(header|body)$' \
  -force-variant='client_auth_type=client_secret_post' \
  -force-variant='response_type=code' \
  -force-variant='response_mode=default'
```

---

## Chunk 6: Distributed Claims Resolution Support

### Goal

Implement `_claim_names`/`_claim_sources` handling and claims endpoint fetches required by distributed-claims module.

### Files

- `rp/userinfo.go`
- `rp/userinfo_test.go`
- potential helper file: `rp/claims.go`

### Checklist

- [ ] Detect distributed claims in userinfo response.
- [ ] Fetch claims from source `endpoint` with source access token.
- [ ] Support signed JWT claims response parsing where required.
- [ ] Merge distributed claims into final claims set safely.
- [ ] Preserve strict `sub` validation guarantees.

### Acceptance Criteria

- [ ] Module log shows RP calls suite claims endpoint.
- [ ] `oidcc-client-test-distributed-claims` passes.

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^oidcc-client-test-distributed-claims$' \
  -force-variant='client_auth_type=client_secret_post' \
  -force-variant='response_type=code' \
  -force-variant='response_mode=default'
```

---

## Chunk 7: WebFinger Discovery Support

### Goal

Support WebFinger resource discovery paths used by acct/url modules.

### Files

- `oidc/` (new webfinger fetch + parsing implementation)
- `rp/` (entrypoint/use of webfinger result)
- `cmd/example-rp/main.go` (conformance trigger resources)
- tests under `oidc/*_test.go` and `rp/*_test.go`

### Checklist

- [ ] Implement WebFinger request/response handling.
- [ ] Support acct-form resource and url-form resource.
- [ ] Resolve issuer from WebFinger before OIDC provider discovery.
- [ ] Add deterministic tests for both syntaxes and error cases.

### Acceptance Criteria

- [ ] `oidcc-client-test-discovery-webfinger-acct` passes.
- [ ] `oidcc-client-test-discovery-webfinger-url` passes.

### Retest

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -module-regex='^oidcc-client-test-discovery-webfinger-(acct|url)$'
```

---

## Chunk 8: Final Full-Plan Validation

### Goal

Confirm all modules pass together in one run and capture evidence.

### Checklist

- [ ] Run full plan with forced post variant across all modules.
- [ ] Verify `failed=false` in report.
- [ ] Archive report and artifact zip path for ticket evidence.

### Command

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp \
  -include-plan-regex='^oidcc-client-test-plan$' \
  -force-variant='client_auth_type=client_secret_post' \
  -force-variant='response_type=code' \
  -force-variant='response_mode=default'
```

### Acceptance Criteria

- [ ] `artifacts/<run-id>/report.json` shows all tests passed (or expected status set for profile semantics).

---

## Execution Notes

- Keep each chunk as a focused commit/PR.
- Prefer red/green TDD for RP and harness logic changes.
- Re-run `go test ./...` after each chunk touching shared logic.
- If any module still flakes, store failing artifact IDs and add a small deterministic reproducer before broad reruns.
