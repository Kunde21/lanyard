## Validation Report: OIDCC Config `request_uri` Hosting Implementation Plan

### Implementation Status
⚠️ Phase 1: Request Object Store & Endpoint - Partially implemented
⚠️ Phase 2: RP Library Support for `request_uri` Mode - Implemented
⚠️ Phase 3: Wire Runtime Config for `request_uri` Mode - Partially implemented
⚠️ Phase 4: Suite Config & Conformance Verification - Implemented, but success criteria failed

### Automated Verification Results
✓ Build passes: `go build ./cmd/example-rp`
✓ Build passes: `go build ./rp`
✓ Tests pass: `go test ./cmd/example-rp/...`
✓ Tests pass: `go test ./rp/...`
✓ Full Go test suite passes: `go test ./...`
✗ OIDCC config conformance fails: `LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v -args -preset=oidcc-config-full`

Conformance run details:
- Artifact: `artifacts/20260410-084141/report.json`
- Result: failed
- Summary: `182/252 tests passed, 70 failed`
- All `request_uri` variants for these modules remained `INTERRUPTED`/`FAILED`:
  - `oidcc-client-test-idtoken-sig-none`
  - `oidcc-client-test-signing-key-rotation`
  - `oidcc-client-test-signing-key-rotation-just-before-signing`

### Code Review Findings

#### Matches Plan:
- Added an in-memory request object store in `cmd/example-rp/request_object_store.go`.
- Added `GET /request/{id}` handling in `cmd/example-rp/handle_request_object.go`.
- Added `rp.WithRequestURIMode` and `RequestURIHandler` in `rp/options.go`.
- Updated `AuthorizationURL()` to emit `request_uri` when a handler is configured in `rp/authrequest.go`.
- Added `shouldUseRequestURI()` and request URI runtime selection in `cmd/example-rp/runtime_resolution.go`.
- Added suite config `request_uris` registration in `conformance/harness/execute.go`.

#### Deviations from Plan:
- Phase 1 / Phase 3: The plan required a shared store that backs both request object creation and the `/request/{id}` endpoint. Actual implementation creates separate stores:
  - `cmd/example-rp/main.go:27-38` registers `/request/` with a store created in `main()`.
  - `cmd/example-rp/runtime_resolution.go:371-376` creates a different store inside `buildRPFromResolvedRequest()` and stores request objects there.
  - Assessment: This is a functional deviation, not an acceptable implementation difference. The endpoint cannot serve the JWTs being stored for authorization redirects.
  - Recommendation: Use one shared store instance for both route handling and `WithRequestURIMode`.

#### Potential Issues:
- Critical: `request_uri` mode is still broken end-to-end because stored JWTs are unreachable from `/request/{id}`. This explains why the suite sees `request_uri` on the authorization request but the affected modules still end in `INTERRUPTED`.
- Coverage gap: There is no integration test proving that a request object stored via runtime resolution can be fetched back through `/request/{id}`. Existing tests validate the store, handler, and redirect URL separately, but not the actual wired flow.
- Minor robustness issue: `cmd/example-rp/request_object_store.go:30` ignores the error from `rand.Read`, which is avoidable in security-sensitive ID generation.

### Manual Testing Required
1. Shared-store flow:
   - [ ] Start the RP and trigger an OIDCC `request_uri` login.
   - [ ] Capture the `request_uri` from the authorization redirect.
   - [ ] `GET` that exact URL and confirm it returns the signed JWT with `Content-Type: application/jwt`.

2. Conformance behavior:
   - [ ] Re-run `oidcc-config-full` after fixing the shared-store bug.
   - [ ] Confirm the three affected modules progress past `INTERRUPTED` for all `request_uri` variants.
   - [ ] Confirm `plain_http_request` and `request_object` variants still pass.

3. Regression checks:
   - [ ] Run a FAPI preset such as `fapi2-sp-full` or `fapi2-ms-full` after the fix to confirm no regression.

### Recommendations
- Fix the shared-store wiring first. This is the root cause of the remaining conformance failures.
- Add an integration test covering runtime resolution -> `AuthorizationURL()` -> `/request/{id}` retrieval using the same store instance.
- Handle `rand.Read` errors in request object ID generation.
