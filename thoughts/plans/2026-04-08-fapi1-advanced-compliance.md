# FAPI 1.0 Advanced Compliance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the FAPI2/OpenID-compliant relying party library to also pass the full FAPI 1.0 Advanced (Final) conformance suite (16 matrix variants) without regressing existing FAPI2 SP, FAPI2 MS, or OIDC Basic conformance.

**Architecture:** The codebase already has ~90% of what FAPI 1.0 Advanced requires. The conformance harness (matrix definitions, presets, negative-test-module mappings, plan config building) is fully wired. The RP core already implements JAR, PAR, JARM, hybrid flow (`code id_token`), `c_hash`/`s_hash` validation, encrypted ID tokens, and `private_key_jwt`/mTLS auth. The remaining work is: (1) a small validation gap in ID token `iat` age checking for token-response ID tokens, (2) ensuring the `code id_token` hybrid flow end-to-end works through the conformance suite, (3) running the suite and fixing failures, (4) adding the FAPI1 Advanced matrix to the `all-rp-full` preset, and (5) regression-testing FAPI2 + OIDC.

**Tech Stack:** Go 1.25+, `github.com/google/go-cmp/cmp` for test assertions, `github.com/go-jose/go-jose/v4` for JWT/JWE, Docker-based conformance suite.

---

## FAPI 1.0 Advanced vs FAPI 2.0 — Key Differences Affecting the RP

| Area | FAPI 2.0 SP/MS | FAPI 1.0 Advanced | RP Code Status |
|------|----------------|-------------------|----------------|
| PAR | Required | Optional (`by_value` or `pushed`) | Configurable via `WithRequirePAR` |
| JAR (signed request objects) | MS only | Required (all variants) | `requestMethodSignedNonRepudiation` |
| JARM | MS only | Optional (alt to `code id_token`) | `rp/jarm.go` |
| `response_type` | `code` | `code id_token` (non-JARM) or `code` (JARM) | `responseTypeForPlanVariant` |
| PKCE | Required S256 | Optional (always sent — harmless) | Always generated |
| Sender constraining | MTLS or DPoP | MTLS only | Matrix fixed to `mtls` |
| Token endpoint auth | `private_key_jwt` or MTLS | `private_key_jwt` or MTLS | Both supported |
| ID token signing algos | PS256, ES256, EdDSA | PS256, ES256 | Provider metadata validated |
| Front-channel ID token | No | Yes (`code id_token` hybrid flow) | `params.IDToken` handled |
| `c_hash` in ID token | N/A | Required | `validateHashClaim` |
| `s_hash` in ID token | N/A | Required (`code id_token` flow) | `validateHashClaim` |
| ID token `iat` age check (token response) | Not tested | Tested (`iat-is-week-in-past`) | **Only checked in authz response path** |
| `nbf` in request object | In MS | Required | Already included |

## What Already Works

The following are already implemented and tested:

- **Conformance harness** (`conformance/harness/`):
  - Matrix: `fapi1-adv-final-all16` (16 variants), `fapi1-adv-final-first4` (4 smoke variants)
  - Presets: `fapi1-adv-full`, `fapi1-adv-smoke`
  - Negative test module list: 17 FAPI1 Advanced modules mapped in `isNegativeTestModule`
  - Plan config: JWKS, encrypted ID token config, client certs — all shared with FAPI2 path
  - Runtime registration: `buildRPRuntimeRequestForAlias` correctly sets `response_type=code id_token` for FAPI1 Advanced non-JARM, `request_type=plain_http_request` for `by_value`, `request_type=pushed_authorization_request` for `pushed`
  - Trigger params: `isFAPI2Variant` returns true for FAPI1 variants, so `client_auth_type` etc. are included in trigger URL

- **RP core** (`rp/`):
  - `AuthorizationURL` handles both PAR and by-value signed request objects
  - `HandleCallback` validates front-channel ID tokens (`validateAuthorizationResponseIDToken`) with `c_hash`, `s_hash`, and `iat` age
  - `validateIDToken` handles encrypted ID tokens, algorithm validation, signature verification
  - `buildSignedRequestObject` includes `iss`, `aud`, `exp`, `nbf`, `jti`, `client_id`, PKCE challenge
  - `buildClientAssertion` for `private_key_jwt` token endpoint auth
  - `parseJARMResponse` for JARM variant

---

## Implementation Tasks

### Task 1: Add `iat` Age Validation to Token-Response ID Tokens

The authorization-response ID token path (`validateAuthorizationResponseIDToken`) already rejects tokens with `iat` older than `clockSkew`. The token-response ID token path (`validateIDTokenClaims`) checks `iat` is present and not in the future, but does **not** reject old `iat`. The conformance test `fapi1-advanced-final-client-test-iat-is-week-in-past` expects this rejection.

**Files:**
- Modify: `rp/idtoken.go:151-199` (`validateIDTokenClaims`)
- Test: `rp/idtoken_test.go`

**Step 1: Write the failing test**

Add a test in `rp/idtoken_test.go` that creates an ID token with `iat` set to 7 days ago, `exp` in the future, valid `iss`/`aud`/`nonce`. Call `validateIDTokenClaims` on an RP with `fapiProfile = fapiProfilePlainFAPI` and verify it returns `ErrIDTokenValidationFailed`.

```go
func TestValidateIDTokenClaims_RejectsOldIatForFAPIProfile(t *testing.T) {
	now := time.Now().UTC()
	claims := idTokenClaims{
		Issuer:  "https://example.com",
		Subject: "sub-1",
		Aud:     audienceClaim{"client-1"},
		Exp:     int64Ptr(now.Add(5 * time.Minute).Unix()),
		Iat:     int64Ptr(now.Add(-7 * 24 * time.Hour).Unix()),
		Nonce:   "nonce-1",
	}

	r := &RP{
		issuer:      "https://example.com",
		clientID:    "client-1",
		fapiProfile: fapiProfilePlainFAPI,
		now:         func() time.Time { return now },
		clockSkew:   5 * time.Minute,
	}

	err := r.validateIDTokenClaims(claims, "nonce-1")
	if err == nil {
		t.Fatal("validateIDTokenClaims() expected error for week-old iat with FAPI profile")
	}
	if !strings.Contains(err.Error(), "iat") {
		t.Fatalf("expected iat-related error, got: %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./rp -run TestValidateIDTokenClaims_RejectsOldIatForFAPIProfile -v`
Expected: FAIL (iat age not currently checked)

**Step 3: Implement the fix**

In `rp/idtoken.go`, add iat age validation in `validateIDTokenClaims`, after the existing `iat in future` check (around line 188):

```go
if r.fapiProfile.isFAPI() && iat.Before(now.Add(-r.clockSkew)) {
    return fmt.Errorf("%w: iat too old", ErrIDTokenValidationFailed)
}
```

This mirrors the existing check in `validateAuthorizationResponseIDToken` (`callback.go:199-202`) but applies it to the token-response ID token path as well. The check is gated on `fapiProfile.isFAPI()` so it only applies to FAPI profiles (FAPI1 and FAPI2), preserving OIDC Basic behavior.

**Step 4: Run test to verify it passes**

Run: `go test ./rp -run TestValidateIDTokenClaims_RejectsOldIatForFAPIProfile -v`
Expected: PASS

**Step 5: Add confirming test that OIDC accepts old iat**

```go
func TestValidateIDTokenClaims_AllowsOldIatForNonFAPI(t *testing.T) {
	now := time.Now().UTC()
	claims := idTokenClaims{
		Issuer:  "https://example.com",
		Subject: "sub-1",
		Aud:     audienceClaim{"client-1"},
		Exp:     int64Ptr(now.Add(5 * time.Minute).Unix()),
		Iat:     int64Ptr(now.Add(-7 * 24 * time.Hour).Unix()),
		Nonce:   "nonce-1",
	}

	r := &RP{
		issuer:      "https://example.com",
		clientID:    "client-1",
		fapiProfile: fapiProfileNone,
		now:         func() time.Time { return now },
		clockSkew:   5 * time.Minute,
	}

	err := r.validateIDTokenClaims(claims, "nonce-1")
	if err != nil {
		t.Fatalf("validateIDTokenClaims() unexpected error for non-FAPI: %v", err)
	}
}
```

Run: `go test ./rp -run TestValidateIDTokenClaims_AllowsOldIatForNonFAPI -v`
Expected: PASS

**Step 6: Run existing tests to check for regressions**

Run: `go test ./rp -v`
Expected: All existing tests pass (the new iat age check only affects FAPI profiles)

**Step 7: Commit**

```bash
git add rp/idtoken.go rp/idtoken_test.go
git commit -m "feat: add iat age validation for token-response ID tokens under FAPI profiles"
```

---

### Task 2: Verify `response_type=code id_token` End-to-End Flow

The hybrid flow (`code id_token`) is already implemented but needs explicit integration test coverage. This task adds tests that mirror the FAPI1 Advanced non-JARM `by_value` flow.

**Files:**
- Test: `rp/callback_test.go`

**Step 1: Write integration-style test for hybrid flow with by_value JAR**

Add a test that exercises the full FAPI1 Advanced `code id_token` + JAR + MTLS flow:

The test helper `callbackRequestWithIDToken` already exists at `callback_test.go:409`. Use it to construct callback requests with `id_token` in query parameters.

Test should cover:
1. Authorization URL contains `request=<signed_jwt>` (not `request_uri`) — by_value
2. Authorization URL contains `response_type=code+id_token`
3. Callback with `id_token` in query triggers `validateAuthorizationResponseIDToken`
4. Front-channel ID token `c_hash` and `s_hash` are validated
5. Token exchange happens after front-channel validation
6. Token-response ID token is also validated
7. Final result includes subject and access token

**Step 2: Write test for JAR + PAR (pushed variant) with code id_token**

Test should cover:
1. Authorization URL contains `client_id` + `request_uri` (no `request` parameter)
2. PAR request body contains `request=<signed_jwt>`
3. Callback validates front-channel ID token with `c_hash`/`s_hash`

**Step 3: Run tests**

Run: `go test ./rp -run TestHandleCallback_HybridFlow -v`
Expected: PASS

**Step 4: Commit**

```bash
git add rp/callback_test.go
git commit -m "test: add hybrid flow (code id_token) integration tests for FAPI1 Advanced"
```

---

### Task 3: Run FAPI1 Advanced Smoke Test (4 variants)

Run the conformance suite with the `fapi1-adv-smoke` preset and analyze results.

**Step 1: Ensure environment is set up**

```bash
bash conformance/scripts/setup.sh
```

**Step 2: Run smoke test**

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi1-adv-smoke
```

Expected: 4 plans x N modules each. Record any failures.

**Step 3: Analyze failures**

If tests fail:
1. Check `./artifacts/{runID}/report.json` for failure details
2. Check Docker logs: `docker logs conformance-rp-1`
3. Look at individual test module summaries in the report

**Step 4: Fix any failures**

Common failure patterns to look for:
- **`iat-is-week-in-past`**: Should be fixed by Task 1
- **`invalid-shash`/`invalid-chash`**: Hash validation in `validateAuthorizationResponseIDToken` — verify hash computation matches spec
- **`invalid-signature`**: Signature verification — check JWKS key matching
- **`invalid-null-alg`**: `alg=none` rejection — verify FAPI profile blocks it
- **`encrypted-idtoken-usingrsa15`**: RSA1.5 rejection — verify only RSA-OAEP accepted
- **`invalid-missing-shash`**: Missing `s_hash` should be rejected — verify `validateHashClaim` rejects empty claim

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix: address FAPI1 Advanced conformance failures from smoke test"
```

---

### Task 4: Run Full FAPI1 Advanced Suite (16 variants)

**Step 1: Run full matrix**

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi1-adv-full
```

Expected: 16 plans (2 auth types x 2 request methods x 2 client types x 2 response modes), all passing.

**Step 2: Fix any remaining failures**

Same analysis approach as Task 3 Step 3-4.

**Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix: address remaining FAPI1 Advanced conformance failures"
```

---

### Task 5: Add FAPI1 Advanced to `all-rp-full` Preset and Update Conformance Docs

**Files:**
- Modify: `conformance/harness/presets.go`
- Modify: `conformance/AGENTS.md`

**Step 1: Update presets**

In `conformance/harness/presets.go`, add FAPI1 Advanced matrices to the `all-rp-full` and `all-rp-smoke` presets:

```go
"all-rp-full": {
    Profile:  "all-rp",
    Matrices: []string{
        "fapi2-sp-final-plain-fapi-all16",
        "fapi2-ms-final-plain-fapi-all32",
        "fapi1-adv-final-all16",
    },
    Parallel:        true,
    MaxParallelRuns: 8,
},
"all-rp-smoke": {
    Profile:  "all-rp",
    Matrices: []string{
        "fapi2-sp-final-plain-fapi-first4",
        "fapi2-ms-final-plain-fapi-jar4",
        "fapi1-adv-final-first4",
    },
    Parallel:        true,
    MaxParallelRuns: 4,
},
```

**Step 2: Update conformance docs**

In `conformance/AGENTS.md`, update:
- Total job count for `all-rp-full`: 1 OIDC + 16 FAPI2-SP + 32 FAPI2-MS + 16 FAPI1-Adv = 65
- Total job count for `all-rp-smoke`: 1 OIDC + 4 FAPI2-SP + 4 FAPI2-MS + 4 FAPI1-Adv = 13

**Step 3: Run preset tests**

Run: `go test ./conformance/harness -run TestResolvePreset -v`
Expected: PASS

**Step 4: Commit**

```bash
git add conformance/harness/presets.go conformance/AGENTS.md
git commit -m "feat: add FAPI1 Advanced matrices to all-rp presets"
```

---

### Task 6: Regression Testing — Verify FAPI2 and OIDC Conformance

**Step 1: Run OIDC conformance**

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -profile=oidc-rp
```

Expected: All OIDC basic tests pass.

**Step 2: Run FAPI2 Security Profile**

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi2-sp-full
```

Expected: 16/16 plans pass.

**Step 3: Run FAPI2 Message Signing**

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=fapi2-ms-full
```

Expected: 32/32 plans pass.

**Step 4: Run unit tests**

```bash
gofumpt ./... && go vet ./... && go test ./...
```

Expected: All pass.

**Step 5: Commit any regression fixes**

```bash
git add -A
git commit -m "fix: address any FAPI2/OIDC regression from FAPI1 Advanced changes"
```

---

### Task 7: Final Verification — Full `all-rp-full` Suite

**Step 1: Run the complete combined suite**

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=all-rp-full
```

Expected: 65 plans (1 OIDC + 16 FAPI2-SP + 32 FAPI2-MS + 16 FAPI1-Adv), all passing.

**Step 2: Verify report**

Check `./artifacts/{runID}/report.json`:
- `"failed": false`
- All plans have `"failed": false`
- All tests have `"result": "PASSED"` or `"result": "SKIPPED"`

---

## Risk Areas and Potential Additional Work

The following areas may surface during conformance testing and could require additional code changes:

### 1. Fragment Response Handling for `code id_token`

For `response_type=code id_token` without explicit `response_mode=form_post`, the default response mode is `fragment`. The conformance harness's `mergeFragmentIntoQuery` (execute.go:452) simulates browser JavaScript that reads `window.location.hash` and converts it to query parameters. If the conformance suite instead uses `response_mode=form_post`, the RP already handles POST body extraction.

### 2. Algorithm Restrictions (PS256/ES256 Only)

FAPI1 Advanced requires PS256 or ES256 for ID token signing (not RS256, EdDSA). Currently, the RP validates signing algorithms against the provider's `id_token_signing_alg_values_supported` list. The conformance suite's provider metadata should advertise only PS256 and ES256 for FAPI1 Advanced.

**If tests fail with unexpected algorithm acceptance**: Add explicit FAPI1 Advanced algorithm allowlisting in `validateIDToken`:

```go
if r.fapiProfile == fapiProfileFAPI1 {
    alg := string(parsed.Headers[0].Algorithm)
    if alg != "PS256" && alg != "ES256" {
        return idTokenClaims{}, fmt.Errorf("%w: FAPI1 Advanced requires PS256 or ES256, got %s", ErrIDTokenValidationFailed, alg)
    }
}
```

This would require changing the matrix to use `"fapi1"` as the profile value (see Alternative below).

### 3. `aud` as Array vs String in Request Object

FAPI1 Advanced requires `aud` in the request object to be the OP's issuer URL. Currently `aud` is set as a string (`claims.Aud = r.issuer`). Some conformance tests may expect `aud` as an array `["issuer_url"]`.

**If tests fail**: Change `requestObjectClaims.Aud` from `string` to `[]string` and update `claimsToMap` serialization.

### 4. Profile-Specific FAPI1 Advanced Behavior (Alternative Approach)

The current matrix uses `"fapi_profile": "plain_fapi"` for all FAPI variants. An alternative approach is to use `"fapi1"` for FAPI1 Advanced variants, which would map to `fapiProfileFAPI1` and enable profile-specific code paths.

**To implement:**
1. In `buildFAPI1AdvancedMatrixVariants`, change `"fapi_profile": "plain_fapi"` to `"fapi_profile": "fapi1"`
2. Verify that `isFAPI2Profile` still returns true (it will, because `cfg.ClientAuthType` is `"private_key_jwt"` or `"mtls"`)
3. Add profile-specific checks where needed (e.g., algorithm restrictions)

**Risk**: The `"fapi_profile"` variant value is sent to the conformance suite when creating plans. Verify that `"fapi1"` is accepted by the suite. If not, keep `"plain_fapi"` and use plan name for profile detection.

---

## Summary of Code Changes by File

| File | Change | Task |
|------|--------|------|
| `rp/idtoken.go` | Add `iat` age check in `validateIDTokenClaims` for FAPI profiles | 1 |
| `rp/idtoken_test.go` | Add tests for iat age validation | 1 |
| `rp/callback_test.go` | Add hybrid flow integration tests | 2 |
| `conformance/harness/presets.go` | Add FAPI1 Advanced matrices to `all-rp-full`/`all-rp-smoke` | 5 |
| `conformance/AGENTS.md` | Update job counts and examples | 5 |
| *(various)* | Fixes from conformance test failures | 3-4 |
