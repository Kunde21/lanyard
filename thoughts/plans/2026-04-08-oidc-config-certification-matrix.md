# OIDC Core Configuration Certification Profile RP Test Matrix

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add test matrix expansion for `oidcc-client-config-certification-test-plan` (42 variants: 7 client auth types x 3 request types x 1 client registration (static only) x 2 response modes).

**Architecture:** Follow the existing matrix pattern (builder function + switch cases in `expandMatrixVariants` + preset registration). The OIDC config plan differs from FAPI plans by having 4 OIDC-native variant dimensions and no FAPI-specific keys. The `RPProfileConfig` struct fields (FAPI-related) will remain empty for OIDC variants. Plan config generation uses the existing `usesStaticClientRegistration` path (no FAPI branch needed since all variants use `static_client`).

**Tech Stack:** Go 1.25+, `github.com/google/go-cmp/cmp` for test assertions, existing conformance harness infrastructure.

---

## Context

### Plan Variants (from suite API)

The conformance suite at `GET /api/plan/available` returns for `oidcc-client-config-certification-test-plan`:

| Variant Key | Values |
|---|---|
| `client_auth_type` | `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` |
| `request_type` | `plain_http_request`, `request_object`, `request_uri` |
| `client_registration` | `static_client`, ~~`dynamic_client`~~ (excluded from matrix) |
| `response_mode` | `default`, `form_post` |

**Matrix cross-product:** 7 x 3 x 1 x 2 = **42 variants**.

### Test Modules (6 total, all discovery/config tests)

```
oidcc-client-test-discovery-openid-config
oidcc-client-test-discovery-jwks-uri-keys
oidcc-client-test-discovery-issuer-mismatch
oidcc-client-test-idtoken-sig-none
oidcc-client-test-signing-key-rotation-just-before-signing
oidcc-client-test-signing-key-rotation
```

All have `response_type: code` module variant. Trigger endpoints are already mapped in `execute.go:539-546`.

### Key Design Decisions

1. **`client_registration` is always `static_client`** — no dynamic client variants. This avoids invalid auth-type combinations and simplifies plan config (always emits static client config).
2. **`RPProfileConfig` FAPI fields are empty** — the struct is reused but all FAPI-specific fields (`SenderConstrain`, `FAPIClientType`, etc.) will be zero values. The `isFAPI2PlanVariant` check returns `false`, so the code takes the OIDC code path throughout.
3. **No changes needed to trigger endpoints** — all 6 config plan modules are already mapped in `moduleTriggerEndpoint`.
4. **`buildPlanConfig` works as-is** — `usesStaticClientRegistration` returns `true` for all matrix variants, so the config builder emits client config. The `isFAPI2PlanVariant` guard is `false`, so no FAPI-specific JWKS/encryption config is added. For `private_key_jwt` and `self_signed_tls_client_auth` auth types, the RP runtime config needs to pass the auth type through (already handled by `buildRPRuntimeRequest` reading `planVariant["client_auth_type"]`).

---

## Task 1: Register plan in OIDC explicit plans

**Files:**
- Modify: `conformance/harness/profiles.go:10-14`

**Step 1: Add the plan name to `oidcExplicitPlans`**

In `conformance/harness/profiles.go`, add `oidcc-client-config-certification-test-plan` to the map:

```go
var oidcExplicitPlans = map[string]struct{}{
	"oidcc-client-basic-certification-test-plan":          {},
	"oidcc-client-formpost-basic-certification-test-plan": {},
	"oidcc-client-config-certification-test-plan":         {},
}
```

**Step 2: Verify existing tests pass**

Run: `go test ./conformance/harness -run TestSelectPlans -v`
Expected: PASS

**Step 3: Commit**

```
feat(conformance): register oidcc-client-config-certification-test-plan in OIDC profile
```

---

## Task 2: Add `chooseVariantValue` entries for new variant keys

**Files:**
- Modify: `conformance/harness/execute.go:712-771`

**Step 1: Write the failing test**

Add to `conformance/harness/matrix_test.go` (or a new test in `execute_test.go` if variant selection tests live there — check `execute_test.go` first):

```go
func TestChooseVariantValue_RequestType(t *testing.T) {
	got := chooseVariantValue("request_type", []string{"request_object", "plain_http_request", "request_uri"})
	if got != "plain_http_request" {
		t.Fatalf("chooseVariantValue(request_type) = %q, want plain_http_request", got)
	}
}

func TestChooseVariantValue_ResponseMode(t *testing.T) {
	got := chooseVariantValue("response_mode", []string{"form_post", "default"})
	if got != "default" {
		t.Fatalf("chooseVariantValue(response_mode) = %q, want default", got)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./conformance/harness -run "TestChooseVariantValue_RequestType|TestChooseVariantValue_ResponseMode" -v`
Expected: FAIL (returns first sorted value, not the preferred one)

**Step 3: Add variant defaults to `chooseVariantValue`**

In `conformance/harness/execute.go`, add two new blocks after the existing `fapi_response_mode` block (around line 769), before `return values[0]`:

```go
	if lowerKey == "request_type" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "plain_http_request") {
				return value
			}
		}
	}

	if lowerKey == "response_mode" {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "default") {
				return value
			}
		}
	}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./conformance/harness -run "TestChooseVariantValue_RequestType|TestChooseVariantValue_ResponseMode" -v`
Expected: PASS

**Step 5: Commit**

```
feat(conformance): add request_type and response_mode defaults to chooseVariantValue
```

---

## Task 3: Build the OIDC config matrix variant builder

**Files:**
- Modify: `conformance/harness/matrix.go` (add builder function)
- Modify: `conformance/harness/matrix.go:27-71` (add switch cases)

**Step 1: Write the failing test for the smoke matrix (2 variants)**

Add to `conformance/harness/matrix_test.go`:

```go
func TestOIDCConfigMatrix_First2(t *testing.T) {
	variants, err := expandMatrixVariants("oidcc-config-cert-first2", "oidcc-client-config-certification-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 2 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 2", len(variants))
	}

	want := []map[string]string{
		{
			"client_auth_type":    "client_secret_basic",
			"request_type":        "plain_http_request",
			"client_registration": "static_client",
			"response_mode":       "default",
		},
		{
			"client_auth_type":    "client_secret_basic",
			"request_type":        "plain_http_request",
			"client_registration": "static_client",
			"response_mode":       "form_post",
		},
	}

	got := make([]map[string]string, 0, len(variants))
	for _, v := range variants {
		got = append(got, v.Variant)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("oidc config first2 mismatch (-want +got):\n%s", diff)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./conformance/harness -run TestOIDCConfigMatrix_First2 -v`
Expected: FAIL with "unknown matrix" error

**Step 3: Implement `buildOIDCConfigMatrixVariants` and register in `expandMatrixVariants`**

In `conformance/harness/matrix.go`, add the builder function after the existing builders:

```go
func buildOIDCConfigMatrixVariants(includeAll bool) []matrixVariant {
	authTypes := []string{"client_secret_basic"}
	requestTypes := []string{"plain_http_request"}
	clientRegistrations := []string{"static_client"}
	responseModes := []string{"default"}

	if includeAll {
		authTypes = []string{
			"client_secret_basic",
			"client_secret_post",
			"client_secret_jwt",
			"private_key_jwt",
			"tls_client_auth",
			"self_signed_tls_client_auth",
			"none",
		}
		requestTypes = []string{"plain_http_request", "request_object", "request_uri"}
		clientRegistrations = []string{"static_client"}
		responseModes = []string{"default", "form_post"}
	}

	total := len(authTypes) * len(requestTypes) * len(clientRegistrations) * len(responseModes)
	variants := make([]matrixVariant, 0, total)
	index := 1
	for _, authType := range authTypes {
		for _, reqType := range requestTypes {
			for _, clientReg := range clientRegistrations {
				for _, respMode := range responseModes {
					variant := map[string]string{
						"client_auth_type":    authType,
						"request_type":        reqType,
						"client_registration": clientReg,
						"response_mode":       respMode,
					}
					variants = append(variants, matrixVariant{
						Name:     fmt.Sprintf("oidc-config-%02d", index),
						PlanName: "oidcc-client-config-certification-test-plan",
						Variant:  variant,
						RPProfile: RPProfileConfig{
							ClientAuthType: authType,
						},
					})
					index++
				}
			}
		}
	}

	return variants
}
```

Then add two new cases to the `switch` in `expandMatrixVariants` (before `default:`):

```go
	case "oidcc-config-cert-first2":
		if planName != "oidcc-client-config-certification-test-plan" {
			return nil, nil
		}
		return buildOIDCConfigMatrixVariants(false), nil
	case "oidcc-config-cert-all42":
		if planName != "oidcc-client-config-certification-test-plan" {
			return nil, nil
		}
		return buildOIDCConfigMatrixVariants(true), nil
```

**Step 4: Run the smoke test to verify it passes**

Run: `go test ./conformance/harness -run TestOIDCConfigMatrix_First2 -v`
Expected: PASS

**Step 5: Commit**

```
feat(conformance): add OIDC config certification matrix builder with smoke variant
```

---

## Task 4: Write the full 42-variant test and plan-isolation tests

**Files:**
- Modify: `conformance/harness/matrix_test.go`

**Step 1: Write the full matrix test**

Add to `conformance/harness/matrix_test.go`:

```go
func TestOIDCConfigMatrix_All42(t *testing.T) {
	variants, err := expandMatrixVariants("oidcc-config-cert-all42", "oidcc-client-config-certification-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 42 {
		t.Fatalf("expandMatrixVariants() returned %d variants, want 42", len(variants))
	}

	authCounts := map[string]int{}
	reqTypeCounts := map[string]int{}
	clientRegCounts := map[string]int{}
	respModeCounts := map[string]int{}
	seen := map[string]bool{}

	for _, v := range variants {
		vv := v.Variant
		authCounts[vv["client_auth_type"]]++
		reqTypeCounts[vv["request_type"]]++
		clientRegCounts[vv["client_registration"]]++
		respModeCounts[vv["response_mode"]]++

		if vv["client_registration"] != "static_client" {
			t.Fatalf("client_registration = %q, want static_client", vv["client_registration"])
		}

		key := strings.Join([]string{
			vv["client_auth_type"],
			vv["request_type"],
			vv["client_registration"],
			vv["response_mode"],
		}, "|")
		seen[key] = true
	}

	wantAuthCounts := map[string]int{
		"client_secret_basic":      6,
		"client_secret_post":      6,
		"client_secret_jwt":       6,
		"private_key_jwt":         6,
		"tls_client_auth":         6,
		"self_signed_tls_client_auth": 6,
		"none":                    6,
	}
	if diff := cmp.Diff(wantAuthCounts, authCounts); diff != "" {
		t.Fatalf("client_auth_type distribution mismatch (-want +got):\n%s", diff)
	}

	wantReqCounts := map[string]int{
		"plain_http_request": 14,
		"request_object":    14,
		"request_uri":       14,
	}
	if diff := cmp.Diff(wantReqCounts, reqTypeCounts); diff != "" {
		t.Fatalf("request_type distribution mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(map[string]int{"static_client": 42}, clientRegCounts); diff != "" {
		t.Fatalf("client_registration distribution mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(map[string]int{"default": 21, "form_post": 21}, respModeCounts); diff != "" {
		t.Fatalf("response_mode distribution mismatch (-want +got):\n%s", diff)
	}

	if len(seen) != 42 {
		t.Fatalf("unique 4D combinations = %d, want 42", len(seen))
	}
}
```

**Step 2: Write the plan-isolation test**

```go
func TestOIDCConfigMatrix_IgnoresOtherPlans(t *testing.T) {
	variants, err := expandMatrixVariants("oidcc-config-cert-all42", "fapi2-security-profile-final-client-test-plan")
	if err != nil {
		t.Fatalf("expandMatrixVariants() failed: %v", err)
	}
	if len(variants) != 0 {
		t.Fatalf("expected 0 variants for mismatched plan, got %d", len(variants))
	}
}

func TestOtherMatrices_IgnoreOIDCConfigPlan(t *testing.T) {
	testCases := []string{
		"fapi2-sp-final-plain-fapi-first4",
		"fapi2-ms-final-plain-fapi-jar4",
		"fapi1-adv-final-first4",
	}
	for _, matrixName := range testCases {
		variants, err := expandMatrixVariants(matrixName, "oidcc-client-config-certification-test-plan")
		if err != nil {
			t.Fatalf("expandMatrixVariants(%q) failed: %v", matrixName, err)
		}
		if len(variants) != 0 {
			t.Fatalf("expandMatrixVariants(%q) returned %d variants, want 0", matrixName, len(variants))
		}
	}
}
```

**Step 3: Run all new tests**

Run: `go test ./conformance/harness -run "TestOIDCConfig" -v`
Expected: All PASS

**Step 4: Commit**

```
test(conformance): add full 42-variant and plan-isolation tests for OIDC config matrix
```

---

## Task 5: Add dedicated OIDC config presets

**Files:**
- Modify: `conformance/harness/presets.go:14-64`

**Step 1: Write failing test for new presets**

Add to `conformance/harness/presets_test.go` (read the file first to match existing test style):

```go
func TestResolvePreset_OIDCConfigFull(t *testing.T) {
	cfg, err := resolvePreset("oidcc-config-full")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "oidc-rp" {
		t.Fatalf("Profile = %q, want oidc-rp", cfg.Profile)
	}
	if diff := cmp.Diff([]string{"oidcc-config-cert-all42"}, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if !cfg.Parallel {
		t.Fatal("Parallel = false, want true")
	}
}

func TestResolvePreset_OIDCConfigSmoke(t *testing.T) {
	cfg, err := resolvePreset("oidcc-config-smoke")
	if err != nil {
		t.Fatalf("resolvePreset() failed: %v", err)
	}
	if cfg.Profile != "oidc-rp" {
		t.Fatalf("Profile = %q, want oidc-rp", cfg.Profile)
	}
	if diff := cmp.Diff([]string{"oidcc-config-cert-first2"}, cfg.Matrices); diff != "" {
		t.Fatalf("Matrices mismatch (-want +got):\n%s", diff)
	}
	if !cfg.Parallel {
		t.Fatal("Parallel = false, want true")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./conformance/harness -run "TestResolvePreset_OIDCConfig" -v`
Expected: FAIL with "unknown preset"

**Step 3: Add presets to `builtInPresets` map**

In `conformance/harness/presets.go`, add two new entries to the `builtInPresets` map:

```go
	"oidcc-config-full": {
		Profile:          "oidc-rp",
		Matrices:         []string{"oidcc-config-cert-all42"},
		IncludePlanRegex: "oidcc-client-config-certification-test-plan",
		Parallel:         true,
		MaxParallelRuns:  8,
	},
	"oidcc-config-smoke": {
		Profile:          "oidc-rp",
		Matrices:         []string{"oidcc-config-cert-first2"},
		IncludePlanRegex: "oidcc-client-config-certification-test-plan",
		Parallel:         true,
		MaxParallelRuns:  2,
	},
```

Also update the `resolvePreset` error message to include the new preset names.

**Step 4: Run tests to verify they pass**

Run: `go test ./conformance/harness -run "TestResolvePreset_OIDCConfig" -v`
Expected: PASS

**Step 5: Commit**

```
feat(conformance): add oidcc-config-full and oidcc-config-smoke presets
```

---

## Task 6: Update existing presets to include OIDC config matrix

**Files:**
- Modify: `conformance/harness/presets.go`

**Step 1: Update `all-rp-full` preset**

Add `"oidcc-config-cert-all42"` to the `all-rp-full` preset's `Matrices` list. Total jobs: 1 (basic) + 42 (config) + 16 (SP) + 32 (MS) + 12 (FAPI1-Adv) = **103 jobs**.

```go
	"all-rp-full": {
		Profile: "all-rp",
		Matrices: []string{
			"oidcc-config-cert-all42",
			"fapi2-sp-final-plain-fapi-all16",
			"fapi2-ms-final-plain-fapi-all32",
			"fapi1-adv-final-all12",
		},
		Parallel:         true,
		MaxParallelRuns:  12,
		ExcludePlanRegex: "ciba|brazil|id1-|id2-|client-credentials",
	},
```

**Step 2: Update `all-rp-smoke` preset**

Add `"oidcc-config-cert-first2"` to the `all-rp-smoke` preset. Total jobs: 1 (basic) + 2 (config) + 4 (SP) + 4 (MS) + 4 (FAPI1-Adv) = **15 jobs**.

```go
	"all-rp-smoke": {
		Profile: "all-rp",
		Matrices: []string{
			"oidcc-config-cert-first2",
			"fapi2-sp-final-plain-fapi-first4",
			"fapi2-ms-final-plain-fapi-jar4",
			"fapi1-adv-final-first4",
		},
		Parallel:        true,
		MaxParallelRuns: 4,
	},
```

**Step 3: Update any existing preset tests that verify specific matrix counts**

Search `presets_test.go` for tests that assert on matrix list contents and update them.

**Step 4: Run all preset tests**

Run: `go test ./conformance/harness -run TestResolvePreset -v`
Expected: All PASS

**Step 5: Commit**

```
feat(conformance): add OIDC config matrix to all-rp-full and all-rp-smoke presets
```

---

## Task 7: Verify `buildPlanConfig` handles OIDC config plan auth types correctly

**Files:**
- Read: `conformance/harness/execute.go:778-845`
- Possibly modify: `conformance/harness/execute.go`

**Step 1: Analyze the code path for each auth type**

For `oidcc-client-config-certification-test-plan` with `static_client`:

1. `usesStaticClientRegistration(planVariant)` → `true` (all variants have `client_registration=static_client`)
2. `isFAPI2PlanVariant(planVariant)` → `false` (no FAPI keys in variant)
3. Guard at line 779: `!true && !false` → `false`, so config is built ✓
4. `isFAPI2` is `false`, so no FAPI JWKS/encryption config is added
5. Client config with `client_id`, `client_secret`, `redirect_uri`, `scope`, `request_type` is emitted ✓

**Potential issue:** For `client_auth_type=private_key_jwt`, the plan config should include `client.jwks`. Currently this is only added when `isFAPI2` is true. Check whether the OIDC config plan with `private_key_jwt` actually needs JWKS in the config, or if the conformance suite provides it.

**Action:** Run a manual test against the suite with `client_auth_type=private_key_jwt`:

```bash
curl -sk 'https://suite.localhost/api/plan?planName=oidcc-client-config-certification-test-plan' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-raw '{"client":{"client_id":"test","redirect_uri":"https://rp.localhost/callback","scope":"openid","request_type":"plain_http_request"}}' \
  -G --data-urlencode 'variant={"client_auth_type":"private_key_jwt","request_type":"plain_http_request","client_registration":"static_client","response_mode":"default"}'
```

If the suite returns 500/requires `jwks`, then extend `buildPlanConfig` to handle OIDC auth types that need JWKS.

**Step 2: If JWKS is needed, add OIDC-aware JWKS config**

Add a check after the FAPI block in `buildPlanConfig`:

```go
	if !isFAPI2 {
		authType := strings.ToLower(strings.TrimSpace(planVariant["client_auth_type"]))
		if authType == "private_key_jwt" || authType == "self_signed_tls_client_auth" {
			clientJWKS := loadPublicJWKS("client.jwks.json")
			cfg["client"].(map[string]any)["jwks"] = clientJWKS
			cfg["client2"].(map[string]any)["jwks"] = clientJWKS
		}
	}
```

**Step 3: Write test for plan config with private_key_jwt**

```go
func TestBuildPlanConfig_OIDCConfigPrivateKeyJWT(t *testing.T) {
	cfg := buildPlanConfig(map[string]string{
		"client_auth_type":    "private_key_jwt",
		"request_type":        "plain_http_request",
		"client_registration": "static_client",
		"response_mode":       "default",
	}, "alias-test", 5)

	client, ok := cfg["client"].(map[string]any)
	if !ok {
		t.Fatal("client config missing")
	}
	if _, hasJWKS := client["jwks"]; !hasJWKS {
		t.Fatal("client.jwks missing for private_key_jwt auth type")
	}
}
```

**Step 4: Run all execute tests**

Run: `go test ./conformance/harness -run "TestBuildPlanConfig" -v`
Expected: PASS

**Step 5: Commit** (only if changes were needed)

```
feat(conformance): add JWKS config for OIDC config plan with private_key_jwt auth
```

---

## Task 8: Verify `buildRPRuntimeRequest` passes auth type through

**Files:**
- Read: `conformance/harness/rpruntime.go:162-198`

**Step 1: Verify the code path**

`buildRPRuntimeRequest` at line 186 sets `ClientAuthType: planVariant["client_auth_type"]`. This is already passed through from the variant map. The RP runtime receives the auth type and can configure itself accordingly.

No changes expected. Verify by checking if `rpRuntimeRequest.ClientAuthType` is used by the example RP in `cmd/example-rp/main.go`.

**Step 2: No changes needed — move on**

---

## Task 9: Run full test suite and lint

**Step 1: Run all harness tests**

Run: `go test ./conformance/harness -v -count=1`
Expected: All PASS

**Step 2: Run linters**

Run: `gofumpt ./conformance/harness && go vet ./conformance/harness`
Expected: No output (clean)

**Step 3: Run go mod tidy**

Run: `go mod tidy`
Expected: No changes (no new dependencies)

**Step 4: Commit any formatting fixes**

```
chore(conformance): format and lint fixes
```

---

## Task 10: Update documentation

**Files:**
- Modify: `conformance/AGENTS.md`

**Step 1: Add OIDC config matrix to the Available Matrices table**

In the "Available Matrices" section, add:

```markdown
| `oidcc-config-cert-first2` | oidcc-client-config-certification-test-plan | 2 | Smoke test: client_secret_basic, plain_http_request, static_client, x 2 response modes |
| `oidcc-config-cert-all42` | oidcc-client-config-certification-test-plan | 42 | Full matrix: all auth types x all request types x static_client x all response modes |
```

**Step 2: Update preset tables**

Update the preset table to reflect new job counts:

- `all-rp-full`: 103 (1 OIDC basic + 42 OIDC config + 16 SP + 32 MS + 12 FAPI1-Adv)
- `all-rp-smoke`: 15 (1 OIDC basic + 2 OIDC config + 4 SP + 4 MS + 4 FAPI1-Adv)

Add new preset rows:

```markdown
| `oidcc-config-full` | oidc-rp | oidcc-config-cert-all42 | 8 | 42 |
| `oidcc-config-smoke` | oidc-rp | oidcc-config-cert-first2 | 2 | 2 |
```

**Step 3: Add OIDC config-specific run commands**

Add a new section for OIDC config plan commands:

```markdown
### OIDC Config Certification Full Matrix

Run all 42 OIDC Configuration certification matrix variants in parallel:

\`\`\`bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=oidcc-config-full
\`\`\`

### OIDC Config Certification Smoke Test

Run 2 OIDC Configuration certification variants:

\`\`\`bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=oidcc-config-smoke
\`\`\`
```

**Step 4: Commit**

```
docs(conformance): document OIDC config certification matrix and presets
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Register plan in OIDC profile | `profiles.go` |
| 2 | Add variant defaults for `request_type`, `response_mode` | `execute.go`, tests |
| 3 | Build matrix variant builder + switch cases | `matrix.go` |
| 4 | Full 42-variant test + plan isolation tests | `matrix_test.go` |
| 5 | Add dedicated OIDC config presets | `presets.go`, tests |
| 6 | Update `all-rp-full` and `all-rp-smoke` presets | `presets.go` |
| 7 | Verify/fix plan config for OIDC auth types | `execute.go` |
| 8 | Verify RP runtime passes auth type | `rpruntime.go` (read-only) |
| 9 | Full test suite + lint | all harness files |
| 10 | Update documentation | `AGENTS.md` |
