# Simplify Provider Endpoint Overrides Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Reduce the public and internal provider override surface in `rp` while preserving conformance-driven metadata overrides.

**Architecture:** Keep `rp.WithProviderMetadata(metadata.Provider)` as the single comprehensive provider override API and route any retained convenience behavior through it. Replace the two hand-written merge functions in `rp/rp.go` with one field-table-driven provider merge helper that supports both override-present fields and fill-missing fields. Preserve `cmd/example-rp` conformance behavior by continuing to pass synthesized `metadata.Provider` values for OAuth-only and encrypted-ID-token cases.

**Tech Stack:** Go, `github.com/Kunde21/lanyard/metadata`, `github.com/google/go-cmp/cmp`, `go test`, `go vet`, `gofumpt`.

---

## Current State

- `rp/options.go:90` exposes `WithProviderMetadata(metadata.Provider)`, which works for full or partial provider metadata.
- `rp/options.go:108-190` also exposes seven granular provider override options: `WithAuthorizationEndpoint`, `WithTokenEndpoint`, `WithUserInfoEndpoint`, `WithJWKSURI`, `WithPushedAuthorizationRequestEndpoint`, `WithMTLSEndpointAliases`, and `WithProviderIssuer`.
- `rp/rp.go:162-229` has `mergeProviderMissing`, used after discovery so configured values win and discovery fills gaps.
- `rp/rp.go:231-298` has `mergeConfiguredProvider`, used while applying explicit options so later explicit values win.
- `cmd/example-rp/runtime_resolution.go:354-356` already uses `rp.WithProviderMetadata(provider)` for conformance-specific provider metadata.
- `cmd/example-rp/runtime_resolution.go:413-450` synthesizes provider metadata for non-OpenID OAuth-only conformance runs and for `local-dev-client-2` encrypted-ID-token cases.
- `cmd/example-rp/runtime_resolution_test.go:55-93` verifies the conformance metadata override behavior that must not regress.
- `rp/rp_test.go:399-465` and `rp/rp_test.go:720-810` mainly exercise granular option behavior and ordering.

## Compatibility Decision Points

Make these decisions before changing source code:

1. **Public API compatibility:** Choose one of these options.
   - Preferred for a simplification branch before the next stable release: remove the seven granular endpoint options and require `WithProviderMetadata(metadata.Provider{...})` instead.
   - Safer for already-shipped consumers: keep the seven granular options as deprecated wrappers around `WithProviderMetadata`, then remove them in a later major release.
2. **Public API test expectation:** If removing symbols, update `rp/public_api_external_test.go:11-35` only if those symbols are currently part of the asserted public API. Today they are not listed there, so removal should not require changing this test unless a new replacement symbol is added.
3. **Discovery merge semantics:** Preserve current semantics exactly.
   - Explicit provider values override discovered values.
   - Discovered values fill missing configured values.
   - Multiple explicit provider options merge in application order, with later non-empty values replacing earlier values.
   - Empty string and empty slice values do not clear earlier configured values.
4. **MTLS aliases:** Preserve per-field alias merging for `metadata.MTLSEndpointAliases.TokenEndpoint`, `UserinfoEndpoint`, and `PushedAuthorizationRequestEndpoint`.
5. **Raw metadata:** Preserve `Raw` behavior and `AuthorizationServer.Raw` synchronization from both existing merge functions.
6. **Conformance:** Do not move `cmd/example-rp/runtime_resolution.go:413-450` to granular options. It should continue using `WithProviderMetadata` so conformance can override endpoint, algorithm, auth-method, PAR, JARM, and MTLS alias metadata in one place.

## Task 1: Characterize Current Merge Semantics With Tests

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/rp_test.go`

**Step 1: Add focused merge behavior tests**

Add table-driven tests near the existing provider metadata tests in `rp/rp_test.go` for these behaviors:

- `mergeConfiguredProvider` copies every currently handled scalar field, slice field, MTLS alias field, and `Raw` field when source values are present.
- `mergeConfiguredProvider` ignores empty string, empty slice, and nil `Raw` values.
- `mergeProviderMissing` fills every currently handled scalar field, slice field, MTLS alias field, and `Raw` field when destination values are missing.
- `mergeProviderMissing` preserves existing destination values when present.

Use `github.com/google/go-cmp/cmp` for assertions, consistent with existing tests.

**Step 2: Run the focused tests and verify they pass before refactoring**

Run:

```bash
go test ./rp -run 'TestMerge(ConfiguredProvider|ProviderMissing)' -count=1
```

Expected: PASS. If a new characterization test fails, fix the test expectation to match the existing implementation before changing production code.

**Step 3: Commit optional checkpoint**

Only commit if this work is being done in a dedicated branch:

```bash
git add /home/kunde21/development/AI/lanyard/rp/rp_test.go
git commit -m "test: characterize provider metadata merging"
```

## Task 2: Consolidate Provider Merge Implementation

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/rp.go:162-298`
- Test: `/home/kunde21/development/AI/lanyard/rp/rp_test.go`

**Step 1: Refactor the merge functions behind the tests**

Replace the duplicated bodies of `mergeProviderMissing` and `mergeConfiguredProvider` with one shared helper in `rp/rp.go`.

Recommended minimal shape:

```go
type providerMergeMode int

const (
    providerMergeFillMissing providerMergeMode = iota
    providerMergeOverridePresent
)

func mergeProviderMissing(dst, src metadata.Provider) metadata.Provider {
    return mergeProvider(dst, src, providerMergeFillMissing)
}

func mergeConfiguredProvider(dst, src metadata.Provider) metadata.Provider {
    return mergeProvider(dst, src, providerMergeOverridePresent)
}
```

Inside `mergeProvider`, keep the field list explicit. Use small local helpers for string fields, slice fields, and MTLS alias fields if that materially reduces duplication without hiding the field list. Do not introduce reflection.

**Step 2: Preserve `Raw` synchronization**

At the end of `mergeProvider`, keep behavior equivalent to:

```go
merged.AuthorizationServer.Raw = merged.Raw
```

For `Raw`, preserve the existing mode-specific rules:

- In fill-missing mode, use `src.Raw` only when `dst.Raw == nil`.
- In override-present mode, use `src.Raw` only when `src.Raw != nil`.

**Step 3: Run the focused merge tests**

Run:

```bash
go test ./rp -run 'TestMerge(ConfiguredProvider|ProviderMissing)' -count=1
```

Expected: PASS.

**Step 4: Run all RP tests**

Run:

```bash
go test ./rp -count=1
```

Expected: PASS.

**Step 5: Commit optional checkpoint**

```bash
git add /home/kunde21/development/AI/lanyard/rp/rp.go /home/kunde21/development/AI/lanyard/rp/rp_test.go
git commit -m "refactor: consolidate provider metadata merging"
```

## Task 3: Reduce Granular Provider Override API Surface

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/options.go:108-190`
- Modify: `/home/kunde21/development/AI/lanyard/rp/rp_test.go:223-278`
- Modify: `/home/kunde21/development/AI/lanyard/rp/rp_test.go:399-465`
- Modify: `/home/kunde21/development/AI/lanyard/rp/rp_test.go:680-810`
- Modify if needed: `/home/kunde21/development/AI/lanyard/rp/doc.go`

**Step 1: Pick compatibility path**

If the project is allowed to break this recently-added API, remove these functions from `rp/options.go`:

- `WithAuthorizationEndpoint`
- `WithTokenEndpoint`
- `WithUserInfoEndpoint`
- `WithJWKSURI`
- `WithPushedAuthorizationRequestEndpoint`
- `WithMTLSEndpointAliases`
- `WithProviderIssuer`

If the project needs source compatibility, keep them and change each function into a tiny deprecated wrapper around `WithProviderMetadata`. Example:

```go
// WithAuthorizationEndpoint configures provider metadata with an authorization endpoint.
//
// Deprecated: use WithProviderMetadata with metadata.Provider instead.
func WithAuthorizationEndpoint(endpoint string) Option {
    endpoint = strings.TrimSpace(endpoint)
    if endpoint == "" {
        return rpOptionFunc(func(*RP) {})
    }
    return WithProviderMetadata(metadata.Provider{
        AuthorizationServer: metadata.AuthorizationServer{AuthorizationEndpoint: endpoint},
    })
}
```

Use the same pattern for the other retained wrappers. If removing all wrappers, also remove any now-unused `strings` or `metadata` imports only if they become unused after the whole file is considered.

**Step 2: Update RP tests to use the consolidated API**

Change tests that only need provider metadata setup from granular options to `WithProviderMetadata(metadata.Provider{...})`.

Examples:

- In `TestNew_WithProfile_StoresProfileOnRP`, replace `WithAuthorizationEndpoint` and `WithTokenEndpoint` with one `WithProviderMetadata` containing `AuthorizationEndpoint` and `TokenEndpoint`.
- In `TestNew_WithDiscoveryMode_DiscoveryDisabledStoredOnRP`, do the same.
- In profile default tests at `rp/rp_test.go:854-981`, replace granular endpoint setup with `WithProviderMetadata`.

**Step 3: Replace granular-specific tests**

If removing granular options, delete granular-only tests and replace them with `WithProviderMetadata` tests covering equivalent behavior:

- Partial provider metadata can be configured and discovery fills gaps.
- Multiple `WithProviderMetadata` calls accumulate unrelated fields.
- Later `WithProviderMetadata` calls win for the same non-empty field.
- Empty fields in later `WithProviderMetadata` calls do not erase earlier values.

If keeping deprecated wrappers, keep a small single test proving one representative wrapper delegates correctly, and move broader ordering/merge coverage to `WithProviderMetadata` tests.

**Step 4: Update docs only if needed**

Inspect `/home/kunde21/development/AI/lanyard/rp/doc.go`. If it names granular endpoint options, replace those references with `WithProviderMetadata`. If it only mentions `WithProviderMetadata`, no doc change is needed.

**Step 5: Run focused RP tests**

Run:

```bash
go test ./rp -run 'TestNew_WithProviderMetadata|TestNew_WithDiscoveryMode|TestWithProfile' -count=1
```

Expected: PASS.

**Step 6: Commit optional checkpoint**

```bash
git add /home/kunde21/development/AI/lanyard/rp/options.go /home/kunde21/development/AI/lanyard/rp/rp_test.go /home/kunde21/development/AI/lanyard/rp/doc.go
git commit -m "refactor: consolidate provider override options"
```

## Task 4: Verify Conformance Runtime Behavior Is Unchanged

**Files:**
- Test: `/home/kunde21/development/AI/lanyard/cmd/example-rp/runtime_resolution_test.go`
- Inspect only unless tests fail: `/home/kunde21/development/AI/lanyard/cmd/example-rp/runtime_resolution.go:326-356`
- Inspect only unless tests fail: `/home/kunde21/development/AI/lanyard/cmd/example-rp/runtime_resolution.go:413-450`
- Inspect only unless tests fail: `/home/kunde21/development/AI/lanyard/conformance/harness/rpruntime.go:205-243`

**Step 1: Run conformance runtime unit tests**

Run:

```bash
go test ./cmd/example-rp -run 'TestProviderMetadataForResolvedRequest|TestBuildRPFromResolvedRequest|TestResolveRPRequest|TestRPRuntime' -count=1
```

Expected: PASS. The important existing checks are:

- `TestProviderMetadataForResolvedRequest_UsesMTLSAliasesForConformanceOAuthOnly`
- `TestProviderMetadataForResolvedRequest_UsesOverrideForEncryptedClient2`

**Step 2: Confirm runtime still uses `WithProviderMetadata`**

Search:

```bash
rg 'WithProviderMetadata|WithAuthorizationEndpoint|WithTokenEndpoint|WithJWKSURI|WithPushedAuthorizationRequestEndpoint|WithMTLSEndpointAliases|WithProviderIssuer' /home/kunde21/development/AI/lanyard/cmd/example-rp /home/kunde21/development/AI/lanyard/conformance
```

Expected:

- `cmd/example-rp/runtime_resolution.go` still appends `rp.WithProviderMetadata(provider)`.
- No conformance runtime code depends on removed granular endpoint options.

**Step 3: Run a conformance smoke test when Docker/suite prerequisites are available**

Run:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v -args -preset=all-rp-smoke
```

Expected: PASS. If prerequisites are unavailable, record that this verification was not run and include the blocker.

## Task 5: Full Verification

**Files:**
- Whole repository

**Step 1: Format**

Run:

```bash
gofumpt ./...
```

Expected: no errors. Review any formatting diffs before committing.

**Step 2: Vet**

Run:

```bash
go vet ./...
```

Expected: PASS.

**Step 3: Test everything**

Run:

```bash
go test ./...
```

Expected: PASS.

**Step 4: Check public API search results**

Run:

```bash
rg 'WithAuthorizationEndpoint|WithTokenEndpoint|WithUserInfoEndpoint|WithJWKSURI|WithPushedAuthorizationRequestEndpoint|WithMTLSEndpointAliases|WithProviderIssuer' /home/kunde21/development/AI/lanyard
```

Expected if removing the API: no matches except historical notes under `/home/kunde21/development/AI/lanyard/thoughts/plans/` or release notes intentionally documenting removal.

Expected if deprecating wrappers: matches only in `rp/options.go`, representative tests, docs that mark them deprecated, and historical plans.

**Step 5: Final optional commit**

```bash
git status --short
git add /home/kunde21/development/AI/lanyard/rp /home/kunde21/development/AI/lanyard/cmd/example-rp /home/kunde21/development/AI/lanyard/conformance
git commit -m "refactor: simplify provider metadata overrides"
```

Only include files actually changed. Do not stage unrelated user changes.

## Risks And Rollback

- **Risk:** Removing exported granular functions breaks external users that adopted them.
  **Mitigation:** Use the deprecated-wrapper compatibility path if this API has shipped or is documented as stable.
- **Risk:** A consolidated merge helper accidentally treats empty values as clearing values.
  **Mitigation:** Keep characterization tests for empty strings, empty slices, nil `Raw`, and per-field MTLS aliases.
- **Risk:** Conformance OAuth-only or encrypted-ID-token flows lose metadata overrides.
  **Mitigation:** Keep `providerMetadataForResolvedRequest` returning full `metadata.Provider` and verify `cmd/example-rp` tests plus `all-rp-smoke` conformance.
- **Rollback:** Revert the source changes from Tasks 2 and 3. The Task 1 characterization tests can remain if they still describe desired behavior.
