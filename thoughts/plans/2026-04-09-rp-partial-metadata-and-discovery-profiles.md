# RP Partial Metadata And Discovery Profiles Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current all-or-nothing `rp.WithProviderMetadata` behavior with granular RP configuration that supports partial metadata, discovery fallback, and explicit discovery/profile defaults such as `rp.OAuth2`, `rp.OIDC`, and `rp.FAPI1Adv`. The end state should let the RP decide when discovery is required, so the conformance harness no longer needs to route modules through special `/discovery` endpoints just to force metadata resolution.

**Architecture:** Introduce two explicit configuration axes in `rp`: a profile/defaults axis (`WithProfile`) and a discovery-policy axis (`WithDiscoveryMode`). Store caller-supplied metadata as partial configuration, merge discovered values only for missing fields, and preserve explicit caller values over discovered ones. Keep `WithProviderMetadata` as compatibility sugar that fills the same partial metadata store rather than bypassing discovery. After the RP supports partial configuration cleanly, simplify the example RP and then remove harness-side module-specific discovery triggering.

**Tech Stack:** Go 1.25+, existing `rp` and `conformance/harness` packages, `go test`, `gofumpt`, `github.com/google/go-cmp/cmp`, standard library HTTP test servers.

---

## Design Constraints

1. Preserve current public behavior for callers that already provide complete metadata through `WithProviderMetadata`.
2. Do not introduce a large new abstraction layer for metadata. Prefer a small partial-config struct plus focused merge helpers.
3. Keep discovery semantics explicit. The code should clearly answer:
   - what metadata the caller supplied
   - what defaults a profile applied
   - whether discovery is allowed
   - whether discovery is required for the current RP setup
4. Preserve explicit caller configuration over discovered values.
5. Keep the public API minimal and additive. Do not remove `WithProviderMetadata` in this change.
6. Defer harness simplification until the RP layer can represent the desired behavior directly.

---

## Proposed Public API

### Profile defaults

Add a small exported profile enum in `rp`:

```go
type Profile int

const (
	OIDC Profile = iota
	OAuth2
	FAPI1Adv
	FAPI2SecurityProfile
	FAPI2MessageSigning
)
```

Add:

```go
func WithProfile(profile Profile) Option
```

This option should apply defaults for RP behavior, not hardcode metadata. Examples:

- `OIDC`: default scopes include `openid`; discovery defaults to OIDC/provider metadata.
- `OAuth2`: default scopes do not force `openid`; discovery defaults to OAuth2 authorization server metadata when discovery is needed.
- `FAPI1Adv`: enable FAPI1 profile defaults, PAR expectation defaults, request/response defaults appropriate for the existing RP feature set.
- `FAPI2SecurityProfile` and `FAPI2MessageSigning`: preserve current sender-constraining and request-mode behavior already expressed elsewhere in options.

Do not let `WithProfile` silently overwrite explicit options that were already set by callers. Defaults should only fill unset fields.

### Discovery policy

Add an exported discovery mode enum:

```go
type DiscoveryMode int

const (
	DiscoveryAuto DiscoveryMode = iota
	DiscoveryOIDC
	DiscoveryOAuth2
	DiscoveryDisabled
)
```

Add:

```go
func WithDiscoveryMode(mode DiscoveryMode) Option
```

Intended behavior:

- `DiscoveryAuto`: choose discovery type from profile/defaults and current RP needs.
- `DiscoveryOIDC`: force OIDC provider metadata discovery.
- `DiscoveryOAuth2`: force OAuth2 authorization server metadata discovery.
- `DiscoveryDisabled`: never discover; fail if required metadata is still missing.

### Granular provider metadata options

Add narrow endpoint/metadata setters that populate partial metadata without implying completeness:

```go
func WithAuthorizationEndpoint(endpoint string) Option
func WithTokenEndpoint(endpoint string) Option
func WithUserInfoEndpoint(endpoint string) Option
func WithJWKSURI(uri string) Option
func WithPushedAuthorizationRequestEndpoint(endpoint string) Option
func WithMTLSEndpointAliases(aliases metadata.MTLSEndpointAliases) Option
func WithProviderIssuer(issuer string) Option
```

Optional if it keeps the API smaller:

```go
func WithAuthorizationServerMetadata(as metadata.AuthorizationServer) Option
```

Do not add setters for fields the RP never reads. Keep the surface aligned with actual runtime requirements.

### Compatibility behavior for `WithProviderMetadata`

Keep:

```go
func WithProviderMetadata(provider metadata.Provider) Option
```

But redefine it so it copies values into the same partial metadata storage used by the new granular options. It should no longer mean “provider is complete, skip discovery unconditionally.”

---

## Internal Model Changes

### Task 1: Add profile and discovery state to `RP`

**Files:**
- Modify: `rp/rp.go`
- Modify: `rp/options.go`
- Modify: `rp/public_api_external_test.go`
- Test: `rp/rp.go`

**Step 1: Add new enums and fields**

Add the new exported `Profile` and `DiscoveryMode` types in `rp`. Store them on `RP` along with whether the caller explicitly set them.

Recommended shape:

```go
type RP struct {
	// existing fields
	profile profileType
	discoveryMode DiscoveryMode
	configuredProvider metadata.Provider
	effectiveProvider metadata.Provider
	configuredProviderSet bool
	profileExplicit bool
	discoveryModeExplicit bool
	// ...
}
```

Use unexported internal normalized forms if needed, but keep the public API small.

**Step 2: Add `WithProfile` and `WithDiscoveryMode` options**

Make these options fill RP config only. They should not trigger discovery directly.

**Step 3: Add basic constructor tests**

Add tests such as:

```go
func TestNew_WithProfile_OAuth2AppliesDefaults(t *testing.T) {}
func TestNew_WithDiscoveryMode_DiscoveryDisabledStoredOnRP(t *testing.T) {}
func TestNew_ExplicitOptionsOverrideProfileDefaults(t *testing.T) {}
```

**Step 4: Run focused RP tests**

Run: `go test ./rp -run 'TestNew_WithProfile|TestNew_WithDiscoveryMode|TestNew_ExplicitOptionsOverrideProfileDefaults' -count=1`
Expected: PASS

**Expected payoff:** Creates explicit configuration vocabulary so later changes do not overload `WithProviderMetadata` or infer discovery behavior from incidental fields.

---

### Task 2: Introduce partial provider metadata storage and granular setters

**Files:**
- Modify: `rp/options.go`
- Modify: `rp/rp.go`
- Modify: `rp/endpoints.go`
- Modify: `rp/rp_test.go`
- Test: `rp/options.go`

**Step 1: Add private merge helpers**

Introduce small helpers such as:

```go
func mergeProviderMissing(dst, src metadata.Provider) metadata.Provider
func providerHasAuthorizationEndpoint(provider metadata.Provider) bool
func providerHasTokenEndpoint(provider metadata.Provider) bool
func providerHasJWKSURI(provider metadata.Provider) bool
```

Keep these explicit rather than reflective.

**Step 2: Add granular options**

Each new option should write into `r.configuredProvider` and mark `configuredProviderSet = true` only when a non-empty value is applied.

Examples:

```go
func WithAuthorizationEndpoint(endpoint string) Option {
	return func(r *RP) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		r.configuredProvider.AuthorizationServer.AuthorizationEndpoint = endpoint
		r.configuredProviderSet = true
	}
}
```

**Step 3: Rewrite `WithProviderMetadata` as a bulk fill**

It should set `configuredProvider` rather than `provider/providerSet`. Do not remove the function.

**Step 4: Update endpoint readers to use effective provider state**

If endpoint helper methods currently read `r.provider`, change them to read `r.effectiveProvider` once that field exists. If the rename is too noisy, keep `provider` as the effective merged provider and use `configuredProvider` as the new partial input field.

**Step 5: Add compatibility and partial-config tests**

Add tests such as:

```go
func TestNew_WithProviderMetadata_SkipsDiscoveryWhenMetadataIsComplete(t *testing.T) {}
func TestNew_WithAuthorizationEndpoint_StoresPartialMetadata(t *testing.T) {}
func TestNew_WithProviderMetadataMissingAuthorizationEndpoint_DoesNotFailWhenDiscoveryCanFillIt(t *testing.T) {}
```

The third test should fail before the merge/discovery work in Task 3; write it once the implementation path is ready.

**Step 6: Run RP tests**

Run: `go test ./rp -run 'TestNew_WithProviderMetadata|TestNew_WithAuthorizationEndpoint' -count=1`
Expected: PASS

**Expected payoff:** Decouples “metadata supplied” from “metadata complete,” which is the core requirement for discovery fallback.

---

### Task 3: Refactor provider initialization into defaults, discovery, and merge stages

**Files:**
- Modify: `rp/rp.go`
- Modify: `rp/discovery.go`
- Modify: `rp/rp_test.go`
- Modify: `rp/discovery_test.go`
- Modify: `rp/authrequest_test.go`
- Test: `rp/rp.go`

**Step 1: Split `initProvider` into focused helpers**

Refactor the current constructor flow into these conceptual stages:

1. validate base inputs
2. initialize defaults
3. apply profile defaults
4. initialize metadata client
5. resolve effective provider metadata
6. resolve auth method
7. validate effective provider for requested operations

Suggested private helpers:

```go
func (r *RP) applyProfileDefaults()
func (r *RP) resolveDiscoveryMode() DiscoveryMode
func (r *RP) resolveProvider(ctx context.Context) error
func (r *RP) discoverProviderMetadataForMode(ctx context.Context, issuer string, mode DiscoveryMode) (metadata.Provider, error)
func (r *RP) providerNeedsDiscovery() bool
```

**Step 2: Define when discovery is required**

Do not use one monolithic “provider is set” flag. Instead, discovery should run when:

- discovery is enabled, and
- required metadata for the RP's configured mode is missing.

Minimum initial rule set:

- authorization flow requires `authorization_endpoint`
- callback/token flow requires `token_endpoint`
- UserInfo validation requires `userinfo_endpoint` only when userinfo will actually be used
- ID token/JARM validation requires `jwks_uri` or another supported signing-key path
- PAR requires `pushed_authorization_request_endpoint`

Start narrow: only gate on fields the RP already consumes today.

**Step 3: Implement discovery-mode-specific resolution**

Target behavior:

- `DiscoveryOIDC`: use `DiscoverProvider`
- `DiscoveryOAuth2`: add or use authorization-server discovery support and map it into `metadata.Provider`
- `DiscoveryAuto`: choose OIDC when OIDC/OpenID semantics are active, OAuth2 otherwise
- `DiscoveryDisabled`: skip network discovery and fail if metadata remains insufficient

If the RP package does not already expose OAuth2 authorization server discovery, implement the smallest internal bridge possible using `metadata.Client.DiscoverAuthorizationServer` and conversion into `metadata.Provider` shape.

**Step 4: Merge discovered metadata only into missing fields**

Caller-configured values win. Discovery fills gaps only. This must be explicit in code and tests.

**Step 5: Add tests that pin the new behavior**

Add or extend tests covering:

```go
func TestNew_WithCompleteProviderMetadata_SkipsDiscoveryHTTP(t *testing.T) {}
func TestNew_WithPartialProviderMetadata_FillsMissingFieldsFromDiscovery(t *testing.T) {}
func TestNew_WithGranularEndpointOptions_FillsMissingFieldsFromDiscovery(t *testing.T) {}
func TestNew_WithDiscoveryDisabledAndMissingAuthorizationEndpoint_ReturnsError(t *testing.T) {}
func TestNew_WithDiscoveryModeOAuth2_UsesAuthorizationServerDiscovery(t *testing.T) {}
func TestNew_ExplicitProviderFieldsOverrideDiscoveredValues(t *testing.T) {}
```

Also keep the existing regression test that `AuthorizationURL` does not rediscover after `New`.

**Step 6: Run RP tests**

Run: `go test ./rp -count=1`
Expected: PASS

**Expected payoff:** Moves the main policy decision into `rp.New`, which is the key prerequisite for removing harness-side discovery triggers.

---

### Task 4: Define profile defaults without hiding important behavior

**Files:**
- Modify: `rp/rp.go`
- Modify: `rp/options.go`
- Modify: `rp/par_test.go`
- Modify: `rp/authrequest_test.go`
- Modify: `rp/jarm_test.go`
- Test: `rp/rp.go`

**Step 1: Map each profile to default settings**

Keep this small and aligned with existing RP capabilities.

Initial recommendation:

- `OIDC`
  - default scopes include `openid`
  - default discovery mode in auto resolves to OIDC
- `OAuth2`
  - do not force `openid`
  - auto discovery resolves to OAuth2 auth server metadata
- `FAPI1Adv`
  - set FAPI1 profile
  - prefer signed request method defaults already supported in the package
  - default PAR requirement when appropriate for current conformance usage
- `FAPI2SecurityProfile`
  - set FAPI2 profile and security defaults already encoded elsewhere
- `FAPI2MessageSigning`
  - same as FAPI2 SP plus message-signing defaults already exercised in conformance

**Step 2: Preserve explicit options over profile defaults**

For example:

- `WithScopes("accounts")` should not be overwritten by `WithProfile(OIDC)`
- `WithRequirePAR(false)` should remain explicit if the caller set it intentionally
- `WithResponseMode(...)` and `WithResponseType(...)` should win over profile defaults

If needed, add internal boolean markers for explicit user configuration on these fields.

**Step 3: Add focused tests**

```go
func TestWithProfile_OIDC_DefaultsOpenIDScope(t *testing.T) {}
func TestWithProfile_OAuth2_DoesNotForceOpenIDScope(t *testing.T) {}
func TestWithProfile_FAPI1Adv_DefaultsCanBeOverridden(t *testing.T) {}
```

**Step 4: Run focused tests**

Run: `go test ./rp -run 'TestWithProfile_' -count=1`
Expected: PASS

**Expected payoff:** Gives the example RP and future callers a compact way to express policy without pushing conformance-specific branching into the harness.

---

## Conformance Integration Changes

### Task 5: Move example RP runtime config from “trigger behavior” toward “configuration only”

**Files:**
- Modify: `cmd/example-rp/runtime_registry.go`
- Modify: `cmd/example-rp/runtime_resolution.go`
- Modify: `cmd/example-rp/main.go`
- Modify: `cmd/example-rp/main_test.go`
- Test: `cmd/example-rp/runtime_resolution.go`

**Step 1: Extend runtime config to express profile and discovery mode**

Add fields such as:

```go
Profile       string `json:"profile,omitempty"`
DiscoveryMode string `json:"discovery_mode,omitempty"`
```

String values are acceptable here because the runtime endpoint is an internal harness contract. Normalize them in the example RP before applying RP options.

**Step 2: Translate runtime config directly into RP options**

In `buildRPFromResolvedRequest`, stop hardcoding discovery selection through endpoint choice. Instead:

- apply `WithProfile(...)` when runtime config specifies one
- apply `WithDiscoveryMode(...)` when runtime config specifies one
- apply granular metadata options for any explicitly provided endpoints
- rely on `rp.New` to discover missing fields as needed

**Step 3: Keep temporary compatibility with current runtime fields**

Existing runtime fields like `RequirePAR`, `FAPIProfile`, `ResponseMode`, and `FAPIRequestMethod` should continue to map to RP options until the harness is simplified.

**Step 4: Add tests**

Add tests proving runtime config can express:

```go
func TestResolveRPRequest_RuntimeOAuth2ProfileUsesOAuthDiscovery(t *testing.T) {}
func TestResolveRPRequest_RuntimePartialMetadataAllowsDiscoveryFallback(t *testing.T) {}
```

**Step 5: Run example RP tests**

Run: `go test ./cmd/example-rp -count=1`
Expected: PASS

**Expected payoff:** Makes the example RP the owner of discovery policy, not the harness.

---

### Task 6: Simplify harness triggering after RP config can express discovery

**Files:**
- Modify: `conformance/harness/execute.go`
- Modify: `conformance/harness/rpruntime.go`
- Modify: `conformance/harness/execute_test.go`
- Modify: `conformance/harness/rpruntime_test.go`
- Test: `conformance/harness/execute.go`

**Step 1: Extend runtime registration payload to carry profile/discovery settings**

Update `rpRuntimeRequest` and `buildRPRuntimeRequestForAlias` to include the new runtime-facing config needed by the example RP.

Good first pass:

- OIDC config/basic plans: `profile=oidc`, `discovery_mode=auto`
- plain OAuth variants: `profile=oauth2`, `discovery_mode=oauth2`
- FAPI1 advanced: `profile=fapi1_adv`, `discovery_mode=oauth2` or `auto`, depending on which best matches the final RP logic

Choose one mapping and make it explicit in tests.

**Step 2: Collapse module trigger routing toward a single front-channel login path**

Once the RP can decide to discover based on missing metadata, reduce `moduleTriggerEndpoint` so discovery/config modules use `/login` unless there is still a concrete reason to keep a separate endpoint.

The expected end state is:

- `/login` handles normal auth-start for almost all modules
- `/login-userinfo-body` remains only if token transport truly differs per module
- `/discovery` and `/discovery-jwks` are removed or kept only as explicit diagnostics, not harness requirements

**Step 3: Remove module-name-based discovery assumptions from harness tests**

Update tests that currently assert `/discovery` and `/discovery-jwks` routing. Replace them with assertions about runtime config generation and the remaining minimal trigger behavior.

**Step 4: Run harness tests**

Run: `go test ./conformance/harness -count=1`
Expected: PASS

**Expected payoff:** Removes test-subject behavior from harness control flow, which was the original architectural goal.

---

## Recommended Test Matrix

Before changing harness behavior, the RP package should have regression tests for these specific cases:

```go
func TestNew_WithCompleteProviderMetadata_SkipsDiscoveryHTTP(t *testing.T) {}
func TestNew_WithPartialProviderMetadata_FillsAuthorizationEndpointFromDiscovery(t *testing.T) {}
func TestNew_WithPartialProviderMetadata_PreservesExplicitTokenEndpoint(t *testing.T) {}
func TestNew_WithDiscoveryDisabled_ReturnsErrorForMissingRequiredMetadata(t *testing.T) {}
func TestNew_WithProfileOAuth2_UsesOAuthDiscoveryByDefault(t *testing.T) {}
func TestNew_WithProfileOIDC_UsesOIDCDiscoveryByDefault(t *testing.T) {}
func TestAuthorizationURL_DoesNotRediscoverAfterConstruction(t *testing.T) {}
```

The example RP should then have integration-style tests for runtime-driven configuration, and only after that should the harness stop calling discovery endpoints.

---

## Risk Notes

1. The biggest behavioral risk is changing `WithProviderMetadata` semantics. Keep compatibility by ensuring complete metadata still skips discovery in practice because nothing is missing.
2. Be careful not to accidentally force OIDC discovery for OAuth-only callers that intentionally omit `openid`.
3. Profile defaults can become too magical. Only default fields the RP already treats as policy-level settings.
4. Do not broaden discovery requirements unnecessarily. Only discover when a missing field is actually needed.
5. Keep the initial implementation focused on constructor-time metadata resolution. Avoid mixing in callback-time rediscovery changes unless tests show a current requirement.

---

## Suggested Execution Order

1. Add `Profile` and `DiscoveryMode` enums/options.
2. Add partial metadata storage and granular endpoint setters.
3. Refactor `rp.New` provider resolution to merge configured and discovered metadata.
4. Add/adjust RP tests until the new semantics are stable.
5. Extend example RP runtime config to pass profile/discovery settings into RP options.
6. Simplify harness trigger routing and remove `/discovery` dependency.

---

## Validation Commands

Run after each stage as appropriate:

```bash
go test ./rp -count=1
go test ./cmd/example-rp -count=1
go test ./conformance/harness -count=1
gofumpt -w rp/*.go cmd/example-rp/*.go conformance/harness/*.go
```

Before finalizing the whole change:

```bash
gofumpt ./...
go test ./...
```

Expected: PASS
