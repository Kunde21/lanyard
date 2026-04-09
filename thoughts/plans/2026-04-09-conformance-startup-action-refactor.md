# Conformance Startup Action Refactor Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

## Goal

Remove harness-triggered RP action endpoints such as `/login` from the conformance contract. Once a conformance module is created and the RP runtime is configured, the example RP should execute the appropriate startup behavior from configuration alone.

This is specifically needed to fix discovery-focused OIDC configuration modules where the suite marks the module complete immediately after observing discovery or discovery+JWKS activity. Those modules fail today because the RP continues into the full authorization flow after the suite has already transitioned the test to `FINISHED`.

## Problem Statement

Current behavior still depends on harness-selected HTTP trigger endpoints. Even after recent cleanup, the harness drives RP behavior by choosing paths like `/login`, which causes the example RP to continue into a full OIDC flow for modules that only require:

- provider metadata discovery, or
- provider metadata discovery plus JWKS fetch/cache initialization.

Evidence from the suite API and logs shows:

- `oidcc-client-test-discovery-openid-config` passes internally as soon as the RP fetches `/.well-known/openid-configuration`, then fails when the RP later hits `/authorize`.
- `oidcc-client-test-discovery-jwks-uri-keys` passes internally as soon as the RP fetches the discovered `jwks_uri`, then fails when the RP later hits `/userinfo`.

The harness should not be deciding RP behavior by selecting front-channel endpoints. The RP configuration should decide behavior, and the example RP should execute that behavior when its runtime is ready.

## Desired End State

1. The harness provisions plans/modules and registers RP runtime, but does not trigger RP behavior via `/login` or similar action endpoints.
2. Runtime configuration includes an explicit startup action such as:
   - `full_flow`
   - `discovery_only`
   - `discovery_and_jwks`
3. The example RP resolves runtime config and immediately performs the configured startup action.
4. Discovery-only modules can be created as standalone runners with minimal client config rather than provisioning the full plan client payload.
5. Normal modules continue to run the full authorization flow, but that flow is initiated by RP runtime setup, not by a harness GET request to an action endpoint.

---

## Architecture Direction

### Responsibilities after refactor

**Harness**

- Create test plans or standalone module runners.
- Wait for modules to reach the expected ready state.
- Register runtime configuration for the RP alias/module.
- Observe and poll suite state.
- Report browser visit URLs when a real browser/front-channel flow is used.

**Example RP**

- Resolve registered runtime config.
- Build RP/discovery clients from configuration.
- Execute the configured startup action.
- Continue to expose callback handling for modules that perform the full flow.

**RP package / metadata package**

- Continue to own provider discovery, metadata merging, and JWKS-related initialization support.
- Remain independent from conformance-specific orchestration choices.

---

## Proposed Runtime Contract Changes

### Add startup action to runtime config

Add a new runtime-facing field in the example RP conformance runtime schema:

```go
type startupAction string

const (
	startupActionFullFlow         startupAction = "full_flow"
	startupActionDiscoveryOnly    startupAction = "discovery_only"
	startupActionDiscoveryAndJWKS startupAction = "discovery_and_jwks"
)
```

Add to runtime JSON payloads:

```go
StartupAction string `json:"startup_action,omitempty"`
```

This should be the single source of truth for what the example RP does once runtime config is available.

### Keep existing profile/discovery config

Do not remove the recent:

- `profile`
- `discovery_mode`

Those fields still define how the RP/discovery client behaves. `startup_action` defines *what to execute*, not *how discovery works*.

### Minimal standalone runner config

For standalone discovery modules created with `POST /api/runner?test=...`, use only the minimum required suite config. Based on suite API observations, the minimal body should look like:

```json
{
  "alias": "run-alias",
  "client": {
    "client_id": "local-dev-client",
    "client_secret": "local-dev-secret-32-bytes-minimum!!",
    "redirect_uri": "https://rp.localhost/callback/run-alias",
    "request_type": "plain_http_request",
    "scope": "openid profile email phone address"
  },
  "waitTimeoutSeconds": 5
}
```

Do not provision `client2` or unrelated config for these standalone modules unless the specific module requires it.

---

## Execution Plan

### Phase 1: Add startup action to runtime types and resolution

**Goal:** Teach the example RP runtime model how to represent startup behavior without changing harness control flow yet.

**Files**

- `cmd/example-rp/runtime_registry.go`
- `cmd/example-rp/runtime_resolution.go`
- `cmd/example-rp/runtime_resolution_test.go`
- `cmd/example-rp/main_test.go`

**Checklist**

- [ ] Add `startup_action` to the runtime registration/request model.
- [ ] Add parsing/normalization helpers for the accepted string values.
- [ ] Ensure missing value defaults to `full_flow` for backward compatibility during the transition.
- [ ] Expose the resolved startup action from runtime resolution.

**Acceptance Criteria**

- [ ] Runtime config can express `full_flow`, `discovery_only`, and `discovery_and_jwks`.
- [ ] Example RP tests cover normalization and defaulting.

**Suggested tests**

```go
func TestResolveRPRequest_DefaultStartupActionIsFullFlow(t *testing.T) {}
func TestResolveRPRequest_ParsesDiscoveryOnlyStartupAction(t *testing.T) {}
func TestResolveRPRequest_ParsesDiscoveryAndJWKSStartupAction(t *testing.T) {}
```

---

### Phase 2: Separate runtime setup from startup execution in the example RP

**Goal:** Make the example RP able to perform discovery-only and discovery+JWKS startup actions without entering the full auth flow.

**Files**

- `cmd/example-rp/main.go`
- `cmd/example-rp/runtime_resolution.go`
- `cmd/example-rp/main_test.go`
- Possibly a new helper file: `cmd/example-rp/startup_actions.go`

**Checklist**

- [ ] Split current login/setup logic into:
  - [ ] runtime resolution
  - [ ] RP/discovery client construction
  - [ ] startup action execution
- [ ] Add a helper to perform discovery-only startup using the configured metadata client.
- [ ] Add a helper to perform discovery + JWKS preload.
- [ ] Keep full-flow behavior intact for normal modules.
- [ ] Ensure startup actions return clear errors when runtime config is incomplete.

**Implementation notes**

The discovery-only path should perform the equivalent of provider metadata discovery and then stop.

The discovery+JWKS path should:

1. perform provider metadata discovery,
2. determine `jwks_uri`,
3. trigger JWKS fetch/cache initialization,
4. stop.

This should use the same discovery/profile configuration the RP would otherwise use, rather than bespoke conformance code paths.

**Acceptance Criteria**

- [ ] Discovery-only startup performs only provider discovery.
- [ ] Discovery+JWKS startup performs discovery and JWKS fetch, but does not continue to auth/token/userinfo.
- [ ] Full-flow startup still performs the existing auth flow behavior.

**Suggested tests**

```go
func TestStartupActionDiscoveryOnly_DoesNotStartAuthorizationFlow(t *testing.T) {}
func TestStartupActionDiscoveryAndJWKS_FetchesJWKSAndStops(t *testing.T) {}
func TestStartupActionFullFlow_StartsAuthorizationFlow(t *testing.T) {}
```

---

### Phase 3: Stop using harness trigger endpoints as the behavior contract

**Goal:** Remove harness responsibility for selecting `/login` or discovery-only paths.

**Files**

- `conformance/harness/execute.go`
- `conformance/harness/execute_test.go`
- `conformance/harness/suiteclient.go` (only if needed)

**Checklist**

- [ ] Remove module-trigger routing such as `moduleTriggerEndpoint`.
- [ ] Remove or bypass code that constructs RP action URLs like `https://rp.localhost/login?...`.
- [ ] Replace trigger execution with runtime registration followed by polling/observation.
- [ ] Keep browser visit reporting logic for modules that genuinely perform browser/front-channel redirects.

**Important constraint**

Do not remove suite browser visit reporting. Full-flow modules still need it.

**Acceptance Criteria**

- [ ] Harness no longer decides RP behavior via action endpoints.
- [ ] Harness tests are updated to reflect configuration-driven startup.

**Suggested tests**

```go
func TestExecute_DoesNotSelectModuleTriggerEndpoint(t *testing.T) {}
func TestExecute_StillReportsBrowserVisitsForRedirects(t *testing.T) {}
```

---

### Phase 4: Use standalone runner creation for discovery-only modules

**Goal:** Avoid provisioning the entire client/plan shape when the module only needs discovery or discovery+JWKS behavior.

**Files**

- `conformance/harness/execute.go`
- `conformance/harness/rpruntime.go`
- `conformance/harness/suiteclient.go`
- `conformance/harness/*_test.go`

**Checklist**

- [ ] Identify the discovery-focused modules that should use standalone runner creation:
  - [ ] `oidcc-client-test-discovery-openid-config`
  - [ ] `oidcc-client-test-discovery-jwks-uri-keys`
- [ ] Add a code path that uses `POST /api/runner?test=...` with minimal JSON config.
- [ ] Keep plan-based execution for normal modules.
- [ ] Ensure runtime registration still uses alias/module-specific config so the RP can resolve the correct startup action.

**Design choice**

Two valid approaches:

1. Hybrid orchestration:
   - standalone runners for discovery-only modules
   - plan-based modules for normal flows

2. Full plan flow retained, but module startup action comes solely from runtime config

Recommendation: start with the hybrid approach if it makes the standalone discovery path much simpler and avoids unnecessary plan provisioning. The key requirement is still that the harness does not choose RP behavior via endpoints.

**Acceptance Criteria**

- [ ] Discovery-only modules can run with minimal client config.
- [ ] No full plan client payload is provisioned for those modules.

**Suggested tests**

```go
func TestCreateStandaloneDiscoveryRunner_UsesMinimalClientConfig(t *testing.T) {}
func TestCreateStandaloneDiscoveryRunner_DoesNotIncludeClient2(t *testing.T) {}
```

---

### Phase 5: Map modules to startup actions in runtime registration

**Goal:** Move the behavioral decision into runtime config generation.

**Files**

- `conformance/harness/rpruntime.go`
- `conformance/harness/rpruntime_test.go`
- `cmd/example-rp/runtime_resolution_test.go`

**Checklist**

- [ ] Add `startup_action` to the runtime request payload generated by the harness.
- [ ] Map modules to startup action:
  - [ ] `oidcc-client-test-discovery-openid-config` -> `discovery_only`
  - [ ] `oidcc-client-test-discovery-jwks-uri-keys` -> `discovery_and_jwks`
  - [ ] default -> `full_flow`
- [ ] Keep `profile` and `discovery_mode` mappings consistent with the module under test.

**Acceptance Criteria**

- [ ] Runtime payload clearly reflects the intended startup behavior.
- [ ] Example RP resolves the same behavior from runtime config with no endpoint-specific logic.

**Suggested tests**

```go
func TestBuildRPRuntimeRequest_DiscoveryConfigModuleUsesDiscoveryOnly(t *testing.T) {}
func TestBuildRPRuntimeRequest_JWKSModuleUsesDiscoveryAndJWKS(t *testing.T) {}
func TestBuildRPRuntimeRequest_DefaultUsesFullFlow(t *testing.T) {}
```

---

### Phase 6: Remove dead RP action endpoint code

**Goal:** Complete the architectural cleanup after the new flow is stable.

**Files**

- `cmd/example-rp/main.go`
- `cmd/example-rp/main_test.go`
- `conformance/harness/execute.go`
- `conformance/harness/execute_test.go`

**Checklist**

- [ ] Remove no-longer-used `/login` trigger behavior from the harness contract.
- [ ] Remove any remaining conformance-only action endpoints that existed solely as harness triggers.
- [ ] Remove compatibility code added only for endpoint-driven startup.

**Acceptance Criteria**

- [ ] No harness code selects RP action endpoints.
- [ ] Example RP startup is configuration-driven.

---

## Conformance Validation Plan

### Unit and package-level validation

Run after each phase as appropriate:

```bash
go test ./cmd/example-rp -count=1
go test ./conformance/harness -count=1
go test ./rp -count=1
```

### Smoke test validation

Re-run the OIDC config smoke preset:

```bash
LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestConformanceHarness -v \
  -args -preset=oidcc-config-smoke
```

### Success criteria for smoke rerun

- `oidcc-client-test-discovery-openid-config` passes because the RP stops after discovery.
- `oidcc-client-test-discovery-jwks-uri-keys` passes because the RP stops after discovery + JWKS fetch.
- Non-discovery modules in the same smoke run still pass.

---

## Risks and Guardrails

1. **Risk: removing `/login` too early breaks normal modules**
   - Guardrail: land startup-action support first, then remove endpoint-based harness behavior.

2. **Risk: example RP starts work before runtime is fully registered**
   - Guardrail: ensure harness waits for module readiness and only then registers runtime / expects startup execution.

3. **Risk: standalone runner config omits a required field for certain variants**
   - Guardrail: start with the two discovery modules proven by logs, and keep config minimal but explicit.

4. **Risk: JWKS preload path diverges from real RP behavior**
   - Guardrail: use the same metadata/discovery client path as production RP setup, only stop earlier.

5. **Risk: browser visit reporting gets removed accidentally**
   - Guardrail: keep explicit tests around browser visit reporting for full-flow modules.

---

## Recommended Implementation Order

1. Add `startup_action` to runtime schema and resolution.
2. Implement startup-action execution in the example RP.
3. Map modules to startup actions in harness runtime registration.
4. Stop using action endpoints as the behavior contract.
5. Add standalone runner creation for discovery-only modules if needed.
6. Remove dead endpoint-based compatibility code.
7. Re-run OIDC config smoke and confirm discovery modules pass.

---

## Concrete Acceptance Snapshot

The refactor is complete when all of the following are true:

- [ ] The harness does not trigger `/login` or any discovery endpoint to choose RP behavior.
- [ ] Runtime config includes `startup_action`.
- [ ] The example RP performs discovery-only or discovery+JWKS startup directly from runtime config.
- [ ] Discovery-focused modules no longer fail with `Illegal test state change: FINISHED -> RUNNING`.
- [ ] `oidcc-config-smoke` passes after the refactor.
