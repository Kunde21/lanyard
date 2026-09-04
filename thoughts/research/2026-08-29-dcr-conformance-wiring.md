# DCR Conformance Wiring: Investigation Findings

**Date:** 2026-08-29
**Context:** Task 9 of `thoughts/plans/2026-08-29-dynamic-client-registration.md` — assess what it takes to run the suite's dynamic-client-registration RP plan against `cmd/example-rp`.

## Conclusion

**Wiring is feasible but medium-effort (roughly 2 focused sessions), and it is gated on self-registration in the example RP, not on the library.** The library surface (`Registrar`, `ClientRegistration.Options()`) now covers everything the plan needs; the remaining work is example-RP orchestration and harness config.

## What the suite provides

The vendored suite (v5.1.41) ships **`oidcc-client-dynamic-certification-test-plan`** ("OpenID Connect Core: Dynamic Certification Profile Relying Party Tests", certification profile "Dynamic RP"):

- **Variants:** `response_type=code`, `client_registration=dynamic_client` (marked incompatible with `static_client`), `client_request_type=request_uri`.
- **Modules (12):** webfinger acct + URL discovery, openid-configuration discovery, jwks_uri keys check, issuer-mismatch detection, `rp-registration-dynamic` (passes as soon as the AS receives the client's registration request — `finishTestIfAllRequestsAreReceived` on `receivedRegistrationRequest`), request_uri signed RS256, request_uri unsigned (`none`), id_token signed with `none`, OP signing-key rotation ×2, signed userinfo.

So unlike grant management, every module is exercisable today — no suite upgrade needed.

## Gaps in the current stack

1. **Example RP never registers.** `rpClientFromRequest` always uses static credentials (`local-dev-client` or per-alias `conformanceRuntimes`). For the plan, the RP must call `Registrar.Register` (RFC 7591) per alias *during the test*, then use the returned credentials for discovery/login/callback. Natural shape: a "dynamic runtime" mode in `runtime_registry.go` — when a runtime is marked dynamic, `resolveRPRequest` registers on first use (issuer's `registration_endpoint`), caches the `ClientRegistration` per alias, and reuses it (the suite's AS re-issues the same `client_id` for a repeated registration with the same redirect URIs; verify against `CreateRegistrationRequest` conditions in the suite source).
2. **Registration metadata requirements.** The suite validates the registration request (`ValidateRegistrationRequest`-family conditions): `redirect_uris` must include the suite's callback URL for the alias, `token_endpoint_auth_method` must match what the client actually uses (`client_secret_basic`), and jwks/jwks_uri handling must be consistent. All expressible with `ClientMetadata` today.
3. **`none`-signed request objects / id_tokens.** Two modules use `alg: none` (request_uri unsigned; id_token sig none). The request-object signing path in `rp/request_object.go` currently rejects `none` (correctly, per FAPI posture); passing these two modules would need an explicit, opt-in-only dev/`none` mode — worth a small `Profile`-style flag or skipping via plan-module exclusion if the harness supports it.
4. **OP key rotation modules** need the RP to re-fetch JWKS after the suite rotates — the `jwks` package caches; verify refresh-on-unknown-kid already handles it (existing FAPI key-rotation tests in `conformance/README.md` results suggest yes: the 104/104 run included FAPI plans with rotation).
5. **Harness config:** add `oidcc-client-dynamic-certification-test-plan` to `oidcExplicitPlans` (profile `oidc-rp`), plus variant forcing `client_registration=dynamic_client` (`parseForcedVariants` already supports this), and preset entry (e.g. `oidc-rp-dynamic-full`). Provisioning may need to skip static client config for this plan (the suite creates the client record from the registration).

## Recommended sequencing (when picked up)

1. Dynamic-runtime mode in example RP (register-on-first-use per alias, persist in memory) + `/register` demo already merged as the manual counterpart.
2. `none`-mode decision: implement minimal opt-in support or exclude the two modules with rationale documented.
3. Harness: explicit plan + variant + preset, then a local full-suite run mirroring `conformance/README.md`'s verified-result protocol.

## Recommendation

**Update 2026-08-29 (later same day): wiring implemented.**

- **Library:** nothing further needed.
- **Example RP:** dynamic runtimes are live — `rpRuntimeConfig.DynamicClientRegistration` + `Module­Name` (provisioned per module by the harness); `ensureDynamicClientRegistration` (cmd/example-rp/dynamic_runtime.go) registers a fresh RFC 7591 client per module window (the suite mock creates a fresh client record per POST), reuses credentials for same-module/callback requests, and resolves flows with the issued credentials. The runtime registry accepts runtimes without a static client_id when dynamic.
- **Harness:** `oidcc-client-dynamic-certification-test-plan` added to the oidc-rp profile; matrix `oidcc-dynamic-cert` forces `{response_type: code, client_registration: dynamic_client, client_request_type: request_uri}`; preset **`oidcc-dynamic-full`** with `ExcludeModuleRegex: oidcc-client-test-request-uri-signed-(rs256|none)` (new `excludeModules` support in the module filter, preset plumbed through `-preset`).
- **Module decisions:** `idtoken-sig-none` runs (the example RP already passes `rp.WithAllowUnsecuredIDTokens(true)` for the OIDC profile); `request-uri-signed-none` is excluded permanently (the library never emits unsigned request objects by design); `request-uri-signed-rs256` is excluded for now — wiring it needs an OIDC-profile request-object key provider + `jwks_uri` in the registration metadata (follow-up). 10 of 12 modules run.
- **Run:** `LANYARD_CONFORMANCE=1 go test ./conformance/harness -run TestHarness -preset oidcc-dynamic-full` against the local stack; record the verified result in `conformance/README.md` like the `all-rp-full` 104/104 entry.

The original assessment below is retained for context.

Defer until there is a concrete need for "Dynamic RP" certification evidence (the current 104/104 baseline covers Basic/Config/FormPost + FAPI). All blocking library work is done; the wiring is purely example-RP + harness orchestration.
