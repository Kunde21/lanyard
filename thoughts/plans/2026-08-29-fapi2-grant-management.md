# FAPI 2.0 Grant Management Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement FAPI 2.0 Grant Management so Lanyard RPs can create, reference, update, query, and revoke grants: authorization-request parameters (`grant_id`, `grant_management_action`), the token-response `grant_id`, and a client for the Grant Management API (GET/DELETE on the grant resource URL), backed by the three new authorization-server metadata parameters.

**Spec basis (two revisions, both must interop):**

- **draft-ietf-oauth-grant-management** ("Grant Management for OAuth 2.0", the OAuth WG draft; snapshot `oauth-v2-grant-management-03` reviewed for this plan) — actions `create` / `merge` / `replace`; `merge` and `replace` **invalidate existing refresh tokens**; grant status carries `created_at`, `last_updated` / `last_updated_at` (draft is internally inconsistent; example uses `last_updated_at`), `expires_at`, `updated_by`.
- **FAPI 2.0 Grant Management Implementer's Draft 1** (`fapi-grant-management-02`, July 2021 — what CDR / UK deployments certify against) — same model but the merge action is spelled **`update`**, and merge/replace do not mandate refresh-token invalidation.

Lanyard is the **client (RP)**. Creation and modification happen through the authorization request (front channel); query and revoke happen through the Grant Management API (back channel, Bearer token with `grant_management_query` / `grant_management_revoke` scope). Grant IDs are public identifiers, not secrets (§10), and grant management is restricted to confidential clients (§5.1).

**Tech Stack:** Go, `rp` package, existing primitives only — `executeTokenGrant`-style HTTP plumbing, `doRequestWithDPoPRetry`, `OAuthError`, `audienceClaim`-style lenient JSON decoding, `go-cmp` for tests.

**Dependencies:** none blocking. Prerequisites already on master: RFC 8707 resource indicators (grant status `scopes[].resource`), RFC 9396 authorization details (`SetAuthorizationDetails`), RFC 9700 refresh-token rotation semantics (`RefreshTokenSource` — relevant because merge/replace invalidate refresh tokens).

**Scope (non-goals):**

- No CIBA (Lanyard has no CIBA flow; the parameters are defined for any authorization request and will work if one is added later).
- No grant-sharing across client_ids / sector identifiers (AS-side concern).
- No consent-resource sharing API (explicitly out of scope in the draft).
- No FAPI conformance-suite automation in the first pass (investigation task at the end).
- The RP does **not** obtain the Grant Management API access token itself — the caller supplies one (typically via `ClientCredentials.Token` + `WithTokenScopes(ctx, "grant_management_query")`). Rationale in D4.

---

## Design Decisions

### D1: Support both action spellings; `merge` is canonical, `update` is a legacy alias

`GrantManagementAction` is a string type with constants `GrantActionCreate`, `GrantActionMerge`, `GrantActionReplace`. Sending uses whatever the caller chose. A separate `GrantActionUpdate` constant (value `"update"`) is documented as the FAPI ID1 spelling of `merge`; `AuthorizationURL` validates that whichever action is chosen is advertised in `grant_management_actions_supported` when that metadata is present, and rejects `create` combined with `grant_id` and `merge`/`replace`/`update` without `grant_id` (all three are `invalid_request` per the drafts). This keeps CDR/UK interop without forking the model.

### D2: `grant_id` surfaces on `Token` and `CallbackResult`

`Token` gains `GrantID string \`json:"grant_id,omitempty"\`` (token response §5.4). `HandleCallback` copies it to `CallbackResult.GrantID` next to `AccessToken`, so browser-flow callers get it without decoding raw payloads. `Token.GrantID` also flows through refresh responses unchanged (the AS keeps returning it).

### D3: Per-request options, mirroring the authorization-details plumbing

`SetGrantManagementAction(action GrantManagementAction, grantID string)` and `SetGrantID(grantID string)` as `AuthorizationURLOption`s. They land in `buildAuthorizationParameters` output (query form), in PAR parameters, and inside signed request objects (add `grant_id` / `grant_management_action` to the request-object claims struct and to the claim-name allowlist in `request_object.go`, exactly like `resource`). When `grant_management_action_required` is `true` in metadata and no action is set, `AuthorizationURL` fails with `ErrInvalidConfiguration`-wrapped validation (draft §7.1: all authorization requests MUST specify one).

### D4: Grant Management API = two RP methods, caller-supplied Bearer token

`QueryGrant(ctx, accessToken, grantID)` and `RevokeGrant(ctx, accessToken, grantID)` on `*RP` (plus a standalone `GrantManager` constructed by `NewGrantManager(ctx, issuer, opts...)` mirroring `NewIntrospector`, minus auth-method negotiation: the API is authorized by the Bearer token, not client auth). Resource URL = `grant_management_endpoint` + "/" + `grant_id`. GET expects 200; DELETE expects 204; both send `Authorization: Bearer <token>`, run through `doRequestWithDPoPRetry` with `AttachDPoPProof(accessToken)` so sender-constrained tokens work, and map 401/403/404/503 to errors (503 should surface `Retry-After` in the error text). Rationale for caller-supplied token: the drafts leave the grant type used to obtain it out of scope; Lanyard already has `ClientCredentials` + `WithTokenScopes` for exactly this.

### D5: `GrantStatus` follows the `IntrospectionResponse` pattern

Typed fields + preserved raw payload:

```go
type GrantStatus struct {
    Scopes              []GrantScope        `json:"scopes,omitempty"`  // {scope, resource[]}
    Claims              []string            `json:"claims,omitempty"`
    AuthorizationDetails json.RawMessage    `json:"authorization_details,omitempty"`
    CreatedAt           *int64              `json:"created_at,omitempty"`
    LastUpdated         *int64              `json:"last_updated_at,omitempty"` // also accepts "last_updated"
    ExpiresAt           *int64              `json:"expires_at,omitempty"`
    UpdatedBy           string              `json:"updated_by,omitempty"`
}
```

Custom `UnmarshalJSON` accepts both `last_updated` and `last_updated_at` (draft inconsistency) into `LastUpdated` and preserves `raw` for `DecodeRaw`, mirroring `IntrospectionResponse`. `UpdatedBy` validated to `client` / `authorization_server` leniently (unknown values kept as-is; it is informational).

### D6: `invalid_grant_id` gets a sentinel

Authorization error responses carrying `error=invalid_grant_id` (draft §5.3) map to a new `ErrInvalidGrantID` sentinel at the callback, distinct from generic authorization errors. (Task includes first checking how `params.Error` is surfaced today — `parseAuthorizationResponse` currently ignores the non-JARM `error` parameter — and surfacing it generally, which is also an RFC 6749 §4.1.2.1 gap.)

### D7: Metadata: three fields, provider merge, no profile changes

`AuthorizationServer` gains `GrantManagementEndpoint string`, `GrantManagementActionsSupported []string`, `GrantManagementActionRequired *bool`; `mergeProvider` fills endpoint/actions like other optional metadata. No new `Profile` value — grant management is an orthogonal capability that composes with the existing FAPI 2.0 profiles.

### D8: Document the refresh-token invalidation interplay

`merge`/`replace` invalidate the grant's refresh tokens (current draft). After such a flow, the tokens returned by that flow's token exchange are the live ones. Document in `RefreshTokenSource` godoc and `rp/doc.go`; add `(*RefreshTokenSource).Replace(refreshToken string)` so callers that complete a merge/replace flow can point the source at the new token without constructing a new source.

---

## Tasks

### Task 1: Metadata fields + provider merge

**Files:** `metadata/authorization_server.go`, `metadata/metadata_test.go`, `rp/rp.go` (mergeProvider)

1. Add the three fields (D7). 2. Merge support (`mergeString` for endpoint, `mergeStrings` for actions, plain overwrite for the bool when src non-nil). 3. Tests: JSON round-trip, merge fill-missing.
4. Commit: `feat(metadata): grant management metadata parameters`

### Task 2: `Token.GrantID`

**Files:** `rp/token_source.go`, `rp/refresh_token_test.go` (or new `rp/grant_id_test.go`)

1. Add field (D2). 2. Tests: token-endpoint responses with `grant_id` decode onto `Token` (code flow via `HandleCallback` is covered in Task 7; here assert parse + `MarshalJSON`/`UnmarshalJSON` round-trip preserves it).
3. Commit: `feat(rp): parse grant_id in token responses`

### Task 3: Authorization request parameters

**Files:** `rp/options.go`, `rp/authrequest.go`, `rp/authrequest_test.go`, `rp/request_object.go`, `rp/request_object_test.go`, `rp/par.go` (if PAR params need explicit wiring beyond `params`)

1. `GrantManagementAction` type + constants (D1). 2. Options (D3) with validation errors stored on the config (`optionErrors` pattern). 3. Wire into `buildAuthorizationParameters` + `buildSignedRequestObject` claims + allowlist. 4. Tests: query-string inclusion, JAR claim presence, PAR body, `create`+`grant_id` rejected, `merge` without `grant_id` rejected, unadvertised action rejected when metadata present, `update` alias accepted.
5. Commit: `feat(rp): grant management authorization request parameters`

### Task 4: `grant_management_action_required` + `invalid_grant_id`

**Files:** `rp/authrequest.go`, `rp/callback.go`, `rp/callback_params.go`, `rp/errors.go`, tests

1. Enforcement of `grant_management_action_required` (D3). 2. Surface front-channel `error`/`error_description` from `params` in `parseAuthorizationResponse`; add `ErrInvalidGrantID` (D6); keep JARM path consistent.
3. Tests: required-flag failure; callback with `error=invalid_grant_id` returns `ErrInvalidGrantID`; ordinary error codes still surface.
4. Commit: `feat(rp): enforce grant_management_action_required and surface invalid_grant_id`

### Task 5: `GrantStatus` + `QueryGrant`

**Files:** new `rp/grant_management.go`, new `rp/grant_management_test.go`

1. `GrantStatus` (D5), `GrantManager`/`RP.QueryGrant` (D4) with DPoP retry and status→error mapping (401/403/404/503+Retry-After, others via `OAuthError` when the body is an OAuth error).
2. Tests: happy path (scopes/claims/authz-details/timestamps/updated_by), `last_updated` vs `last_updated_at` both accepted, `DecodeRaw`, 404/401 errors, DPoP proof attached when configured, Bearer header shape.
3. Commit: `feat(rp): grant management query API`

### Task 6: `RevokeGrant` + `RefreshTokenSource.Replace`

**Files:** `rp/grant_management.go`, `rp/grant_management_test.go`, `rp/refresh_rotation.go`, `rp/refresh_rotation_test.go`

1. `RP.RevokeGrant`/`GrantManager.Revoke` (204 on success). 2. `Replace` method (D8).
3. Tests: 204 success, non-204 error, `Replace` swaps the current token.
4. Commit: `feat(rp): grant revocation and refresh token replacement`

### Task 7: `CallbackResult.GrantID` + integration test

**Files:** `rp/callback.go`, `rp/callback_test.go`

1. Copy `GrantID` from token response (D2). 2. End-to-end: authorize with `create` → token response carries `grant_id` → `CallbackResult.GrantID` populated; empty when absent.
3. Commit: `feat(rp): expose grant_id on CallbackResult`

### Task 8: Documentation + public API

**Files:** `SPECIFICATIONS.md`, `README.md`, `rp/doc.go`, `rp/public_api_external_test.go`

1. New SPECIFICATIONS section (both revisions noted), flip the Not-Implemented table row + summary table. 2. `rp/doc.go` "Grant management" section (create/merge/replace semantics, refresh invalidation, query/revoke, scopes `grant_management_query`/`grant_management_revoke`). 3. README capability bullet. 4. External compile test for every new exported symbol.
5. Commit: `docs: grant management capabilities`

### Task 9 (investigation, optional): conformance suite

Check `conformance/harness` for how FAPI plan matrices are declared and whether the OpenID certification suite's grant-management tests can run against `cmd/example-rp`. Write findings to `thoughts/research/`; only wire a matrix if it's low-friction.

---

## Verification

- `gofumpt -w . && go vet ./... && go test ./...` after every task; `go test -race ./rp/` before the docs commit.
- Cross-check wire formats against the draft examples verbatim (authorization URL query, grant status JSON with `scopes[].resource`, DELETE → 204).
- Public API compile test in external package stays green (catches accidental unexported-type leakage in new signatures).
