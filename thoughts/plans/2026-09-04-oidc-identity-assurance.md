# OIDC for Identity Assurance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement OpenID Connect for Identity Assurance 1.0 (Final, incorporating errata set 1) client-side support: requesting `verified_claims` via the OIDC `claims` parameter (including the base claims-parameter support the library currently lacks), parsing and validating the `verified_claims` response container (in ID Token and UserInfo), and the OP metadata that advertises identity-assurance capabilities.

**Spec basis:**

- **OpenID Connect for Identity Assurance 1.0 — Final + errata set 1** (`openid-connect-4-identity-assurance-1_0-errata1`). Request syntax: the `claims` parameter's `userinfo`/`id_token` elements gain a `verified_claims` member containing `verification` (filters: `trust_framework`, `time`, `evidence[]` with `type`/`check_details[]`/`document_details`…) and a nested `claims` map (values `null` or `{essential, value, values, max_age}`). An **array of `verified_claims` objects** is allowed (different verification requirements per claim set, §5.6). Constraint semantics: `value`/`values` on constrainable elements; `evidence/type` MUST use `value` only (§5.4); `max_age` applies to any date/timestamp element (§5.5.2). The draft-era `purpose` member is NOT in the final spec — do not implement it.
- **OpenID Identity Assurance Schema Definition 1.0** — response schema for `verification`/`evidence`/`check_details`/`document_details` etc.
- **Wire ground truth in-tree:** the vendored conformance suite ships the normative JSON Schemas at `conformance/.upstream/conformance-suite/src/main/resources/json-schemas/ekyc-ida/` (`verified_claims_request.json`, `verified_claims.json`, `claims_schema.json`) — use their structures and the spec's verbatim examples as test fixtures.

**Conformance reality (researched):** the suite's `ekyc-test-plan-oidccore` (12 modules) is **OP-side** (`ekyctest` profile) — it drives a mock *RP* against the suite's OP; it cannot run against `cmd/example-rp` the way the client-profile plans do. There is no RP-profile IDA plan in the suite. Validation is therefore unit tests grounded in the suite's schemas/spec examples; record this in a research note (Task 8).

**Tech Stack:** Go, `rp` package, existing primitives — `authorizationURLConfig` option plumbing, `buildAuthorizationParameters` (query), PAR, request objects (`requestObjectClaims` + `claimsToMap` allowlist), `idTokenClaims` extension pattern, userinfo `map[string]any` payload, `go-cmp` tests.

**Dependencies:** none. Everything else in SPECIFICATIONS.md is done.

**Scope (non-goals):**

- No OP-side behavior (Lanyard is an RP library).
- No `purpose` member (draft-only; rejected by final spec).
- No OpenID Attachments binary processing (separate spec; attachments pass through as raw JSON).
- No new aggregated/distributed-claims machinery — userinfo's existing `resolveDistributedClaims` already applies; `verified_claims` passthrough rides on it.
- No drafts: Authority claims, ASC (Selective Abort/Omit, Transformed Claims), Attachments.

---

## Design Decisions

### D1: Base `claims` parameter first (OIDC Core 5.5)

The library has never had a claims request parameter (only `claims_parameter_supported` metadata parsing). Add:

- `WithClaims(raw string)` client-level default Option (validated JSON object at construction; stored `ErrInvalidConfiguration` otherwise), and
- `SetClaims(raw string)` `AuthorizationURLOption` for per-request use (validated in `AuthorizationURL`).

Wiring: `claims` query parameter in `buildAuthorizationParameters`, PAR body, and signed request objects (`requestObjectClaims.Claims json.RawMessage` + `claimsToMap` entry + claim-name allowlist entry `"claims"`). Merge semantics: per-request option overrides client default. The value is passed as caller-authored JSON — the IDA builders (D2) generate it, but plain OIDC claims requests remain usable.

### D2: Typed request builders producing the claims JSON

```go
type ClaimsRequest struct { IDToken, UserInfo map[string]any } // top level; raw for non-verified members
```

Rather than a full claims DSL, provide IDA-focused builders:

- `VerifiedClaimsFilter` — `Verification *VerificationFilter`, `Claims map[string]*ClaimConstraint` (nil = `null`).
- `VerificationFilter` — `TrustFramework Constrainable`, `Time *Constrainable`, `Evidence []EvidenceFilter` (OR semantics), marshals `null`/`{value}`/`{values}` per the schema.
- `ClaimConstraint` — `Essential *bool`, `Value any`, `Values []any`, `MaxAge *int64` (seconds).
- `AddVerifiedClaimsToUserInfo(cr *ClaimsRequest, f ...VerifiedClaimsFilter)` / `...ToIDToken(...)` — appends single object or array (array when >1, §5.6).
- Validation: `evidence[].type` must carry exactly one `value` (spec forbids `values` there); `max_age` only on date/timestamp elements the schema allows (`time`, document `date_of_issuance`/`date_of_expiry`) — enforced as a warning-free build error where statically known.

### D3: Response types — typed core, raw tails

```go
type VerifiedClaims struct {
    Verification *Verification   `json:"verification,omitempty"`
    Claims       map[string]any  `json:"claims,omitempty"`
    raw          json.RawMessage // DecodeRaw
}
type Verification struct {
    TrustFramework    string           `json:"trust_framework,omitempty"`
    AssuranceLevel    string           `json:"assurance_level,omitempty"`
    Time              *time.Time       `json:"time,omitempty"` // RFC3339
    Evidence          []Evidence       `json:"evidence,omitempty"`
    AssuranceProcess  json.RawMessage  `json:"assurance_process,omitempty"`
    raw               json.RawMessage
}
type Evidence struct {
    Type            string          `json:"type,omitempty"`
    Time            *time.Time      `json:"time,omitempty"`
    CheckDetails    []CheckDetails  `json:"check_details,omitempty"`
    DocumentDetails json.RawMessage `json:"document_details,omitempty"` // typed follow-up if needed
    raw             json.RawMessage
}
type CheckDetails struct { CheckMethod string `json:"check_method,omitempty"`; CheckID, Organization string; Time *time.Time }
```

Delivery surfaces:
- `idTokenClaims.VerifiedClaims json.RawMessage` → `CallbackResult.VerifiedClaims []VerifiedClaims` (parsed; absent = nil; malformed → `ErrIDTokenValidationFailed`-wrapped error).
- `ParseVerifiedClaims(payload map[string]any) ([]VerifiedClaims, error)` for userinfo payloads (the member can be object or array).
- Existing distributed-claims resolution continues to run on the userinfo payload untouched.

### D4: Freshness helper per spec §5.5.2

`(v *Verification) FreshFor(maxAge time.Duration, now time.Time) bool` — elapsed from `verification.time`; absent `time` → consults evidence dates; none present → false. Dates (as opposed to timestamps) count from the **last valid second** of the day. Keep the helper honest about absence rather than guessing.

### D5: OP metadata + provider merge

Add to `metadata.Provider` (OIDC-level, alongside `claims_parameter_supported`): `TrustFrameworksSupported`, `ClaimsInVerifiedClaimsSupported`, `EvidenceSupported`, `DocumentsSupported`, `DocumentsCheckMethodsSupported`, `ElectronicRecordsSupported`. **Known spec discrepancy:** prose names it `documents_check_methods_supported` while the spec's own example uses `documents_methods_supported` — parse BOTH into `DocumentsCheckMethodsSupported` (example spelling wins when both present; document in godoc). All `[]string`, merge via `mergeStrings`.

### D6: Example-RP demo

`/login?claims=<urlencoded json>` passthrough via `SetClaims` (validation surfaced as 400), plus the IDA builders demonstrated in `rp/example_test.go` (doc examples beat a half-driven demo endpoint — there is no RP conformance plan to satisfy).

---

## Tasks

### Task 1: Base claims request parameter

**Files:** `rp/options.go`, `rp/authrequest.go`, `rp/par.go`, `rp/request_object.go`, tests

1. `WithClaims` option + `SetClaims` AuthorizationURLOption (D1) with JSON validation. 2. Wire query + PAR + request object (claims struct member, `claimsToMap`, allowlist). 3. Tests: query/PAR/JAR presence, override precedence, invalid JSON errors, request-object round-trip.
4. Commit: `feat(rp): OIDC claims request parameter`

### Task 2: IDA request builders

**Files:** new `rp/identity_assurance.go`, new `rp/identity_assurance_test.go`

1. Types + builders + validation (D2). 2. Tests: spec §5.3/5.4/5.5.1/5.5.2/5.6 verbatim examples reproduce byte-comparable JSON (key order normalized via unmarshal-compare); evidence/type `values` rejection; max_age serialization.
3. Commit: `feat(rp): verified_claims request builders (IDA 1.0)`

### Task 3: OP metadata

**Files:** `metadata/provider.go`, `metadata/metadata_test.go`, `rp/rp.go`

1. Six fields + both spellings for check methods (D5) + `mergeProvider` entries. 2. Tests incl. the spec's openid-configuration example snippet.
3. Commit: `feat(metadata): identity assurance OP metadata`

### Task 4: Response parsing + surfacing

**Files:** `rp/identity_assurance.go`, `rp/idtoken.go`, `rp/callback.go`, tests

1. `VerifiedClaims`/`Verification`/`Evidence`/`CheckDetails` + `ParseVerifiedClaims` (D3). 2. ID-token integration + `CallbackResult.VerifiedClaims`. 3. Tests: spec §5.2 examples (ID token + userinfo), object-or-array tolerance, malformed member error, absent member = nil.
4. Commit: `feat(rp): parse verified_claims responses`

### Task 5: Freshness helper

**Files:** `rp/identity_assurance.go`, tests

1. `FreshFor` (D4) incl. last-valid-second date semantics. 2. Tests: timestamp/date/boundary/absent cases.
3. Commit: `feat(rp): verification freshness checks (IDA max_age)`

### Task 6: Example-RP + doc examples

**Files:** `cmd/example-rp/main.go` (claims query param), `rp/example_test.go`

1. `/login?claims=` wiring. 2. Doc examples for builders + response handling.
3. Commit: `feat(example-rp): claims parameter demo`

### Task 7: Documentation + public API

**Files:** `SPECIFICATIONS.md`, `README.md`, `rp/doc.go`, `rp/public_api_external_test.go`

1. New IDA section (feature table), summary row, drop the last Not-Implemented row. 2. `rp/doc.go` section. 3. README bullet. 4. External compile coverage (nil-safe method values only).
5. Commit: `docs: identity assurance capabilities`

### Task 8: Research note

`thoughts/research/2026-09-04-ida-conformance-status.md` — the ekyc suite plan is OP-side (`ekyctest`), no RP-profile IDA plan exists; RP validation strategy = unit tests grounded in the suite's in-tree JSON schemas + spec examples; revisit if OIDF ships an RP plan.

---

## Verification

- `gofumpt -w . && go vet ./... && go test ./...` per task; `go test -race ./rp/` before Task 7.
- Spec examples reproduced verbatim (compared as parsed JSON) in tests for both request and response sides.
- Public API external compile test stays green.
- Conventional commits, both remotes synced.
