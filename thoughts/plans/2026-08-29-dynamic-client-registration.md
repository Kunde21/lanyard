# Dynamic Client Registration (RFC 7591 + RFC 7592) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement client-side Dynamic Client Registration so Lanyard RPs can register themselves at an authorization server (RFC 7591) and manage the resulting registration over its lifecycle — read, update/secret-rotation, delete (RFC 7592) — then construct a normal `RP` from the issued credentials.

**Spec basis:**

- **RFC 7591** — OAuth 2.0 Dynamic Client Registration: POST client metadata to `registration_endpoint` (optionally protected by an initial access token) → 201 Created with `client_id`, optional `client_secret`, `client_id_issued_at`, `client_secret_expires_at`, and — when the server supports management — `registration_access_token` + `registration_client_uri`. Error codes: `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement`. `jwks`/`jwks_uri` are mutually exclusive; `software_statement` is a pre-signed JWT string the server verifies.
- **RFC 7592** — Dynamic Client Registration Management Protocol: `GET` (read), `PUT` (update; server MAY rotate the secret), `DELETE` (unregister → 204) on `registration_client_uri`, authorized with the `registration_access_token` (usable ONLY on that URI, never on other endpoints). Errors additionally include `invalid_token`, `unauthorized_client`.
- **FAPI 2.0 / Brazil alignment:** Brazil Open Banking DCR uses PS256-signed software statements; the library accepts the statement as an opaque string, so callers satisfy this by building the JWT themselves (go-jose is already a dependency). The conformance suite exercises both registration and the full client-configuration lifecycle (`CallClientConfigurationEndpoint`, `UnregisterDynamicallyRegisteredClient...` conditions in the vendored v5.1.41).

**Tech Stack:** Go, `rp` package, existing primitives — issuer discovery via `clientConfig` (same as `NewIntrospector`/`NewGrantManager`), `OAuthError` for coded error bodies, raw-payload-preserving response types (`IntrospectionResponse`/`GrantStatus` pattern), `go-cmp` for tests.

**Dependencies:** none. `metadata.Provider.RegistrationEndpoint` (+ MTLS alias) already parses from discovery; the missing merge support is Task 1.

**Scope (non-goals):**

- No server-side (AS) registration endpoint — Lanyard is a relying-party library.
- No software-statement signing helper (statement passed through verbatim; note in godoc points at go-jose).
- No automatic registration persistence or background secret-rotation scheduling — the caller stores the `ClientRegistration` and decides when to update.
- No federation-entity registration (OpenID Federation has its own mechanism; separate effort if ever needed).
- Conformance-suite wiring for the existing `oidcc-client-dynamic-certification-test-plan` is an investigation task (Task 9), not implementation.

---

## Design Decisions

### D1: `ClientMetadata` is the wire-faithful request type

```go
type ClientMetadata struct {
    RedirectURIs        []string          `json:"redirect_uris,omitempty"`
    TokenEndpointAuthMethod AuthMethod    `json:"token_endpoint_auth_method,omitempty"`
    GrantTypes          []string          `json:"grant_types,omitempty"`
    ResponseTypes       []string          `json:"response_types,omitempty"`
    ClientName          string            `json:"client_name,omitempty"`
    ClientURI           string            `json:"client_uri,omitempty"`
    LogoURI             string            `json:"logo_uri,omitempty"`
    Scope               string            `json:"scope,omitempty"`
    Contacts            []string          `json:"contacts,omitempty"`
    JWKSURI             string            `json:"jwks_uri,omitempty"`
    JWKS                json.RawMessage   `json:"jwks,omitempty"`
    SoftwareID          string            `json:"software_id,omitempty"`
    SoftwareVersion     string            `json:"software_version,omitempty"`
    SoftwareStatement   string            `json:"software_statement,omitempty"`
}
```

Client-side validation (RFC 7591 §2/§3.1): reject `jwks`+`jwks_uri` both set; require `redirect_uris` unless `grant_types` is exactly `["client_credentials"]`; unknown enum values left to the server (its `invalid_client_metadata` is the authority).

### D2: `Registrar` follows the `NewIntrospector` construction pattern

`NewRegistrar(ctx, issuer, opts...)` — discovers metadata, requires `registration_endpoint`, does **not** require client credentials (none exist yet). Rejects `AuthCodeOption`s like its siblings. New option `WithInitialAccessToken(token)` sets the Bearer token for open-but-protected registries. Reuses `clientConfig` (httpClient, metadataClient, logger).

### D3: `ClientRegistration` response type — typed fields + raw preservation

Fields: `ClientID`, `ClientSecret`, `ClientIDIssuedAt *int64`, `ClientSecretExpiresAt *int64` (**0 means "does not expire"** per RFC 7591 §3.2.1 — kept as-is, semantics documented), `RegistrationAccessToken`, `RegistrationClientURI`, plus the echoed metadata fields (`RedirectURIs`, `GrantTypes`, `ResponseTypes`, `TokenEndpointAuthMethod`, `Scope`, `ClientName`, `JWKSURI`, `SoftwareID`, `SoftwareVersion`). Custom `UnmarshalJSON` preserves `raw` for `DecodeRaw` — the server response is the single source of truth for what was accepted.

Ergonomics helpers:
- `(r ClientRegistration) SecretExpired(now time.Time) bool` — false when secret empty or `client_secret_expires_at` is 0.
- `(r ClientRegistration) Manageable() bool` — both `RegistrationClientURI` and `RegistrationAccessToken` present (RFC 7592 §1.1 requires the pair).

### D4: RFC 7592 as explicit-argument methods, not stateful client

`Register` returns everything needed; the caller persists `RegistrationClientURI` + `RegistrationAccessToken` alongside credentials. Management methods on `Registrar` take them explicitly:

- `Read(ctx, registrationClientURI, accessToken) (ClientRegistration, error)` — GET → 200
- `Update(ctx, registrationClientURI, accessToken, meta ClientUpdate) (ClientRegistration, error)` — PUT with `client_id` + metadata → 200; returned registration carries any rotated secret
- `Delete(ctx, registrationClientURI, accessToken) error` — DELETE → 204
- `ClientUpdate` embeds `ClientMetadata` + `ClientID` (PUT MUST carry `client_id`, RFC 7592 §2.2)

Stateful alternative rejected: management tokens can outlive process restarts; explicit arguments keep the API honest about what must be persisted.

### D5: Errors reuse `OAuthError` + one new sentinel

`ErrRegistrationFailed` wraps every failure. RFC 7591/7592 coded JSON bodies map to `*OAuthError` (extend its doc comment to cover registration error codes) — same `errors.As` ergonomics as token endpoints. 201/200/204 enforced exactly; other statuses → status-text error. 401/403 include the `WWW-Authenticate` challenge text in the message.

### D6: No client auth on registration calls

Registration endpoints are protected by initial/registration access tokens, not OAuth client auth — no auth-method negotiation, no DPoP. `Authorization: Bearer` only. Document this in the package doc.

### D7: Bridging into `rp.New` via plain option extraction

`(r ClientRegistration) Options() []Option` returns `WithClientID(r.ClientID)` plus `WithClientSecret` when a secret was issued — the two-argument splice into `New(ctx, issuer, append(reg.Options(), ...)...)`. No magic: the caller still supplies redirect URI, scopes, key material, etc.

### D8: Example-RP demo endpoint

`POST /register?issuer=...&client_name=...` on `cmd/example-rp` registers a client using env-configured redirect URIs + `TokenEndpointAuthMethod = client_secret_basic`, renders the issued credentials + registration management info (and warns to store them — demo only, nothing persisted server-side). GET on `/register` renders an HTML form for manual playing. Reuses the `handleGrantsWithBuild`-style injectable-core pattern for tests.

---

## Tasks

### Task 1: Registration endpoint merge support

**Files:** `rp/rp.go`, `rp/rp_test.go`

1. `mergeProvider` currently does not merge `RegistrationEndpoint` (verified missing). Add `mergeString` for it (both the `AuthorizationServer` field and the `MTLSEndpointAliases.RegistrationEndpoint` alias).
2. Extend the `providerWithMergeFields` helper + one merge case.
3. Commit: `fix(rp): merge registration_endpoint in provider metadata`

### Task 2: `ClientMetadata` + validation

**Files:** new `rp/dynamic_registration.go`, new `rp/dynamic_registration_test.go`

1. `ClientMetadata` struct (D1) with `validate()` (jws/jwks_uri exclusion, redirect_uris rule).
2. Table tests for validation incl. client_credentials-only exemption.
3. Commit: `feat(rp): client metadata for dynamic registration`

### Task 3: `ClientRegistration` response type

**Files:** `rp/dynamic_registration.go`, `rp/dynamic_registration_test.go`

1. Struct + `UnmarshalJSON` raw preservation + `DecodeRaw` + `SecretExpired` + `Manageable` (D3).
2. Tests: full RFC 7591 §3.2.1 example JSON decodes field-by-field (including `client_secret_expires_at: 0` semantics), `DecodeRaw` round-trip, expiry math.
3. Commit: `feat(rp): client registration response type`

### Task 4: `Registrar.Register` (RFC 7591)

**Files:** `rp/dynamic_registration.go`, `rp/dynamic_registration_test.go`, `rp/options.go` (`WithInitialAccessToken`)

1. `NewRegistrar` (D2) + `WithInitialAccessToken`.
2. `Register`: POST JSON, `Accept: application/json`, Bearer when configured; exactly 201; parse into `ClientRegistration`; error mapping per D5 (incl. `invalid_software_statement`).
3. Tests: request shape (body fields + headers, both with/without initial token), happy path, each error code → `*OAuthError` + `ErrRegistrationFailed`, missing endpoint at construction, non-201 rejection.
4. Commit: `feat(rp): dynamic client registration (RFC 7591)`

### Task 5: Registration management (RFC 7592)

**Files:** `rp/dynamic_registration.go`, `rp/dynamic_registration_test.go`

1. `ClientUpdate` + `Read`/`Update`/`Delete` (D4); 200/200/204 enforcement; `invalid_token`/`unauthorized_client`/404 mapping.
2. Tests: GET reads rotated state, PUT rotates secret (assert returned secret differs, `SecretExpired` false), DELETE → 204 then subsequent GET → 404 surfaced, 401 with `WWW-Authenticate` text, PUT body includes `client_id`.
3. Commit: `feat(rp): dynamic registration management (RFC 7592)`

### Task 6: `ClientRegistration.Options` bridge

**Files:** `rp/dynamic_registration.go`, `rp/dynamic_registration_test.go`

1. `Options()` (D7) — with/without issued secret variants.
2. Test: `New(ctx, issuer, append(reg.Options(), WithRedirectURI(...), ...)...)` produces a working RP against a stub AS (reuse the callback test issuer pattern).
3. Commit: `feat(rp): build RP options from client registration`

### Task 7: Example-RP demo endpoint

**Files:** `cmd/example-rp/dynamic_registration.go`, `cmd/example-rp/dynamic_registration.go` tests, `cmd/example-rp/main.go` (routes + root link)

1. `POST /register` + `GET /register` form (D8); issuer from query/env; validation of RFC 7591 combos surfaced as 400s.
2. Tests via injectable registrar core: success render, upstream error mapping, invalid metadata 400.
3. Commit: `feat(example-rp): dynamic registration demo endpoint`

### Task 8: Documentation + public API

**Files:** `SPECIFICATIONS.md`, `README.md`, `rp/doc.go`, `rp/public_api_external_test.go`

1. SPECIFICATIONS: new RFC 7591 + RFC 7592 section (feature table incl. MTLS alias, software statement passthrough) + summary-table row.
2. `rp/doc.go`: "Dynamic client registration" section (register → `Options()` → `New`; management lifecycle; token caveats: initial token vs registration access token; secret expiry).
3. README capability bullet.
4. External compile test: `ClientMetadata`, `ClientRegistration`, `ClientUpdate`, `Registrar`, `NewRegistrar`, `WithInitialAccessToken`, `ErrRegistrationFailed`, method values (no calls on nil pointers — use method values only).
5. Commit: `docs: dynamic client registration capabilities`

### Task 9 (investigation): DCR conformance wiring

The vendored suite ships `oidcc-client-dynamic-certification-test-plan` (client profile "Dynamic RP": webfinger/discovery + `rp-registration-dynamic` + request_uri + key rotation modules; variant `client_registration=dynamic_client`, which the suite marks incompatible with `static_client`). The harness already supports forced variants (`parseForcedVariants`) and registers clients per-alias (`conformanceRuntimes`).

Write `thoughts/research/2026-08-29-dcr-conformance-wiring.md` covering: what the plan requires of the example RP (self-register per alias at startup, use returned credentials for login + request_uri hosting, survive key-rotation modules), what harness/preset changes would be needed (add to `oidcExplicitPlans`? new preset `oidc-rp-dynamic`? provisioning of `registration_endpoint` in suite config), and effort estimate. Implementation only if findings say low-friction.

---

## Verification

- `gofumpt -w . && go vet ./... && go test ./...` after every task; `go test -race ./rp/` before the docs commit.
- Decode the verbatim RFC 7591 §3.2.1 example response in tests.
- Public API external compile test stays green (nil-pointer rule: method values only).
- Commit messages follow the conventional-commit style used throughout master.
