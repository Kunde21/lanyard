# FEATURE-003: Basic RP Test Profile Implementation Plan

## Overview

Implement a conformance-capable example OpenID Connect Relying Party (RP) in this repo and verify it locally against the OpenID conformance suite profile `OpenID Connect Core: Basic Certification Profile Relying Party Tests`.

The implementation adds a new `rp/` package that performs the protocol flow (Authorization Code + PKCE), using existing `oidc/` discovery and `jwks/` primitives. The example app (`cmd/example-rp`) becomes thin HTTP wiring exposing `/`, `/login`, and `/callback`.

This plan is written TDD-first: every phase starts by adding failing tests, then implementing until green.

## Current State Analysis

- The example RP is a placeholder and does not implement any OIDC protocol flow behavior (`cmd/example-rp/main.go:9-31`).
- Discovery + caching + metadata validation are implemented and should be reused (`oidc/discovery.go:14-62`, `oidc/http_fetch.go:72-113`, `oidc/validate.go:102-167`).
- JWKS remote key fetching and refresh-on-unknown-kid are implemented and should be reused for signature verification (`jwks/remote_keyset.go:64-127`, `oidc/jwks.go:10-31`).
- Local conformance stack terminates TLS at Caddy and routes `rp.test` to the `rp` container, where the example RP listens on `:8080` (`conformance/Caddyfile:6-9`, `conformance/docker-compose.yml:22-29`).
- Current conformance runbook documents an expected-failing run and indicates likely failures due to missing protocol logic (`conformance/README.md:77-92`).

## Desired End State

After completing this plan:

- `cmd/example-rp` implements a Basic RP profile with:
  - `/login` to initiate Authorization Code flow with PKCE (S256), `state`, and `nonce`.
  - `/callback` to validate `state`, exchange `code` at the token endpoint, validate the ID token, call UserInfo, and render a minimal result page.
- Running the local conformance suite against `https://rp.test/callback` passes the full test plan for `OpenID Connect Core: Basic Certification Profile Relying Party Tests` (including required negative/failure coverage).
- We capture local evidence artifacts (suite export ZIP + recorded profile/plan/test identifiers) and provide a runbook so another engineer can reproduce the run.

### Success Criteria

#### Automated Verification
- [x] Unit/integration tests pass: `go test ./...`
- [x] No vet issues: `go vet ./...`
- [x] Code formatted: `gofumpt ./...`
- [x] Module builds: `go build ./...`

#### Manual Verification
- [ ] Using the existing local stack, run the suite profile against `https://rp.test/callback` and obtain passing results for the target plan.
- [ ] Save evidence artifacts locally (suite export ZIP) and record:
  - profile name
  - plan ID
  - test IDs and their final statuses
- [ ] Confirm negative/failure tests are handled by strict rejection (not permissive parsing/acceptance).
- [ ] Follow the updated runbook end-to-end on a clean local environment.

## Key Discoveries

- Discovery and JWKS layers exist and are reliable building blocks; protocol flow is currently missing.
  - Discovery fetch + SWR caching: `oidc/discovery.go:14-62`
  - HTTP error handling with capped body preview: `oidc/http_fetch.go:102-105`
  - JWKS refresh logic and unknown-kid behavior: `jwks/remote_keyset.go:91-127`
- Local conformance routing assumes the RP is reached at `https://rp.test` and forwards to a service on `:8080`.
  - Caddy routes: `conformance/Caddyfile:6-9`
  - Compose wiring: `conformance/docker-compose.yml:22-29`
- The suite typically exports test results via a UI “publish/certification package” flow; we will treat that downloadable ZIP as the primary evidence artifact to save locally.

## What We're NOT Doing

- Advanced profiles/specs (PAR, JAR, JARM, FAPI).
- Hybrid/implicit flows (only Authorization Code).
- RP-initiated logout/session management.
- Refresh token grant coverage.
- Dynamic client registration.
- CI integration of the conformance suite.
- New containerization work beyond the existing `conformance/` environment.

## Implementation Approach

- Add a new `rp/` package that:
  - wraps/uses `oidc.Client` discovery and `jwks.RemoteKeySet` to implement the protocol flow.
  - exposes a small API for the example RP to call (build auth URL; handle callback).
  - keeps storage pluggable but ships with an in-memory default suitable for conformance.
- Keep `cmd/example-rp` as thin HTTP wiring. It should not contain protocol logic.
- TDD-first per phase:
  - write tests that fail
  - implement minimal code to pass
  - refactor while keeping tests green

## Phase 1: Introduce `rp/` Package Skeleton (TDD)

### Overview

Create `rp/` as the protocol package with minimal configuration and options, without implementing network calls yet.

### Changes Required

#### 1. `rp` public API + options
**Files**:
- `rp/rp.go`
- `rp/options.go`
- `rp/errors.go`

**Tests first**:
- `rp/rp_test.go`
  - constructing an RP with required inputs
  - options validation (issuer, redirect URI, client id)
  - default behaviors (e.g., default scopes = `openid`)

**Implementation**:
- `rp.New(...)` should accept issuer/client credentials and hold references to:
  - an `oidc.Client` (injected or default)
  - a logger and HTTP client as options
  - redirect URI, scopes

### Success Criteria

#### Automated Verification
- [x] `go test ./...` (new `rp/` tests compile and pass)

#### Manual Verification
- [x] `go doc ./...` shows doc comments for exported `rp` identifiers.

---

## Phase 2: State/Nonce/PKCE + Authorization URL Builder (TDD)

### Overview

Implement flow initiation primitives and build the authorization URL with PKCE (S256), `state`, and `nonce`.

### Changes Required

#### 1. PKCE utilities
**Files**:
- `rp/pkce.go`

**Tests first**:
- `rp/pkce_test.go`
  - verifier length/charset
  - S256 challenge correctness against a fixed test vector
  - rejection of invalid verifier inputs (if applicable)

**Implementation**:
- generate `code_verifier` with `crypto/rand`
- compute `code_challenge = BASE64URL(SHA256(verifier))`

#### 2. State store (in-memory default)
**Files**:
- `rp/state_store.go`
- `rp/memory_state_store.go`

**Tests first**:
- `rp/state_store_test.go`
  - save/get/delete
  - TTL expiry
  - concurrent access safety (basic concurrency test)

#### 3. Authorization request builder
**Files**:
- `rp/authrequest.go`

**Tests first**:
- `rp/authrequest_test.go`
  - builds URL containing required params: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`
  - uses provider `authorization_endpoint` from discovery
  - deterministic encoding assertions (query parameters present, not exact ordering)

**Implementation**:
- call `oidc.Client.DiscoverProvider(ctx, issuer)` to obtain `AuthorizationEndpoint` (`oidc/discovery.go:14-37`)
- store `state -> {nonce, code_verifier, created_at}`

### Success Criteria

#### Automated Verification
- [x] `go test ./...`

#### Manual Verification
- [ ] Running the example RP and visiting `/login` produces a redirect to the suite’s authorization endpoint (during conformance).

---

## Phase 3: Example RP HTTP Wiring (`/`, `/login`, `/callback`) (TDD)

### Overview

Wire `cmd/example-rp` endpoints to `rp/` while keeping UI minimal.

### Changes Required

#### 1. HTTP handlers
**File**: `cmd/example-rp/main.go`

**Tests first**:
- `cmd/example-rp/main_test.go`
  - GET `/` returns a simple info page (and link to `/login`)
  - GET `/login` returns 302 redirect
  - GET `/callback` missing parameters yields 400 with non-sensitive message
  - GET `/callback` invalid/missing state yields 400

**Implementation**:
- `/` should not start the flow; it should present a tiny page linking to `/login`
- `/login` calls into `rp/` to construct auth URL and redirects
- `/callback` parses `code`/`state` (and `error` parameters), then calls into `rp/` callback handling

### Success Criteria

#### Automated Verification
- [x] `go test ./...`

#### Manual Verification
- [ ] `https://rp.test/` loads and offers `/login`
- [ ] `/login` redirects to the suite OP

---

## Phase 4: Token Exchange (TDD)

### Overview

Implement Authorization Code exchange at the token endpoint.

### Changes Required

#### 1. Token exchange client
**Files**:
- `rp/token.go`
- `rp/token_exchange.go`

**Tests first**:
- `rp/token_exchange_test.go`
  - uses `application/x-www-form-urlencoded`
  - includes `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`
  - uses `client_secret_basic` by default (Basic Auth header)
  - handles non-200 with bounded response preview (similar to `oidc/http_fetch.go:102-105`)

**Implementation**:
- POST to `ProviderMetadata.TokenEndpoint`
- parse JSON response into struct with at least: `access_token`, `token_type`, `expires_in`, `id_token`

### Success Criteria

#### Automated Verification
- [x] `go test ./...`

#### Manual Verification
- [ ] Successful `/callback` run exchanges code and proceeds to ID token validation.

---

## Phase 5: ID Token Validation (TDD)

### Overview

Verify ID token signature and required claims for the Basic RP profile.

### Changes Required

#### 1. ID token validation
**Files**:
- `rp/idtoken.go`

**Tests first**:
- `rp/idtoken_test.go`
  - signature verification using a JWKS served by `httptest` and a signed token
  - claim validation table:
    - `iss` equals discovered issuer
    - `aud` contains client id
    - `exp` not expired (with skew)
    - `iat` reasonable (with skew)
    - `nonce` matches stored nonce
    - `azp` enforced when multiple audiences
  - negative cases must fail closed

**Implementation**:
- parse JWS via `go-jose`
- select key by `kid` via `oidc.Client.RemoteKeySet(...)` and `RemoteKeySet.Key(...)` (`oidc/jwks.go:10-31`, `jwks/remote_keyset.go:91-127`)
- validate claims with configurable clock skew

### Success Criteria

#### Automated Verification
- [x] `go test ./...`

#### Manual Verification
- [ ] Conformance tests expecting ID token rejection on invalid claims/signature pass.

---

## Phase 6: UserInfo Client + Validation (TDD)

### Overview

Call UserInfo using the access token and validate the response.

### Changes Required

#### 1. UserInfo client
**Files**:
- `rp/userinfo.go`

**Tests first**:
- `rp/userinfo_test.go`
  - sends `Authorization: Bearer <token>`
  - parses JSON response
  - validates `sub` equals ID token `sub`
  - handles non-200 and invalid JSON

**Implementation**:
- GET `ProviderMetadata.UserinfoEndpoint`
- decode JSON; enforce `sub` match

### Success Criteria

#### Automated Verification
- [x] `go test ./...`

#### Manual Verification
- [ ] Conformance tests that require UserInfo usage pass.

---

## Phase 7: Negative Handling, Determinism Hardening, and Runbook + Evidence

### Overview

Ensure strict failure behavior for negative tests, reduce flakiness, and document the passing run and evidence capture.

### Changes Required

#### 1. Error handling and HTTP responses
**Files**:
- `rp/errors.go`
- `cmd/example-rp/main.go`

**Tests first**:
- table tests that ensure:
  - missing/invalid `state` rejected
  - missing `code` rejected
  - token endpoint error rejected
  - ID token invalid rejected
  - UserInfo `sub` mismatch rejected
  - no secrets in error bodies

**Implementation**:
- map errors to HTTP 400/500 consistently
- cap any error-body previews
- avoid logging tokens/secrets

#### 2. Runbook updates + evidence capture
**File**: `conformance/README.md`

**Changes**:
- Update from “expected failing” to “passing” workflow.
- Document exact suite configuration values we support (redirect URI, response type, token auth method).
- Document how to capture evidence:
  - keep the suite UI open until finished
  - export/download the suite results ZIP (“publish/certification package” flow)
  - record the plan ID and the test IDs + statuses into a local file under `conformance/artifacts/` (gitignored)
- Document cleanup steps and warnings about ephemeral Mongo data.

### Success Criteria

#### Automated Verification
- [x] `go test ./...`

#### Manual Verification
- [ ] Local conformance run passes; evidence ZIP + recorded IDs are saved.

---

## Testing Strategy

### Unit Tests
- PKCE: verifier/challenge generation and encoding.
- State store: TTL, concurrency.
- Authorization URL builder: required query parameters.
- Token exchange: request shape + auth method + error mapping.
- ID token validation: signature + claim enforcement.
- UserInfo: request auth + JSON parsing + `sub` matching.

### Integration Tests (Mock HTTP)
- Use `httptest` to simulate OP endpoints:
  - discovery document
  - token endpoint
  - jwks endpoint
  - userinfo endpoint

### Manual Testing Steps
1. Start conformance stack: `docker compose -f conformance/docker-compose.yml up -d`
2. Confirm RP reachable: open `https://rp.test/` and click `/login`.
3. In suite UI, create and run `OpenID Connect Core: Basic Certification Profile Relying Party Tests` with redirect URI `https://rp.test/callback`.
4. Iterate until all tests reach an acceptable final status.
5. Export/download the suite evidence ZIP and record plan/profile/test IDs.

## Performance Considerations

- Prioritize correctness over performance.
- Avoid stampedes by relying on existing discovery/JWKS caching (`oidc/discovery.go:14-62`, `jwks/remote_keyset.go:64-89`).
- Add reasonable HTTP timeouts in the RP package via injected `http.Client` (example RP should set one).

## Migration Notes

- This introduces a new `rp/` package and expands `cmd/example-rp` behavior. No existing public APIs are removed.

## References

- Original ticket: `thoughts/tickets/feature_basic_rp_test_profile.md`
- Related research: `thoughts/research/2026-02-22_basic_rp_conformance_profile.md`
- Conformance local setup plan: `thoughts/plans/openid_conformance_local.md`
- Conformance runbook: `conformance/README.md`
- Example RP entrypoint: `cmd/example-rp/main.go`
