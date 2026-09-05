# OpenTelemetry Tracing Instrumentation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:execing-plans to implement this plan task-by-task.

**Goal:** Add OpenTelemetry tracing to the `rp` and `metadata` packages: spans for every public operation and its meaningful internal phases (discovery, JWKS, authorization request construction, PAR, callback processing, token exchange with fallbacks, ID token validation, userinfo, refresh/rotation, introspection, grant management, DCR), events for notable protocol steps — with a hard guarantee that **no secret or PII value ever enters a span**.

**Guiding spec/conventions:**

- **OTel Go library guidelines**: libraries depend on the OTel *API* only (`go.opentelemetry.io/otel`, `.../otel/trace`), never on the SDK or exporters; obtain the tracer from a caller-supplied `TracerProvider` or the global provider (no-op by default → zero configuration, near-zero overhead when unused).
- **Semantic conventions** (loosely, where applicable): `http.request.method`, `http.response.status_code`, scheme/host/path URL components — never `url.query`.
- The existing `WithLogger`/`slog` surface stays orthogonal and untouched.

**Tech Stack:** Go; `go.opentelemetry.io/otel` + `go.opentelemetry.io/otel/trace` (runtime); `go.opentelemetry.io/otel/sdk` + `sdk/trace/tracetest` (test-only, span recorder).

**Dependencies:** none blocking. New module requires the three OTel modules (API is dependency-light; trace propagators not needed — the library creates spans only).

**Scope (non-goals):**

- No exporters, SDK setup, or sampler configuration in the library (caller's job).
- No metrics (spans carry counts/durations; metrics can be a follow-up).
- No context propagation changes: spans attach to the caller's `ctx` where one exists.
- No tracing of the example-RP HTTP dump logger — but that logger currently dumps full requests/responses (tokens included) at Info level; Task 8 gates it behind `RP_HTTP_DUMP=true` (default off), out-of-band hardening consistent with this plan's theme.

---

## Design Decisions

### D1: API-only tracer, provider injection, inheritable

`clientConfig` (and `metadata.Client`) gain a `trace.Tracer` created from a `trace.TracerProvider`. New options:

- `rp.WithTracerProvider(tp trace.TracerProvider) Option` (default `otel.GetTracerProvider()` → no-op tracer),
- `metadata.WithTracerProvider(tp) Option` for the metadata client (discovery + JWKS spans).

Tracer names: full import path (`github.com/Kunde21/lanyard/rp`, `.../metadata`). All `clientConfig`-derived clients (`Introspector`, `GrantManager`, `Registrar`) inherit the tracer automatically. When the tracer is a no-op, `tracer.Start` returns a non-recording span — code paths stay allocation-light and unconditional (no `Enabled()` branching beyond what otel itself does).

### D2: Span vocabulary

Tracer-scoped, stable span names (dash-case, `<pkg>.<operation>`):

- metadata: `metadata.discovery` (oidc/oauth2/auto mode attribute), `metadata.jwks_fetch`, `metadata.jwks_refresh` (key-rotation fallback path).
- rp authz request: `rp.authorization_url` → children `rp.par_request`, `rp.signed_request_object`, `rp.request_uri_store`.
- rp callback: `rp.handle_callback` → children `rp.authorization_response` (mode: query/jarm/form_post), `rp.state_validation`, `rp.token_exchange`, `rp.id_token_validation` (attributes: decrypted, alg, kid — **never the token**), `rp.userinfo` (attributes: transport, signed_response bool).
- grants: `rp.refresh_token` (+ event `rotation`), `rp.client_credentials`, `rp.token_exchange`, `rp.introspection` (attributes: response_mode json/jwt, jwt_encrypted bool, active bool), `rp.grant_query`, `rp.grant_revoke`.
- DCR: `rp.registration_register`, `rp.registration_read`, `rp.registration_update` (+ event `secret_rotated`), `rp.registration_delete`.
- DPoP: `rp.dpop_proof` child spans under any endpoint call that attaches one (+ event `nonce_challenge_retry` under the parent).

### D3: Attributes — identifiers and enums only

Allowed attribute kinds: booleans, small enums, counters, HTTP status codes, scheme/host/path, issuer, client_id, scopes list, algorithms, key IDs, durations (implicit). Custom keys under the `lanyard.` prefix where no semconv fits (e.g. `lanyard.auth_method`, `lanyard.fallback`, `lanyard.rotation`). `grant_id` is an identifier (like client_id) — allowed. `sub` is PII — **not** recorded anywhere.

### D4: Secrets never recorded — enforced taxonomy

Never in attributes, events, or `RecordError` payloads:

| Category | Examples |
|---|---|
| Credentials | client_secret, registration_access_token, initial access token |
| Tokens | access/refresh/ID tokens, introspected token value, userinfo/ID token payloads, verified_claims values |
| Flow secrets | authorization code, PKCE verifier, state, nonce, DPoP proofs + nonce, client_assertion JWTs, signed request objects, cookies |
| Crypto | private keys, JWK private material |
| URLs with query | authorization redirect (carries state/nonce/challenge), discovery URLs are query-free and safe |

Error handling: HTTP-transport errors embed response previews (bodies may contain tokens) → record **only** the sentinel name (`errors.Is` check against the exported sentinel set) + `http.response.status_code`; validation errors with static messages may be recorded verbatim. URLs recorded as scheme://host/path only (query stripped by construction, never string-scrubbed after the fact).

### D5: Events for protocol milestones

`AddEvent` at: auth-method post→basic fallback, DPoP nonce challenge + retry, refresh rotation received/rejected (`invalid_grant`), ID token decryption performed, signed-userinfo verification, JWT introspection response (mode + verification), key-refresh fallback on unknown kid, registration secret rotation, grant management action type. Events carry the same attribute rules.

### D6: Testing — recorder + sentinel sweep

Unit tests use `sdk/trace/tracetest` with a `span.Recorder`:

1. **Coverage assertions**: each flow's test asserts the expected span tree (names + parent links) and milestone events.
2. **Sentinel sweep (the core guarantee)**: flows run with deliberately distinctive secret fixtures (`SECRET-ACCESS-TOKEN`, `SECRET-REFRESH`, `SECRET-CLIENT`, `SECRET-STATE`, `SECRET-NONCE`, `SECRET-VERIFIER`, `SECRET-CODE`, `SECRET-ASSERTION`, `SECRET-IDTOKEN`, `SECRET-RAT` …). After the flow, walk **every recorded span's attributes and events** and assert none of the sentinel substrings appear. A shared helper (`assertNoSecrets(t, spans)`) makes the sweep one line per test and catches accidental future regressions in any attribute.

### D7: Plumbing mechanics

`trace.SpanFromContext` is never inspected; spans are always started even under no-op. Public entrypoints that lack a `ctx` parameter today (`AuthorizationURL(w, req, ...)`, `HandleCallback(w, req)`) use `req.Context()`. Internal helpers receive `ctx` explicitly (they already do for network calls).

---

## Tasks

### Task 1: Dependencies + tracer plumbing

**Files:** `go.mod`, `rp/client_config.go`, `rp/options.go`, `metadata/client options`

1. Add OTel modules (`go get go.opentelemetry.io/otel go.opentelemetry.io/otel/trace`; sdk for tests). 2. Tracer fields + `WithTracerProvider` options (rp + metadata) + defaults. 3. Test: custom provider yields spans; default yields none.
4. Commit: `feat(rp): opentelemetry tracer plumbing`

### Task 2: metadata instrumentation

**Files:** `metadata/discovery.go`, `metadata/jwks.go` (+ merge into discovery_refresh)

1. `metadata.discovery`, `metadata.jwks_fetch`, `metadata.jwks_refresh` spans with mode/issuer attributes, key-count (not keys). 2. Recorder tests incl. discovery fallback path.
3. Commit: `feat(metadata): discovery and jwks tracing`

### Task 3: Authorization request path

**Files:** `rp/authrequest.go`, `rp/par.go`, `rp/request_object.go`

1. `rp.authorization_url` + children (PAR, signed request object, request_uri store) + attributes (PAR used, JAR used, response_mode, scopes). 2. Recorder + sentinel sweep (state/nonce/verifier/request object JWT).
3. Commit: `feat(rp): authorization request tracing`

### Task 4: Callback processing

**Files:** `rp/callback.go`, `rp/idtoken.go`, `rp/userinfo.go`

1. Parent + children per D2 (authorization response mode incl. JARM, state validation, token exchange with fallback events, ID token validation — alg/kid/decrypted, userinfo incl. signed-response event). 2. Recorder tests for code-flow happy path + JARM + fallback + failure paths. 3. Sentinel sweep (code/state/nonce/id_token/access token/userinfo payload).
4. Commit: `feat(rp): callback processing tracing`

### Task 5: Grant paths

**Files:** `rp/refresh_token.go`, `rp/refresh_rotation.go`, `rp/client_credentials.go`, `rp/token_exchange.go`

1. Spans + events (rotation observed, invalid_grant rejection, fallback). 2. Tests + sweep (refresh token values, assertions).
3. Commit: `feat(rp): token grant tracing`

### Task 6: Introspection, grant management, DCR, DPoP

**Files:** `rp/introspection.go`, `rp/grant_management.go`, `rp/dynamic_registration.go`, `rp/dpop.go`

1. Spans + attributes/events per D2/D5 (response mode, encrypted JWT, active flag, registration rotation, DPoP nonce retry). 2. Tests + sweep (introspected token, registration access token, initial token, DPoP proof).
3. Commit: `feat(rp): introspection grant-management and registration tracing`

### Task 7: Consolidated sensitive-data guard

**Files:** `rp/otel_test.go` (new), shared test helper

1. `assertNoSecrets` helper + one cross-flow test running every public operation with sentinelized fixtures, asserting zero leakage across all spans. 2. Also asserts URL attributes never contain `?`.
3. Commit: `test(rp): opentelemetry sensitive data guard`

### Task 8: Example-RP hardening + docs + public API

**Files:** `cmd/example-rp/runtime_resolution.go`, `README.md`, `rp/doc.go`, `rp/public_api_external_test.go`

1. Gate the HTTP dump logger behind `RP_HTTP_DUMP` (default off — today it logs tokens at Info). 2. `rp/doc.go` "Tracing" section: how to enable, what's recorded, the secrets rule. 3. README bullet. 4. Public API compile coverage (`WithTracerProvider`).
5. Commit: `docs: opentelemetry tracing`

---

## Verification

- `gofumpt -w . && go vet ./... && go test ./...` per task; `go test -race ./rp/ ./metadata/` before Task 8.
- Default (no provider) behavior byte-identical: existing tests must pass unchanged — they are the regression net.
- Sentinel sweep green across all flows (Task 7 is the enforcement point).
- No OTel SDK/exporter imports outside `_test.go` files.
