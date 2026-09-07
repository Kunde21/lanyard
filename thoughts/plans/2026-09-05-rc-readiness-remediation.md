# RC Readiness Remediation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**STATUS: COMPLETE 2026-09-05.** All 12 tasks landed in commits 374e643..de030dd (12 atomic commits, one per task); full suite + race green; every fix carries regression tests per the goal. Remaining review suggestions intentionally deferred: production-shaped runnable example app and fuzzed callback/token parsing (release-work section) - tracked for the RC polish pass.

**Source:** `thoughts/reviews/stable-rc-readiness-3e4826a.md` (review of `3e4826a`).
**Goal:** Resolve all P1 findings and the tractable P2 findings, each with regression tests, gated commits, and the review's release gates in mind.

## Task order (dependency + risk)

### T1 (F2+F6, idtoken policy cluster)
- Honor explicit `WithAllowUnsecuredIDTokens(false)` even for non-FAPI: track explicit-set flag; `finalizeSecurityDefaults` only fills when unset.
- Unsigned branch enforces advertised-alg membership (if advertised list non-empty and lacks "none" → reject) before the allow-unsecured branch.
- Remove `local-dev-client-2` advertised-alg bypass; keep encrypted-token path but apply inner-token alg policy. Update example-rp conformance client-2 usage if tests surface legitimate needs (verify against advertised lists).
- Tests: explicit-false rejects none-token; client-2 no longer bypasses; encrypted inner token checked.

### T2 (F5, preloaded metadata ≠ no discovery)
- `validateIDToken`: when `r.providerSet` and provider has JWKSURI → `RemoteKeySetFromJWKSURI` directly; discovery-based path only when provider not pre-resolved. Keep rotation fallback.
- Test: complete `WithProviderMetadata` + `DiscoveryDisabled`, issuer 404s discovery, JWKS served → callback succeeds.

### T3 (F12, error causes)
- Replace `%v` cause-wraps with `%w` at: client_credentials.go Token, refresh_token.go (non-invalid_grant path), rp.go discovery wrap, token_exchange.go decode error.
- Verify `errors.As(*OAuthError)` works through ClientCredentials.Token and RefreshToken.
- Tests: errors.Is/As through public entrypoints.

### T4 (F4, CallbackResult lifecycle)
- Add `CallbackResult.Token *Token` (full response incl. refresh/ID token/expiry/grant_id) and `CallbackResult.Issuer string`; keep existing fields.
- Set in both FAPI and standard paths. Test: refresh token + ID token reachable via result; doc example updated.

### T5 (F9, client credentials auth gaps)
- Implement `AuthMethodClientSecretJWT` in client-credentials request builder (shared `buildClientSecretJWTAssertion`).
- Auto-selection filters advertised methods by available credentials (secret vs key provider).
- Test: matrix per grant × auth method (supported combos succeed, unsupported rejected at construction).

### T6 (F10, Token persistence)
- `Token.UnmarshalJSON`: explicit lifecycle fields win over raw; raw fills only zero fields. Synthesized refresh survives round-trip.
- Tests: rotate/no-rotate responses → marshal → unmarshal preserves effective values.

### T7 (F8, optional UserInfo)
- Callback skips userinfo when provider lacks userinfo_endpoint (nil UserInfo, success). Keep subject-match when called.
- Test: signed ID token callback, no userinfo endpoint → success.

### T8 (F3, concurrent RP safety)
- Stop mutating shared RP fields in callbacks: per-callback transaction RP built field-wise (no struct copy — mutex safety), carrying correlation-supplied issuer/clientID/secret/provider overrides.
- Fix memory-store map read races (`store.go:95-108,158-176`): clone under lock.
- Test: N concurrent AuthorizationURL+HandleCallback on one RP under -race.

### T9 (F7, FAPI profile enforcement)
- Construction-time validation for FAPI profiles: asymmetric client auth (private_key_jwt/tls) OR mtls sender-constrain; PAR or signed request object; reject secrets with FAPI unless mtls-constrained appropriately; unknown `WithRequestMethod` values error.
- Tests: insecure FAPI configs rejected; valid conformance-shaped config accepted.

### T10 (F1, default store browser binding)
- Default state store becomes cookie-bound memory: AuthorizationURL sets a random binding cookie; correlation records bind state→cookie value; ConsumeCorrelation requires match. Defeats login-CSRF cross-browser handoff.
- Two-browser regression test (attacker cookie ≠ victim cookie → consume fails).
- Memory store: bounded capacity + sweep of expired entries on access.

### T11 (F11, cookie consumption replay + payload growth)
- Cookie store marks consumed states inside the payload cookie (server-verifiable on replay); prune abandoned states.
- Test: same cookie replayed in two fresh requests → second consume fails.

### T12 (docs/infra follow-ups)
- README production example without printed tokens; TokenSource clarification; HTTP deadline/size-limit defaults note; SUPPORT/SECURITY policy docs; CI workflow (test/vet/race/examples). Record in docs; separate commits.

## Verification
Per task: `go test ./... > log; grep -q "^FAIL"` gate, race on touched packages, conventional commit, both remotes. After T10: rerun full conformance presets affected (oidcc smoke) to prove no regression in bound-default flows.
