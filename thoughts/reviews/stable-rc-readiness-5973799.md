# Second stable RC preparation review

Revision: `5973799` (clean worktree at review start).
Previous review: [stable-rc-readiness-3e4826a.md](stable-rc-readiness-3e4826a.md).

## Verdict

**Hold the RC pending the findings below.** The remediation materially improves
security and usability, but several fixes are incomplete and the browser-binding
change introduces real-browser interoperability/lifetime problems. Passing the
in-progress conformance run will not by itself close these findings.

The ongoing conformance run was not modified, restarted, or treated as complete.
No library code was changed; this report is the only repository addition.

## Validation

- `go test ./...`: 895 tests passed across 14 packages.
- `go test -race ./...`: 895 tests passed across 14 packages.
- `go vet ./...`: passed.
- Targeted public-API race reproduction: **2 data races** in memory.Store.LoadValue.
- Public-API reproductions confirmed nil Token on successful OAuth2 callback,
  restoration of cleared token fields, missing binding-cookie renewal, and FAPI2
  signed authorization without PAR.
- A shell reproduction confirmed the CI formatting gate succeeds when gofumpt
  is unavailable.
- AFT inspection was attempted twice, including a scoped attempt. Both failed with
  `writer_lease_timeout`; no clean AFT result is claimed.
- Temporary reproduction programs: `/tmp/lanyard-rc2.go` and
  `/tmp/lanyard-rc2-fapi.go`. Race output: `/tmp/lanyard-rc2-race.log`.
- Browser SameSite behavior was assessed from emitted cookie attributes and
  browser cookie semantics, not an automated Chromium/Firefox run.

## Findings

### R1 — P1: Default browser binding breaks cross-site form_post callbacks

Location: `rp/store/memory/store.go:78-85,128-131`.

The newly introduced binding cookie is explicitly SameSite=Lax. Browsers do not
send that cookie on an authorization server's cross-site POST to the callback.
ConsumeCorrelation now requires it, so an otherwise valid form_post callback is
rejected as unknown/expired state. This affects ordinary deployments with RP and
issuer on different sites and the advertised Form Post flow, including relevant
JWT response-mode variants. The memory store exposes no SameSite override.

The HTTP-level tests manually propagating cookies do not simulate SameSite
filtering and therefore cannot catch this regression.

**Fix:** choose/configure a secure binding cookie policy compatible with the
selected response mode (SameSite=None + Secure for cross-site POST), or provide
another browser-binding mechanism that works with POST. Do not remove binding.

**Regression gate:** real-browser login between two different sites using both
query and form_post callbacks. Verify that a second browser still cannot consume
another browser's correlation.

### R2 — P1: OAuth-only callbacks still discard the complete token response

Location: `rp/callback.go:207-210`; conflicting public contract at lines 36-40.

The OIDC and FAPI branches populate Token and Issuer, but the early OAuth-only
return still populates only AccessToken. A successful OAuth2 callback reproduced:

```
token nil=true issuer="" grant=""
```

The token server returned refresh_token, expires_in, token_type, and grant_id.
Consumers cannot persist/refresh these authorizations and can panic when trusting
Token's documented non-nil-on-success guarantee.

**Fix:** populate Token, Issuer, and GrantID consistently on every successful
callback path. Subject can correctly remain empty for an OAuth-only flow.

**Regression gate:** external OAuth2 login -> callback -> JSON persistence ->
NewRefreshTokenSource, in addition to the corresponding OIDC/FAPI tests.

### R3 — P1: A remaining memory-store path performs unsynchronized map access

Location: `rp/store/memory/store.go:248-268`, especially line 266.

LoadValue clones the value while holding RLock, then re-reads entry.values[name]
after releasing the lock when the cloned value is nil. A nil stored value or
missing key is entirely valid input. SaveValue/DeleteValue can mutate the map in
parallel, causing a race and potentially a fatal concurrent-map panic.

A two-goroutine external consumer repeatedly saving nil and loading the same key
reported **2 data races**, both at the post-unlock map lookup. The full repository
race suite remains green because this input/path is not covered concurrently.

**Fix:** capture both value and presence under the same read lock; never read the
shared map afterward. Test nil, absent, empty non-nil, and ordinary byte values
concurrently with saves/deletes.

A related source-level gap remains in `rp/par.go:89,98`: these reads access
resolvedAuthMethod directly despite writes using methodMu. Use one locked auth
method snapshot per PAR request and add concurrent PAR/callback coverage. This
PAR-specific race was identified by source inspection, not the reproduction above.

### R4 — P1: FAPI2 still accepts signed requests instead of mandatory PAR

Location: `rp/rp.go:94-95,459-465`, `rp/authrequest.go:154-185`.

The new validator uses one generic "PAR OR signed request" rule for all FAPI
profiles. FAPI 2.0 Security Profile requires PAR; a front-channel signed request
object is not a substitute. FAPI2 defaults select signed requests, so this is not
limited to a consumer explicitly opting out of security.

An external consumer configured FAPI2SecurityProfile, private_key_jwt with an
ES256 key, and DPoP against a provider with no PAR endpoint. Construction and
AuthorizationURL both succeeded, producing request=<JWT> without request_uri.

**Fix:** validate profile-specific requirements. Require PAR and the necessary
endpoint for FAPI2 Security Profile and profiles building on it; keep FAPI1's
requirements separate. Validate the effective behavior, not just configuration
flags. This finding establishes incomplete profile enforcement, not an arbitrary
signature/authentication bypass.

**Regression gate:** no-PAR metadata must reject FAPI2 construction even with
valid signing keys, signed-request mode, and DPoP. Positive tests must observe
an actual PAR request before the browser redirect.

### R5 — P2: Clearing token fields still resurrects stale persisted credentials

Location: `rp/token_source.go:65-85`, plus MarshalJSON's raw payload preservation.

The fix handles nonzero edits but equates empty/zero with absent. Explicitly
clearing AccessToken/RefreshToken or setting ExpiresIn to zero falls back to the
old raw response on reload. Reproduction:

```
cleared token restored: access="old" refresh="revoked" lifetime=3600
```

This contradicts the new explicit-fields-take-precedence contract. It can restore
credentials a consumer deliberately removed, including refresh credentials marked
unusable. Optional fields' omitempty also removes evidence of an explicit clear.

**Fix:** define an unambiguous persisted token envelope with authoritative fields,
including zero values. Distinguish absent fields from present-but-empty values
when compatibility with raw-only representations is needed. Preserved provider
raw data must not silently overwrite lifecycle state.

**Regression gate:** round-trip all fields after clearing them, not only replacing
one nonempty refresh token with another. Specify whether clearing a credential
also removes it from serialized raw provider data.

### R6 — P2: Reused binding cookies expire before newly created correlations

Location: `rp/store/memory/store.go:70-86`.

Set-Cookie is sent only when the request lacks a binding cookie. The default
cookie lasts eleven minutes from the first login; subsequent logins reuse its
value without refreshing its lifetime. A fresh ten-minute correlation can therefore
become unusable seconds later when the old cookie expires.

For example: first login at t=0; new login at t=10m30s; provider returns at t=11m30s.
The second correlation is only one minute old but its browser cookie has expired.
The external reproduction confirmed a second login sends no renewal cookie.

**Fix:** renew the lifetime on every new correlation while retaining the binding
value for overlapping tabs. Ensure every newly saved correlation has a browser
binding valid for its entire supported lifetime.

**Regression gate:** clock-controlled cookie-jar/browser test with a second login
near the original binding's expiry, followed by a still-valid callback.

### R7 — P2: CI formatting gate silently passes without its formatter

Location: `.github/workflows/ci.yml:11-16`.

The workflow sets up Go but never installs gofumpt. Its expression
`test -z "$(gofumpt -l .)"` examines captured stdout, not the formatter's exit
status. If the command is missing, stdout is empty and the test succeeds. Shell
reproduction with gofumpt unavailable produced:

```
gofumpt: command not found
CI format gate status without gofumpt: 0
```

**Fix:** explicitly install a pinned compatible gofumpt version. Capture/check its
exit status separately before testing whether its output is empty. Missing tools
and formatter errors must fail CI.

**Regression gate:** validate three cases: formatted source succeeds, unformatted
source fails, unavailable/failing formatter fails.

## Consumer experience / nonblocking polish

The new full-token callback API, optional UserInfo endpoint handling, structured
error preservation, safer signed-token defaults, and release/support documents are
substantial improvements. Finish their edge-case contracts rather than adding more
features before the RC.

Still useful before release:

- A production-shaped external example with application sessions, token persistence,
  absolute expiry bookkeeping, refresh rotation, and downstream API requests.
- Clear state-store deployment guidance: process-local defaults vs multi-instance
  services; POST callbacks; browser-binding lifetime; cookie replay limitations.
- Security hardening review of the binding cookie name: the current unprefixed
  name accepts arbitrary presented values. Consider a __Host- prefix to prevent
  sibling-domain cookie injection. This review did not run a browser attack for
  that threat model and does not count it among the confirmed findings above.
- Negative profile tests and real-browser tests alongside protocol conformance.
- Deferred vulnerability scanning/fuzzing, plus commit-pinned conformance evidence.

## RC acceptance gates

1. Address R1–R4 before release; add regressions covering the exact missing paths.
2. Resolve R5–R7 so persistence, login lifetime, and CI contracts match their claims.
3. Repeat full tests, race tests, and vet, including the targeted external scenarios.
4. Let the current conformance run finish and associate its results with its exact
   commit/configuration. Run the affected plans again after any subsequent fixes.
