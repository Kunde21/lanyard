# Stable release-candidate readiness review

Reviewed commit: `3e4826a`.
Scope: public consumer API, browser authorization/callback integration, token lifecycle,
state stores, security defaults, HTTP behavior, and release documentation.

## Recommendation

**Do not cut a stable RC from this commit.** The feature coverage is substantial,
but ordinary consumer integration reveals security and correctness defects that
are not exercised by the current passing suite. Fix the P1 findings and settle
public API contracts before freezing the stable API.

This is a source review with targeted external-consumer reproductions, not an
independent protocol certification or exhaustive security audit. The OpenID
Foundation conformance suite was not rerun during this review.

## Verification

- `go test ./...`: 882 tests passed across 14 packages.
- `go test -race ./...`: 882 tests passed across 14 packages.
- `go vet ./...`: passed.
- AFT diagnostics: no reported errors or warnings.
- External consumer with simultaneous login/callback calls on one RP:
  **23 data races**, race detector exit status 66 (go run exits 1).
- External consumer reproduced unsigned-ID-token opt-out failure, cookie replay,
  stale token persistence, discovery despite DiscoveryDisabled, mandatory UserInfo,
  missing client_secret_jwt assertion, inaccessible OAuthError, and permissive FAPI configuration.
- Reproduction programs were written outside the repository at
  `/tmp/lanyard-rc-review.go` and `/tmp/lanyard-rc-integration.go`.
  These are temporary investigation artifacts, not committed regression tests.
- No library code was changed.

## Findings

### 1. P1 — Default browser state is not bound to the initiating browser

Locations: `rp/rp.go:305-309`, `rp/store/memory/store.go:40-86`,
`rp/callback.go:124-135`.

The default store ignores both HTTP request and response and indexes correlation
solely by the state string. An attacker can initiate login, authenticate their own
account, withhold the redirect, and send the resulting callback URL to a victim.
The victim's callback consumes the attacker's server-side state. PKCE and nonce
still match that transaction: neither binds it to the victim's browser.

The external consumer successfully completed a callback without any cookie or
other browser binding. Its test issuer was synthetic; the source-level attack
also applies when an honest issuer supplies the attacker's genuine signed token.

Require independent browser/session binding in the default flow, or require an
explicitly configured safe store rather than silently choosing this default.
Add a two-browser login-CSRF regression test.

### 2. P1 — Explicit unsigned-ID-token rejection is overridden

Locations: `rp/rp.go:433-436`, `rp/options.go:183-187`, `rp/idtoken.go:77-91`.

`finalizeSecurityDefaults` changes false to true for non-FAPI profiles, including
when the caller explicitly passed `WithAllowUnsecuredIDTokens(false)`. An external
consumer received a successful OIDC callback with an alg=none token despite that
option. The unsigned branch also returns before the advertised-algorithm check.

Default to signed verification and honor explicit configuration. Any unsecured
compatibility mode must be explicit and documented. This finding does not imply
an arbitrary remote attacker can replace a token delivered over authenticated TLS;
it establishes that the advertised verification policy is not enforced.

### 3. P1 — RP is unsafe for normal concurrent HTTP handlers

Locations: `rp/callback.go:136-174`, `rp/auth_method.go:32-36`,
`rp/client_config.go:186-198`, `rp/callback.go:230-237`.

Callbacks overwrite shared client ID, secret, issuer, and provider state. Auth
method writes use a mutex, but multiple reads bypass it. A public-API program
sharing one RP across 12 simultaneous login/callback requests produced 23 races.
This is the natural deployment pattern shown by the README, not unusual misuse.

Keep construction-time configuration immutable, use per-callback transaction
configuration, and consistently synchronize genuinely mutable shared state.
Also fix state-store map reads: `rp/store/memory/store.go:95-108,158-176` releases
the lock before reading/cloning the shared values map while SaveValue can mutate it.

### 4. P1 — CallbackResult loses the token lifecycle information

Locations: `rp/callback.go:18-41,194-209,227`, `rp/doc.go:46-58`.

The callback exchanges for a full Token but exposes only its access-token string
and selected identity fields. Consumers cannot obtain the refresh token for the
advertised RefreshToken/NewRefreshTokenSource flow, know the token lifetime/type,
or persist the original ID token. OAuth-only callbacks additionally discard grant_id.

Expose the complete token response and a useful validated identity representation.
Include issuer plus subject for stable identity keys, not subject alone. Decide
this API before stable release and add an external example that signs in,
persists tokens, then refreshes without intercepting HTTP traffic.

### 5. P1 — Preloaded metadata does not actually eliminate discovery

Locations: `rp/idtoken.go:103-106`, `metadata/jwks.go:13-22`.

Signed-ID-token validation calls RemoteKeySet by issuer, which discovers provider
metadata again. If discovery fails, validation returns before trying the supplied
JWKS URI. An external consumer with complete WithProviderMetadata and
WithDiscoveryMode(DiscoveryDisabled) constructed successfully but failed its
callback on a .well-known 404 despite having a valid configured JWKS endpoint.

Use the resolved provider's JWKS URI directly and retain normal caching/rotation.
Test a complete signed callback against an issuer that exposes no discovery endpoint.

### 6. P1 — A hard-coded client ID bypasses algorithm policy

Location: `rp/idtoken.go:94-100`.

The advertised-signing-algorithm check is skipped for client ID
`local-dev-client-2`, as well as for encrypted ID tokens. Client-ID naming must not
change validation policy. Encryption does not justify skipping validation of the
inner token's permitted signing algorithm.

Remove the test-specific exception and explicitly define/enforce the accepted
signing policy for signed and nested tokens alike. This is an algorithm-policy
bypass, not a general signature-verification bypass.

### 7. P1 — FAPI profile selection does not enforce FAPI requirements

Locations: `rp/rp.go:386-420,439-467`, `rp/par.go:26-30`,
`rp/options.go:460-465,482-522`.

The profile defaults set scopes/request-object mode but do not require PAR,
sender constraining, or asymmetric client authentication. A consumer could select
FAPI2SecurityProfile with a client secret and WithRequestMethod("plain"), then
successfully generate an ordinary code URL with neither request nor request_uri.
Unknown request-method strings also silently become plain requests.

The docs call these defaults rather than certification guarantees, but the names
are hazardous for consuming projects. Offer strict, validated security profiles
that reject contradictory options. Keep permissive conformance/testing knobs
separate and clearly named. Add negative tests for insecure profile configurations.

### 8. P2 — Valid OIDC sign-in requires an optional UserInfo service

Location: `rp/callback.go:212-225`.

Ordinary OIDC callbacks fail if userinfo_endpoint is absent, and otherwise always
call it. An external consumer verified that a valid signed identity is rejected
solely because the provider has no UserInfo endpoint. OIDC identity-only consumers
should not need this additional service or grant access to profile claims.

Make UserInfo retrieval optional/lazy or explicitly configurable. Preserve subject
matching when it is requested. Return useful validated ID-token claims directly.

### 9. P2 — Client credentials accepts authentication it does not implement

Locations: `rp/client_config.go:167-171`, `rp/client_credentials.go:116-128`.

AuthMethodClientSecretJWT passes configuration validation, but the client
credentials request switch has no implementation for it. An external token server
observed no client_assertion and returned invalid_client.

Implement shared authentication consistently across token grant methods, or reject
unsupported combinations at construction. Add a per-grant/auth-method test matrix.
Also make automatic auth selection consider available credentials:
`rp/client_config.go:112-137` chooses private_key_jwt before basic/post even when
the consumer supplied only a secret, causing avoidable constructor failures with
providers that advertise several methods.

### 10. P2 — Token JSON persistence restores stale fields

Locations: `rp/token_source.go:50-61,65-91`, `rp/refresh_rotation.go:55-59`.

MarshalJSON writes exported fields alongside preserved raw data; UnmarshalJSON
then treats raw as authoritative. Reproduction: decode refresh_token="old", set
RefreshToken="new", marshal/unmarshal, and the restored value is "old".
RefreshTokenSource also adds a retained refresh token to responses that omit it,
but that synthesized field is lost on round-trip because it is absent from raw.

Define one authoritative persistence representation and preserve current fields.
Keep raw provider data separate from token lifecycle state. Test refresh responses
both with and without rotation and then persist/reload the returned Token.

### 11. P2 — State stores have unsafe lifecycle/consumption contracts

Locations: `rp/store/memory/store.go:40-86`,
`rp/store/cookie/store.go:133-168,421-453`.

Memory-store expiry is only checked when the particular state is accessed. There
is no sweep or capacity limit: abandoned login attempts remain indefinitely. Add
bounded storage and eviction for expired entries without requiring their keys.

Cookie ConsumeCorrelation claims atomic removal, but only changes the response
cookie. Replaying the original cookie in two fresh requests returned true twice.
An authorization server's one-use code still provides an independent replay
barrier; this finding does not establish repeated successful token redemption.
Nevertheless consumers cannot rely on this store for one-time consumption.
Provide a server-side consumed-state mechanism if required, or document the weaker
contract explicitly. Cookie payloads also accumulate abandoned states without
pruning, risking cookie-size failures during repeated logins.

### 12. P2 — Public error wrapping removes actionable causes

Locations: `rp/client_credentials.go:86-87`, `rp/refresh_token.go:45-50`,
`rp/rp.go:339-341`, `rp/token_exchange.go:98-101`.

Several public boundaries wrap their sentinel with %w but format the actual cause
with %v. OAuthError advertises errors.As support, yet the external client-credentials
reproduction could not recover invalid_client as OAuthError. Refresh preserves
invalid_grant specially but flattens other OAuth errors. Discovery/cancellation
causes are similarly lost in several paths.

Preserve both sentinel and cause, and test errors.Is/errors.As through public
entrypoints. Consumers need structured errors for reauthentication, retries,
configuration diagnostics, and cancellation handling.

## Developer-experience and release work

- Provide a genuinely runnable production-shaped browser example: random persistent
  keys loaded from configuration, HTTP deadlines, login and callback routes,
  application session creation, token persistence, refresh, and failure handling.
  README currently embeds fixed cookie keys and prints an access token
  (`README.md:103-108,241`). Label fixtures clearly and remove token logging.
- Explain browser binding, multi-instance state storage, reverse proxies, key rotation,
  and SameSite=None + Secure for cross-site form_post. The cookie default is Lax.
- Clarify that TokenSource is not golang.org/x/oauth2.TokenSource and that
  ClientCredentials.Token performs a request every time. README promises an
  interface for caching/reuse, but there is no provided expiry-aware cache or
  authenticated resource HTTP client. RefreshTokenSource does not implement TokenSource.
- Provide a supported DPoP resource-request integration path; consumers must know
  how to attach proofs, handle nonce challenges, and retain the binding key rather
  than treating every access token as an interchangeable bearer string.
- Document HTTP deadlines and response-size limits. The default HTTP client has no
  overall timeout (`rp/rp.go:294`, `rp/client_config.go:245`), and successful JSON
  bodies are not bounded (`rp/http.go:40-42`). Harden defaults where practical.
- Document the minimum Go version (go.mod currently specifies 1.25.7), stable API
  compatibility policy, security reporting/support policy, and release notes.
- Add automated release gates for external API examples, race-enabled concurrent
  handlers, fuzzed callback/token parsing, vulnerability scanning, and supported
  Go versions. No .github workflow files were found in this checkout; externally
  managed CI may exist and was not inspected.
- Attach conformance evidence to the reviewed commit, suite version, configuration,
  and date. Passing suite plans are valuable but do not establish safe defaults,
  concurrent use, or end-to-end consumer usability.

## Suggested release gates

1. Resolve findings 1–7 and add negative/security regression tests.
2. Resolve the token lifecycle, error, and state-store contracts before freezing API.
3. Run an external consumer end-to-end: cookie-bound login, signed validation,
   optional UserInfo, persisted tokens, refresh rotation, authenticated API request.
4. Exercise shared clients under concurrent login, callback, refresh, and metadata
   rotation; then rerun tests, vet, race detection, vulnerability checks, and conformance.
5. Publish versioned evidence and a clear supported integration guide with the RC.
