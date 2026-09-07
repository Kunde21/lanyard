# Third RC preparation review

Revision: `5874cf8`, pushed to `origin/master` before review.

## Verdict: hold RC

R1–R7 from the second review are addressed. This pass identifies additional
security and interoperability gaps, plus an actual CI failure. Security review
was delegated to a read-only `gpt-5.6-sol` worker; the parent independently
checked the source paths underlying the findings below. No library or CI code
was changed during this review.

## Findings

### T1 — P1: browser binding can be fixed by a sibling-domain attacker

`rp/store/memory/store.go:18-21,71-91,132-150` uses the unprefixed cookie name
`lanyard_state_binding` and accepts an arbitrary existing value as the binding
for a newly saved correlation.

An attacker controlling `evil.example.com` can set a Domain=example.com cookie
with that name and a known value for a victim visiting `app.example.com`. The
attacker initiates and completes their own authorization using the same known
binding value, then transfers the callback to the victim. The state lookup and
binding equality succeed. This requires sibling-domain control and successful
cookie injection; it is not a claim that an unrelated origin can set the cookie.
A victim without an existing host-only binding is the straightforward case.

Use a `__Host-` cookie name with Secure, Path=/ and no Domain, and add a real-browser
sibling-domain injection regression. Source-established attack path; this pass
has not executed that complete browser attack.

### T2 — P1: required signed authorization responses can be downgraded

`rp/callback.go:53-67` selects JARM based only on the presence of the incoming
`response` field (`rp/jarm.go:145-146`), not the configured/required response mode.
A plain code/state response can therefore bypass JARM processing even when JWT
responses were requested. `rp/rp.go:447-487` also does not establish the response
protections required by FAPI1 Advanced or FAPI2 Message Signing.

`rp/jarm.go:107-143` only requires a nonempty issuer; comparison to the transaction
issuer is conditional on `validateAuthorizationResponseIssuer` in
`rp/callback.go:178-184`. FAPI2 does not enable that policy in its defaults.

Enforce profile-specific response type/mode and issuer requirements, and reject
plain callbacks when JARM is required. Compare JARM issuer to the transaction
issuer unconditionally. Test missing JARM, mismatched issuer, missing issuer,
and contradictory explicit options. These are integrity/profile gaps; no
arbitrary-code-substitution or account-takeover reproduction is claimed here.

### T3 — P1: explicit DPoP protection does not reject bearer token responses

`rp/token_exchange.go:122-147` parses a successful token response without checking
its token type against the requested DPoP protection. The callback accepts the
token and returns it (`rp/callback.go:199-235`), including under FAPI profiles.
The same common execution path serves refresh and client-credentials requests.

RFC 9449 section 5 distinguishes a DPoP token response from an unprotected one;
when DPoP is security-critical the client must discard an unprotected response.
A misconfigured/noncompliant AS returning Bearer or no token type currently does
not make the configured protection fail closed. This does not force a compliant
AS to downgrade.

Require a DPoP token type when sender constraining is explicitly required, with
negative tests across all three grants. Keep optional opportunistic DPoP behavior
separate from mandatory policy.

### T4 — P2: client credentials ignores mTLS endpoint aliases

`rp/client_credentials.go:175-176` always sends to `provider.TokenEndpoint` rather
than selecting `provider.MTLSEndpointAliases.TokenEndpoint` for mTLS. Assertion
and nonce handling also directly use the ordinary endpoint at lines 128,154,158,180.
Consumers using a provider that separates its mTLS endpoint cannot obtain tokens
through the advertised route.

External routing reproduction `/tmp/lanyard-rc3-mtls.go`, with tls_client_auth,
explicit MTLS sender constraining and preloaded metadata, printed:

```
request path=/ordinary wanted=/mtls err=<nil>
```

The local server did not require a client certificate: this verifies endpoint
selection, not a complete mutual-TLS handshake. Select the effective endpoint
consistently for transport, assertions, DPoP/nonce bookkeeping, and tests.

### T5 — P2: cookie store default is incompatible with cross-site form_post

`rp/store/cookie/store.go:66-75` still defaults to SameSite=Lax. The memory store
fix does not apply here. Consumers selecting this store and cross-site form_post
lose the state cookie on the POST callback. Provide a secure compatible policy
or clear configuration guidance/validation, and cover this store in real-browser
tests. This is source-based browser-semantics analysis, not a new browser run.

### T6 — release gate: pushed CI fails its browser tests

[CI run 34104895237](https://github.com/Kunde21/lanyard/actions/runs/34104895237)
for `5874cf8` passed formatter installation, gate self-tests, formatting and vet,
but failed Test. Cross-site query, form_post, and different-browser rejection
cases each hit the Chromium command timeout (`signal: killed`):
`rp/store/memory/browser_test.go:74,115`. Race and Build were skipped.

Evidence: `/tmp/lanyard-5874cf8-ci-failed.log`. This establishes a red release gate,
not its root cause. Diagnose browser startup/navigation/termination on the runner,
retain real-browser assertions, and obtain a green run rather than suppressing
or skipping these failures. Prior local full race/test passes do not substitute
for this failing clean-runner check.

## Additional policy verification needed

The security worker also flagged generic JOSE algorithms/key sizes and mTLS
transport/profile combinations that are not restricted by the FAPI constructor.
Before release, audit these against the exact FAPI specification/version claimed
by each exported profile. They are not counted as independently reproduced
findings in this report; avoid treating a nonempty sender-constraint enum or a
configured certificate object as proof of a completed mutual-TLS connection.

## Validation scope

- Push completed through `5874cf8`.
- Inspected actual GitHub CI job results and failure log.
- Ran external mTLS endpoint-routing reproduction.
- Independently checked source evidence for security-worker findings above.
- Did not rerun conformance, alter its presets, or reinterpret earlier smoke
  results as coverage for these negative cases.
- No fresh full local suite in this read-only pass; the previous verification
  remains recorded in the second review's remediation follow-up.
