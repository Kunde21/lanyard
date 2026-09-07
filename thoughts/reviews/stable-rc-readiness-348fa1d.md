# Fourth RC preparation review

Revision: `348fa1d`. Push confirmed origin/master was already up to date.

## Verdict: hold RC

CI run [34130172865](https://github.com/Kunde21/lanyard/actions/runs/34130172865)
is successful at this revision. `conformance/README.md:46-54` records passing
all-rp-smoke, oidcc-dynamic-full, fapi1-adv-smoke, fapi2-sp-full and fapi2-ms-full
runs against code revision `41b7bb9`. Those are meaningful improvements, but do
not cover the following dependency and negative-path issues.

A read-only gpt-5.6-sol worker reviewed protocol security. The parent independently
reran its six endpoint/mTLS/DPoP/FAPI reproductions and inspected relevant source.
No library, CI, or conformance configuration was changed by this review.

## R1 — P1: vulnerable JOSE dependency

`go.mod` uses `github.com/go-jose/go-jose/v4 v4.1.3`.
`govulncheck` reports GO-2026-4945 (CVE-2026-34986), a panic during malicious JWE
decryption, fixed in v4.1.4. The official Go advisory confirms the affected range
and denial-of-service impact. The scanner reports the library's
`rp.RP.decryptIDTokenIfNeeded -> jose.JSONWebEncryption.Decrypt` path.

Upgrade to v4.1.4 or a later compatible fixed version, rerun tests and the scan,
and add vulnerability scanning to the release gate. No exploit was run; the
reachability statement is the scanner's result, not proof that every consumer
configuration is exploitable.

Evidence: `/tmp/lanyard-348fa1d-govulncheck.log`,
`/tmp/lanyard-GO-2026-4945.json`, https://pkg.go.dev/vuln/GO-2026-4945.

## R2 — P1: credential-bearing endpoints and redirects permit cleartext

Locations: `rp/options.go:104-118`, `rp/client_config.go:77-88`,
`metadata/validate.go:114-171`, `rp/token_exchange.go:18-37`, `rp/http.go:24-46`.

Preloaded provider metadata bypasses discovery validation. The discovery
validator also omits several extension endpoints. Requests use the configured
HTTP client without a sensitive-request redirect policy.

Independently reproduced with `/tmp/lanyard_rc_security_repro.go`:

- ClientCredentials accepted an HTTP token endpoint and posted a fixture secret.
- An HTTPS endpoint's 307 redirect to HTTP resent the secret-bearing POST body.
- Both token calls returned success.

Direct HTTP configuration requires incorrect/untrusted endpoint configuration;
the downgrade case requires an endpoint returning that redirect. Neither is a
claim that a passive attacker can rewrite an authenticated TLS response.
Validate all effective credential-bearing endpoints and reject insecure or
cross-origin redirects for sensitive OAuth requests. Test configured metadata,
discovered extension endpoints, and 307/308 body replay explicitly.

## R3 — P1: mTLS wiring is incomplete across public constructors

Locations: `rp/rp.go:107-123,405-451`, `rp/client_credentials.go:16-54`,
`rp/introspection.go:120-155`, `rp/grant_management.go:115-143,258-287`.

The certificate-wiring remediation is on RP.New, not the standalone
ClientCredentials/Introspector/grant-management constructors. Additionally,
private_key_jwt plus MTLS sender constraining does not require a certificate;
the wiring helper silently returns when no certificate exists.

Independently reran `/tmp/lanyard_rc_mtls_repro.go`: tls_client_auth construction
succeeded with a certificate-bearing key provider, but a real mutual-TLS server
rejected the request (`tls: certificate required`); its handler was not reached.
This is primarily an integration failure against compliant servers, not a way
to bypass a server's certificate requirement.

Centralize certificate validation/wiring in shared client configuration and use
it in all applicable constructors. Preserve custom transport behavior safely or
reject configurations where wiring cannot be guaranteed.

## R4 — P1: explicit DPoP may send no proof

Locations: `rp/dpop.go:191-193,253-262`, `rp/client_config.go:203-209`,
`rp/client_credentials.go:144-159`, `rp/token_exchange.go:64-76`.

Proof attachment is gated on client-authentication method. Basic/Post,
client_secret_jwt and unauthenticated configurations cannot exercise explicit
DPoP through that gate, although DPoP is independent of these auth methods.
The newer response check only verifies token_type.

Independently reran `/tmp/lanyard_rc_dpop_option_repro.go`: Basic plus explicit
DPoP constructed, sent an empty DPoP header, then accepted a response labeled
DPoP. A compliant AS would not supply a usable newly DPoP-bound token without
its proof; the library nonetheless reports success for the mock response.

Support these combinations or reject unsupported explicit configurations at
construction. Mandatory response validation must accompany actual proof
attachment, not stand in for it.

## R5 — P1: FAPI response/issuer and sender-constraint invariants remain optional

Locations: `rp/rp.go:97-108,540-578`, `rp/options.go:177-182`,
`rp/callback.go:191-197`, `rp/jarm.go:149-154`.

Independently reproduced:

- `/tmp/lanyard_rc_fapi_issuer_repro.go`: FAPI2SecurityProfile with
  WithValidateAuthorizationResponseIssuer(false) constructed and accepted a
  callback with code/state but no iss.
- `/tmp/lanyard_rc_fapi1_repro.go`: FAPI1Adv plus DPoP constructed; default
  authorization parameters were response_type=code and no response_mode.

Thus mandatory issuer policy is still disableable, and FAPI1 defaults lack
hybrid or JARM response protection while allowing a sender constraint outside
its mTLS profile. Reject contradictory options, establish FAPI1 response
protection, and enforce profile-specific sender constraints. These reproductions
establish profile enforcement gaps, not an arbitrary account-takeover exploit.

## R6 — P2: FAPI JARM uses a broader algorithm policy than the hardened ID-token path

Locations: `rp/jarm.go:25-56`; compare `rp/idtoken.go:50-56,75-79`.

The generic JARM allowlist and provider-advertised algorithms can still admit
RS256 under FAPI2 Message Signing. Independently reran
`/tmp/lanyard_rc_jarm_alg_repro.go`: a complete RS256-JARM FAPI2MessageSigning
callback succeeded and returned the fixture access token.

Apply the profile's authorization-response signing policy as well as the
provider-advertised policy. This is profile noncompliance; RS256 alone is not
claimed to be cryptographically broken.

## R7 — P1, optional store: sibling-domain planting remains possible for cookie state

Locations: `rp/store/cookie/options.go:10-12,19-25,46-50`,
`rp/store/cookie/store.go:104-176,382-397,429-458`.

The memory store now uses a host-prefixed binding, but the optional cookie store
still defaults to unprefixed `lanyard_rp_state`. A captured valid attacker-session
cookie is sufficient to carry the attacker's correlation, including its verifier.
An attacker controlling an HTTPS sibling domain can plant that valid cookie with
Domain=example.com and then transfer the attacker's callback to a victim without
an existing conflicting host-only cookie. Cookie signing/encryption prevents
forgery, not transplantation of the attacker's own valid cookie.

The worker's `/tmp/lanyard_rc_cookie_transfer_repro.go` demonstrates store-level
transplantation. Full sibling-domain browser injection was not rerun in this
pass; distinguish this conditional attack from cross-origin cookie forgery.
Use a __Host- default and enforce compatible Secure/Path/Domain attributes,
with explicit documented opt-out if non-host-scoped configurations are supported.
Add a real-browser sibling-domain regression for this store too.

## Verification boundaries

- Fresh dependency scan and official advisory retrieved by parent.
- Actual latest GitHub CI success checked; no fresh full local suite run here.
- Six external security reproductions independently rerun by parent.
- Earlier positive fixes are present: memory host binding, JARM-presence checks,
  Bearer rejection for mandatory DPoP, mTLS endpoint alias selection, cookie-store
  form_post guidance/coverage, and CI browser provisioning.
- No new conformance runs, no changes to exclusions, no certification claim.
