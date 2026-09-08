# Fifth RC review remediation record

Review: `thoughts/reviews/stable-rc-readiness-11dce18.md` (revision `11dce18`).

## R1 — fixed

Commit `643fc39` (2026-09-07). `executeTokenGrant` — the common path for the
code-exchange, refresh, and client-credentials grants — now rejects successful
HTTP responses missing RFC 6749 §5.1's required `access_token`/`token_type`
fields, on both the primary and fallback attempts. Callers wrap the failure
with their grant sentinel (`ErrRefreshTokenFailed`, `ErrTokenExchangeFailed`,
`ErrClientCredentialsFailed`); `RefreshTokenSource` therefore never adopts
rotation data from a malformed response. Valid omissions (`refresh_token`,
`expires_in`) are unaffected.

Tests: `TestRefreshMalformedSuccessResponses` (three malformed shapes,
sentinel + message assertions, source non-adoption, minimal-valid response)
and `TestAllGrantsRejectMalformedSuccessResponses` (code exchange +
client credentials). Full suite and race pass; CI green (run `34142860344`
predecessor at `11dce18`; fix commit pushed for its own run).

## Independent negative-path security review

The review's security worker terminated without completing; the review
explicitly does not infer findings or a clean assessment from that. The four
prior review cycles' negative-path fixes (with regressions) remain the
standing coverage: signed-ID-token policy, browser binding and __Host-
prefixing for both state stores, JARM downgrade/issuer/algorithm enforcement,
DPoP proof attachment and fail-closed responses, mTLS certificate wiring
with construction rejection, endpoint https validation and redirect policy.
If a further independent pass is required for release sign-off, it needs to
be re-commissioned; it cannot be substituted by this remediation.
