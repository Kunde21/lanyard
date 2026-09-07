# Third RC review remediation verification

Review: `thoughts/reviews/stable-rc-readiness-5874cf8.md` (revision `5874cf8`).

All six findings addressed 2026-09-07; each commit is atomic with regression
tests; both remotes synced; CI green (run `34113607599`, commit `d16e0c6`).

## Findings

| ID | Verdict | Commit | Resolution |
|----|---------|--------|------------|
| T1 (P1) sibling-domain cookie injection | fixed | `403ed53` | `__Host-` binding-cookie prefix (browser-enforced host-only/Secure/Path=/, no Domain) + real-browser regression proving the sibling-site injection is refused |
| T2 (P1) JARM downgrade | fixed | `253f71c` | Plain callbacks rejected whenever a JWT response mode is configured; JARM `iss` compared to transaction issuer unconditionally; FAPI profiles default response-issuer validation on (explicit override honored); FAPI2-MS defaults `response_mode=jwt` and rejects contradictory explicit modes at construction |
| T3 (P1) DPoP fail-open | fixed | `af8ce9e` | Explicit DPoP constraint rejects Bearer/missing token types with `ErrSenderConstraintViolated` across code, refresh, and client-credentials grants; opportunistic DPoP stays lenient |
| T4 (P2) mTLS alias ignored | fixed | `d1952f1` | Client-credentials selects the mTLS token endpoint alias via shared `effectiveTokenEndpoint` for transport, assertion audiences, and DPoP nonce bookkeeping |
| T5 (P2) cookie store SameSite | fixed | `4509a9f` | `WithSameSite(None)` documented for cross-site form_post (HTTPS + proxy-scheme requirements); real-browser regression proves the Lax default drops the state cookie on cross-site form_post and None carries it |
| T6 (release gate) red CI | fixed | `50ab0a6`→`d16e0c6` | See below |

## T6 root-cause chain

1. `50ab0a6`: marker-driven success (immune to exit hangs) + stderr
   diagnostics + 90s startup budget. Runner still failed → not an exit hang.
2. `7f5bc4a`: Playwright Chromium instead of runner snap. Full
   Chrome-for-Testing 153 aborted TLS handshakes with Go TLS servers
   (reproduced minimally outside the test suite with a local install).
3. `123c412`: playwright's `chrome-headless-shell` (works with Go TLS) +
   natural-exit mode for cookie-establishing navigations (marker-kill raced
   the cookie store flush for later same-profile launches).
4. `d16e0c6`: the shell is argv[0]-sensitive - launched through a
   `google-chrome` symlink it idled without navigating; linked and looked up
   as `chrome-headrome-shell` (`chrome-headless-shell`), plus a CI smoke
   step proving `--dump-dom` works before the tests run. **Green run.**

Browser-test helpers live in `internal/browsertest` (CHROMIUM_PATH env
override; marker and natural-exit modes; profile-dir tolerant cleanup).

## Deferred

- The review's "additional policy verification" (JOSE algorithm/key-size
  restrictions and mTLS transport/profile combinations in FAPI constructors)
  remains open as a pre-release audit item; it was explicitly not counted as
  a finding.
