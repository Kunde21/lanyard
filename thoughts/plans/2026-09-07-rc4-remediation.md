# Fourth RC Review Remediation Plan

**Source:** `thoughts/reviews/stable-rc-readiness-348fa1d.md` (revision `348fa1d`).
**Goal:** all seven findings fixed, atomic commits, regression coverage each.

- **R1** go-jose v4.1.4+ (GO-2026-4945) + govulncheck in CI.
- **R2** https-validate every effective credential-bearing endpoint (preloaded metadata included; loopback exempt) + sensitive-request redirect policy (no cross-scheme/cross-origin) at the shared HTTP choke points.
- **R3** mTLS cert wiring centralized on clientConfig; applied in New + ClientCredentials + Introspector + GrantManager; MTLS sender-constraining without a certificate rejected at construction.
- **R4** explicit DPoP attaches proofs independent of client-auth method; explicit DPoP without a key provider rejected at construction.
- **R5** FAPI invariants: explicit `WithValidateAuthorizationResponseIssuer(false)` rejected under FAPI; FAPI1Adv defaults to hybrid `code id_token` response protection; FAPI1Adv rejects DPoP sender constraining (mTLS-profile only).
- **R6** JARM parsing restricted to PS256/ES256 under FAPI profiles.
- **R7** cookie store defaults to `__Host-lanyard_rp_state`; incompatible attributes rejected at construction when the prefix requires them; real-browser sibling-domain regression.
