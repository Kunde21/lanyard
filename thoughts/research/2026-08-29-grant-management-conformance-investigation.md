# Grant Management Conformance Testing: Investigation Findings

**Date:** 2026-08-29
**Context:** Task 9 of `thoughts/plans/2026-08-29-fapi2-grant-management.md` — determine whether the OpenID conformance suite's grant-management tests can run against `cmd/example-rp`, and wire a harness matrix only if low-friction.

## Conclusion

**Nothing to wire today.** No grant-management conformance tests exist in the OpenID Foundation conformance suite at any relevent revision, and no grant-management certification program exists yet. The recommendation is to rely on the library's unit/integration tests and revisit when the OIDF ships plans — the harness will pick them up with **zero changes** (see below).

## Evidence

### 1. Vendored suite has no grant-management tests

The local stack vendors `openid/conformance-suite` at `96c68a8fd` (2025-12-04, tagged `release-v5.1.41`) under `conformance/.upstream/conformance-suite`. Searching the entire `src/main` tree:

- Zero Java files reference `GrantManagement` or `grant_management`.
- All `*Grant*` hits are grant-type metadata checks (`FAPICheckDiscEndpointGrantTypesSupported*`, `CheckTokenEndpointReturnedInvalidGrant*`, dynamic-registration grant-type conditions).
- No test plan (16 plan classes under `net/openid/conformance/tests/`) touches grant management.

The suite README states its coverage: *"OpenID Connect, FAPI1-Advanced, FAPI2, FAPI-CIBA and OpenID for Identity Assurance (ekyc)"* — grant management is absent.

### 2. No grant-management certification program

The OIDF certification pages list supported FAPI certifications: FAPI 1.0 Advanced Final, FAPI 2.0 Security Profile (Final + ID2), FAPI 2.0 Message Signing (ID1). "Grant Management for OAuth 2.0" is an FAPI WG **Implementer's Draft** (the `fapi-grant-management-02` snapshot we planned against) but has no conformance tests or certification track published.

### 3. Ecosystem status

Authlete implements the grant management API in their AS (their docs and SDKs reference the spec), and grant-revocation-style endpoints exist in UK OB (`/account-access-consents`) and CDR (`cdr_arrangement_id` / `/arrangements/revoke`) as bespoke precursors — but none of these are exposed as RP/client test plans in the OIDF suite. Upstream GitLab (19 branches, active through 2026) shows no grant-management branch.

## Harness behavior when tests DO appear

`conformance/harness/profiles.go` discovers plans from the running suite's API and matches them with:

```go
fapiFallbackPattern = regexp.MustCompile(`(?i)fapi.*(client|rp)|rp.*fapi`)
```

plus profile heuristics (`isFAPIRPPlan`). A future plan named e.g. `fapi2-grant-management-client-test-plan` (matching OIDF naming conventions) would be **auto-selected** by the `fapi-rp` / `all-rp` profiles after a suite image bump — no harness code change needed.

What WOULD be needed at that point:

1. Bump the vendored suite / image (how the other suites are updated).
2. Extend `cmd/example-rp` to exercise the library's grant-management surface during the browser flow (issue `SetGrantManagementAction` on login, persist/surface `CallbackResult.GrantID`, wire query/revoke behind the RP's pages). The library side (`SetGrantManagementAction`, `Token/CallbackResult.GrantID`, `QueryGrant`, `RevokeGrant`, `RefreshTokenSource.Replace`) is already implemented and unit-tested.
3. Possibly a preset entry in `conformance/harness/presets.go` if the plan needs its own configuration block (e.g. grant-management-enabled flag for the example RP).

## Recommendation

- Do not wire a matrix now; there is nothing to run.
- Keep the library-level tests as the conformance evidence for grant management.
- Re-check the OIDF suite (e.g. quarterly, or when the FAPI WG announces grant-management certification) — then follow the three steps above; effort should be small since the harness auto-discovers matching plans.
