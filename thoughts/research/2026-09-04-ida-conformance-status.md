# Identity Assurance Conformance Status

**Date:** 2026-09-04
**Context:** Task 8 of `thoughts/plans/2026-09-04-oidc-identity-assurance.md`.

## Conclusion

**No RP-profile identity assurance conformance plan exists in the OIDF suite; validation is library unit tests grounded in the spec and the suite's own schemas.** The library implementation is complete and green.

## Findings

1. **The suite ships one IDA plan, OP-side only.** `ekyc-test-plan-oidccore` ("OpenID for IDA using OpenID Connect Core", profile `ekyctest`) contains 12 modules (happy path variants, essential claims, unknown claims, verified claims in id_token vs userinfo, userinfo defaults). The `ekyctest` profile drives a mock **RP** against the suite's **OP** — it certifies OPs, and cannot be pointed at `cmd/example-rp` the way the `rptest`-profile client plans are.

2. **No RP-profile IDA plan** appears in `/api/plan/available` output beyond the OP-side one (verified during the DCR wiring sessions, where the full plan list was enumerated).

3. **Ground truth is available in-tree for free.** The suite vendors the normative JSON Schemas (`conformance/.upstream/conformance-suite/src/main/resources/json-schemas/ekyc-ida/`: `verified_claims_request.json`, `verified_claims.json`, `claims_schema.json`). The implementation's tests reproduce the spec's §5.2-5.6 examples verbatim (request and response sides), which those schemas define — the same fixtures the OP-side modules validate against.

4. **Spec discrepancies handled:** the final spec's prose names `documents_check_methods_supported` while its own §8 example uses `documents_methods_supported`; both parse into distinct fields (see `TestProvider_IdentityAssuranceMetadata`). The draft-era `purpose` member is absent from the final spec and deliberately not implemented.

## Recommendation

- Revisit when the OIDF ships an RP-profile IDA plan (unlikely soon — the ekyc WG's active work is on drafts: Authority claims, ASC, Attachments, none of which are in scope).
- Until then, the SPECIFICATIONS.md IDA section is the capability record; the plan document and this note document the validation rationale.
