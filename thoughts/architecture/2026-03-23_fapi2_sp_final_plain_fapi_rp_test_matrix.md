---
date: 2026-03-23T00:00:00Z
repository: lanyard
topic: "FAPI2 Security Profile Final plain_fapi RP test matrix"
tags: [architecture, conformance, fapi2, rp, test-matrix]
last_updated: 2026-03-23
---

# FAPI2 Security Profile Final `plain_fapi` RP Test Matrix

## Summary

This note records the configuration matrix exposed by the OpenID conformance suite for the relying party plan `fapi2-security-profile-final-client-test-plan` when restricted to `fapi_profile=plain_fapi`.

The matrix was confirmed from two sources:

- suite API: `https://suite.localhost/api/plan/available`
- suite UI: `https://suite.localhost/schedule-test.html`

For this plan, the suite fixes two values and exposes four selectable axes.

Fixed values:

- `fapi_request_method=unsigned`
- `fapi_response_mode=plain_response`

Selectable values:

- `client_auth_type`: `private_key_jwt` or `mtls`
- `sender_constrain`: `mtls` or `dpop`
- `authorization_request_type`: `simple` or `rar`
- `fapi_client_type`: `oidc` or `plain_oauth`

This yields `2 x 2 x 2 x 2 = 16` suite-exposed combinations for `plain_fapi`.

## Matrix

| # | client_auth_type | sender_constrain | authorization_request_type | fapi_client_type |
|---|---|---|---|---|
| 1 | `private_key_jwt` | `mtls` | `simple` | `oidc` |
| 2 | `private_key_jwt` | `mtls` | `simple` | `plain_oauth` |
| 3 | `private_key_jwt` | `mtls` | `rar` | `oidc` |
| 4 | `private_key_jwt` | `mtls` | `rar` | `plain_oauth` |
| 5 | `private_key_jwt` | `dpop` | `simple` | `oidc` |
| 6 | `private_key_jwt` | `dpop` | `simple` | `plain_oauth` |
| 7 | `private_key_jwt` | `dpop` | `rar` | `oidc` |
| 8 | `private_key_jwt` | `dpop` | `rar` | `plain_oauth` |
| 9 | `mtls` | `mtls` | `simple` | `oidc` |
| 10 | `mtls` | `mtls` | `simple` | `plain_oauth` |
| 11 | `mtls` | `mtls` | `rar` | `oidc` |
| 12 | `mtls` | `mtls` | `rar` | `plain_oauth` |
| 13 | `mtls` | `dpop` | `simple` | `oidc` |
| 14 | `mtls` | `dpop` | `simple` | `plain_oauth` |
| 15 | `mtls` | `dpop` | `rar` | `oidc` |
| 16 | `mtls` | `dpop` | `rar` | `plain_oauth` |

## Notes

- `authorization_request_type=rar` adds the extra configuration field `resource.authorization_details_types_supported`.
- `fapi_client_type=oidc` is the OpenID Connect-capable branch; `plain_oauth` excludes ID token behavior.
- `plain_fapi` itself adds no extra profile-specific configuration fields in this RP plan.
- For certification naming, the plan emits generic FAPI2 Security Profile RP labels plus an additional OpenID Connect label when `fapi_client_type=oidc`.

## Must-Run First Subset

If the immediate goal is fast confidence rather than exhaustive coverage, the smallest practical first-pass subset is 8 runs. This keeps both values of every selectable axis in play while avoiding running all 16 combinations up front.

Recommended first-pass subset:

| # | client_auth_type | sender_constrain | authorization_request_type | fapi_client_type | Why include it |
|---|---|---|---|---|---|
| 1 | `private_key_jwt` | `mtls` | `simple` | `oidc` | Baseline OIDC path with private key auth and MTLS sender constraint |
| 2 | `private_key_jwt` | `dpop` | `simple` | `oidc` | Covers DPoP with the same auth mode |
| 3 | `mtls` | `mtls` | `simple` | `oidc` | Covers MTLS client auth plus MTLS sender constraint |
| 4 | `mtls` | `dpop` | `simple` | `oidc` | Covers mixed MTLS client auth and DPoP sender constraint |
| 5 | `private_key_jwt` | `mtls` | `rar` | `plain_oauth` | Introduces RAR and plain OAuth together |
| 6 | `private_key_jwt` | `dpop` | `rar` | `plain_oauth` | RAR plus DPoP under private key auth |
| 7 | `mtls` | `mtls` | `rar` | `plain_oauth` | RAR plus full MTLS mode |
| 8 | `mtls` | `dpop` | `rar` | `plain_oauth` | RAR plus mixed auth/constraint mode |

This subset covers:

- both client authentication methods
- both sender-constraining methods
- both authorization request types
- both client types

Implementation milestone note:

- The first parallel-runner bring-up milestone uses a narrower 4-case subset before the full 8-case first pass.
- That initial subset is the `simple + oidc` cross-product of `client_auth_type` and `sender_constrain`:
  - `private_key_jwt + mtls + simple + oidc`
  - `private_key_jwt + dpop + simple + oidc`
  - `mtls + mtls + simple + oidc`
  - `mtls + dpop + simple + oidc`
- This lets the harness, runtime registry, state isolation, and per-job reporting stabilize before widening to `rar` and `plain_oauth` cases.

Operationally, this is the best first wave for implementation and debugging. If all 8 pass, the remaining 8 runs are largely confirmation of the opposite `fapi_client_type` within each already-covered auth/request combination.

## Exhaustive Completion Order

After the 8-run first pass, complete the other 8 runs by flipping only `fapi_client_type` within the same auth/request tuples:

- add the `plain_oauth` twin of rows 1-4
- add the `oidc` twin of rows 5-8

That produces the full 16-case `plain_fapi` matrix.

## Source References

- Plan-level fixed variants: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestPlan.java:83`
- RP client variant definitions: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java:232`
- Client type enum: `conformance/.upstream/conformance-suite/src/main/java/net/openid/conformance/variant/FAPIClientType.java:1`
- Live suite endpoint inspected: `https://suite.localhost/api/plan/available`
