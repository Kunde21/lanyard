# FAPI policy audit (third RC review deferral)

Scope: JOSE algorithms, key sizes, and mTLS transport wiring for the exported
FAPI profiles (`FAPI1Adv`, `FAPI2SecurityProfile`, `FAPI2MessageSigning`;
`PlainFAPI` is a testing profile and excluded), against the claimed specs:

- FAPI 1.0 Advanced Final: §8.4/§8.6 (PS256/ES256 signing), §8.6 (ID token
  alg), private_key_jwt / tls_client_auth, TLS 1.2+ (BCP 195), RSA ≥ 2048.
- FAPI 2.0 Security Profile Final: §5.2 (PS256/ES256 request/response
  signing), asymmetric client auth, TLS 1.2+ mTLS.
- FAPI 2.0 Message Signing Final: adds JARM responses signed PS256/ES256.

## Findings (all confirmed in source at `d16e0c6`)

### A1 — FAPI accepts any provider-advertised ID token algorithm

`supportedIDTokenAlgs` (rp/idtoken.go) accepts RS*, PS*, ES*; the FAPI
profile narrows nothing, so an RS256-signed ID token validates under a FAPI
profile whenever the provider advertises RS256. FAPI requires PS256/ES256.

**Fix**: FAPI profiles restrict accepted ID token (and authorization
response) algorithms to PS256/ES256 regardless of the advertised list.

### A2 — no signing-key size floor

A 1024-bit RSA key provider is accepted for private_key_jwt/request
objects/DPoP under FAPI profiles. FAPI requires RSA ≥ 2048 bits (EC P-256+).

**Fix**: construction-time rejection for FAPI profiles.

### A3 — mTLS client authentication never presents the certificate

The library validates that a `tls.Certificate` exists for
`tls_client_auth`/`self_signed_tls_client_auth`, but nothing wires it into
the RP's own HTTP transport: only the example application sets
`GetClientCertificate`. A consumer with a default `http.Client` constructs
successfully and then fails every token-endpoint call against a real mTLS
endpoint — exactly the "configured certificate is not proof of a mutual-TLS
connection" hazard the review flagged.

**Fix**: `New` wires the key provider's certificate into the RP's HTTP
transport automatically when mTLS client auth (or mTLS sender constraining)
is configured: `*http.Transport` instances are cloned with
`GetClientCertificate`; transports that already present one are left alone;
custom non-`*http.Transport` round trippers cannot be modified and remain
the consumer's responsibility (documented).

### A4 — client assertion / request object algorithm unrestricted

The key provider's declared algorithm is used verbatim for private_key_jwt
assertions, request objects, and DPoP proofs; RS256 material passes FAPI
construction.

**Fix**: construction-time restriction to PS256/ES256 under FAPI profiles
(covers A2's floor check at the same site). DPoP proofs additionally SHOULD
be ES256 (RFC 9449 §4.1) but MAY use others when the server accepts;
documented rather than enforced.

## Non-findings

- TLS protocol floor: transport TLS versions are the consumer's `http`
  client's; Go defaults to TLS 1.2 minimum (1.3 preferred) — BCP 195
  compliant by default. Documented in the audit only.
- `PlainFAPI` is explicitly a testing profile (unsigned requests); excluded.

## Verification

Negative/positive construction and validation tests accompany each fix; see
the implementation commits. CI green.
