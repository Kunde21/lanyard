# Lanyard Specifications

This document lists the OpenID Connect, OAuth 2.0, and related specifications implemented by Lanyard, as well as specifications required for OAuth 2.1, FAPI 1.0 Advanced, and FAPI 2.0 compliance.

## OpenID Connect Specifications

### OpenID Connect Core 1.0

**Status**: Implemented

Core OpenID Connect specification for Relying Party functionality.

| Feature                          | Status | Notes                                       |
|----------------------------------|--------|---------------------------------------------|
| Discovery (openid-configuration) | ✅     | `.well-known/openid-configuration` endpoint |
| Authorization Code Flow          | ✅     | Complete flow with state, nonce, PKCE       |
| ID Token Validation              | ✅     | Signature verification, claims validation   |
| UserInfo Endpoint                | ✅     | Bearer token authentication                 |
| ID Token Claims                  | ✅     | iss, sub, aud, exp, iat, nonce, azp         |
| Session Management               | ✅     | State stores (memory, cookie)               |

**Implementation**:

- `oidc/discovery.go` - Provider discovery
- `rp/rp.go` - Authorization Code flow
- `rp/idtoken.go` - ID Token validation
- `rp/userinfo.go` - UserInfo endpoint

---

### OpenID Connect Discovery 1.0

**Status**: Implemented

Provider metadata discovery and validation.

| Feature             | Status | Notes                                     |
|---------------------|--------|-------------------------------------------|
| Provider Metadata   | ✅     | Full metadata struct with FAPI extensions |
| JWKS URI            | ✅     | Remote key set fetching                   |
| Metadata Validation | ✅     | Required fields, HTTPS enforcement        |
| WebFinger Discovery | ✅     | RFC 7033 issuer resolution                |

**Implementation**:

- `oidc/metadata_provider.go` - Provider metadata
- `oidc/validate.go` - Metadata validation
- `oidc/webfinger.go` - WebFinger discovery

---

### JARM (JWT Secured Authorization Response Mode)

**Status**: Not Implemented

**Required for**: FAPI 1.0 Advanced, FAPI 2.0 Message Signing

JWT-wrapped authorization responses for integrity protection.

| Feature             | Status | Notes                           |
|---------------------|--------|---------------------------------|
| query.jwt mode      | ❌     | JWT in query parameter          |
| fragment.jwt mode   | ❌     | JWT in fragment                 |
| form_post.jwt mode  | ❌     | JWT in form POST                |
| Response JWT Claims | ❌     | iss, aud, exp, iat, code, state |
| Response Signature  | ❌     | AS-signed response verification |

**Required Claims**:

- `iss` - Authorization server issuer
- `aud` - Client ID
- `exp` - Expiration time
- `iat` - Issued at time
- Authorization response parameters (code, state, error, etc.)

---

## OAuth 2.0 Specifications

### RFC 6749: OAuth 2.0 Authorization Framework

**Status**: Implemented

Core OAuth 2.0 specification.

| Feature                  | Section | Status | Notes                      |
|--------------------------|---------|--------|----------------------------|
| Authorization Code Grant | §4.1    | ✅     | Primary flow               |
| Client Credentials Grant | §4.4    | ✅     | Service-to-service auth    |
| Token Endpoint           | §3.2    | ✅     | With multiple auth methods |
| Bearer Token Usage       | §10.12  | ✅     | Authorization header       |

**Implementation**:

- `rp/rp.go` - Authorization Code flow
- `rp/client_credentials.go` - Client Credentials grant
- `rp/token_exchange.go` - Token endpoint requests

---

### RFC 6750: OAuth 2.0 Bearer Token Usage

**Status**: Implemented

Bearer token usage in HTTP requests.

| Feature                 | Status | Notes                  |
|-------------------------|--------|------------------------|
| Authorization Header    | ✅     | Bearer scheme          |
| Form-Encoded Body       | ✅     | access_token parameter |
| WWW-Authenticate Header | ✅     | Error responses        |

**Implementation**:

- `rp/userinfo.go` - Bearer token in Authorization header
- `rp/http.go` - HTTP request handling

---

### RFC 7636: PKCE (Proof Key for Code Exchange)

**Status**: Implemented

Protection against authorization code interception attacks.

| Feature                    | Status | Notes                           |
|----------------------------|--------|---------------------------------|
| S256 Code Challenge Method | ✅     | SHA-256 hash                    |
| Code Verifier Generation   | ✅     | Cryptographically random        |
| Code Verifier Validation   | ✅     | Length 43-128, unreserved chars |

**Implementation**:

- `rp/pkce.go` - PKCE implementation

---

### RFC 8414: OAuth 2.0 Authorization Server Metadata

**Status**: Implemented

Authorization server metadata discovery.

| Feature               | Status | Notes                                    |
|-----------------------|--------|------------------------------------------|
| Well-Known URI        | ✅     | `.well-known/oauth-authorization-server` |
| Metadata Fields       | ✅     | Full RFC 8414 fields                     |
| mTLS Endpoint Aliases | ✅     | RFC 8705 extension                       |

**Implementation**:

- `oidc/well_known.go` - Well-known URL construction
- `oidc/metadata_oauth_as.go` - Authorization server metadata
- `rp/endpoints.go` - Endpoint resolution with mTLS aliases

---

### RFC 8693: OAuth 2.0 Token Exchange

**Status**: Implemented

Token exchange for delegation and impersonation.

| Feature                | Status | Notes                                                      |
|------------------------|--------|------------------------------------------------------------|
| Token Exchange Request | ✅     | grant_type=urn:ietf:params:oauth:grant-type:token-exchange |
| Subject Token          | ✅     | Token to exchange                                          |
| Actor Token            | ✅     | Acting party token                                         |

**Implementation**:

- `rp/token_exchange.go` - Token exchange requests

---

### RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication

**Status**: Implemented

Mutual TLS for client authentication and sender constraint.

| Feature               | Status | Notes                          |
|-----------------------|--------|--------------------------------|
| tls_client_auth       | ✅     | mTLS client authentication     |
| mTLS Endpoint Aliases | ✅     | Alternative endpoints for mTLS |
| Sender Constraint     | ✅     | Certificate-bound tokens       |

**Implementation**:

- `rp/auth_method.go` - tls_client_auth method
- `oidc/metadata_oauth_as.go` - MTLSEndpointAliases
- `rp/endpoints.go` - Endpoint resolution

---

### RFC 9126: OAuth 2.0 Pushed Authorization Requests (PAR)

**Status**: Implemented

Pushed Authorization Requests for improved security.

| Feature          | Status | Notes                       |
|------------------|--------|-----------------------------|
| PAR Request      | ✅     | POST to PAR endpoint        |
| Request URI      | ✅     | request_uri parameter       |
| Client Assertion | ✅     | private_key_jwt auth at PAR |

**Implementation**:

- `rp/par.go` - PAR implementation

---

### RFC 9449: DPoP (Demonstrating Proof-of-Possession)

**Status**: Implemented

Proof-of-posession for OAuth tokens.

| Feature               | Status | Notes                           |
|-----------------------|--------|---------------------------------|
| DPoP Proof Generation | ✅     | JWT with method, URL, timestamp |
| DPoP Header           | ✅     | Binding to HTTP request         |
| Access Token Binding  | ✅     | ath claim for token hash        |

**Implementation**:

- `rp/dpop.go` - DPoP proof generation and validation

---

### RFC 7523: JWT Profile for OAuth 2.0 Client Authentication

**Status**: Implemented

JWT-based client authentication (private_key_jwt).

| Feature              | Status | Notes                          |
|----------------------|--------|--------------------------------|
| private_key_jwt Auth | ✅     | JWT client assertion           |
| Client Assertion JWT | ✅     | iss, sub, aud, exp, jti claims |
| JWT Bearer Grant     | ✅     | Authorization grant type       |

**Required Claims in Client Assertion**:

- `iss` - Client identifier
- `sub` - Client identifier
- `aud` - Authorization server issuer/token endpoint
- `exp` - Expiration time
- `jti` - JWT ID (replay protection)

**Implementation**:

- `rp/auth_method.go` - private_key_jwt method
- `rp/par.go` - Client assertion building

---

### RFC 8707: Resource Indicators for OAuth 2.0

**Status**: Not Implemented

**Required for**: FAPI 2.0 Grant Management

Specifies target resource servers for access tokens.

| Feature              | Status | Notes                           |
|----------------------|--------|---------------------------------|
| resource Parameter   | ❌     | In authorization request        |
| Multiple Resources   | ❌     | Repeated resource parameter     |
| invalid_target Error | ❌     | Invalid resource error response |

**Purpose**:

- Binds access tokens to specific resource servers
- Prevents token misuse across APIs
- Required for fine-grained authorization

---

### RFC 7800: Proof-of-Possession Key Semantics for JWTs

**Status**: Not Implemented

**Required for**: DPoP/mTLS sender constraint

Defines the `cnf` (confirmation) claim for token binding.

| Feature                | Status | Notes                        |
|------------------------|--------|------------------------------|
| cnf Claim              | ❌     | Confirmation claim in JWT    |
| JWK Thumbprint         | ❌     | jkt confirmation method      |
| Certificate Thumbprint | ❌     | x5t#S256 confirmation method |

**Purpose**:

- Binds access tokens to proof-of-possession keys
- Used by DPoP (JWK thumbprint) and mTLS (certificate thumbprint)
- Resource servers verify binding

---

### RFC 9101: JWT Secured Authorization Request (JAR)

**Status**: Not Implemented

**Required for**: FAPI 1.0 Advanced, FAPI 2.0 Message Signing

JWT-secured authorization request parameters.

| Feature                | Status | Notes                          |
|------------------------|--------|--------------------------------|
| Request Object JWT     | ❌     | Signed authorization request   |
| request Parameter      | ❌     | JWT in authorization request   |
| Request Object Claims  | ❌     | response_type, client_id, etc. |
| Signature Verification | ❌     | AS validates JWT signature     |

**Required Claims**:

- `iss` - Client identifier
- `aud` - Authorization server issuer
- `exp` - Expiration time
- `nbf` - Not valid before
- `jti` - JWT ID (replay protection)
- Authorization request parameters (response_type, client_id, redirect_uri, scope, state, nonce, code_challenge)

**FAPI Requirements**:

- `alg=none` forbidden
- RS256 forbidden for FAPI Advanced
- PS256 or ES256 required

---

### RFC 9700: OAuth 2.0 Security Best Current Practice

**Status**: Partially Implemented

**Required for**: OAuth 2.1, FAPI 2.0

Security recommendations for OAuth 2.0 deployments.

| Recommendation            | Status | Notes                        |
|---------------------------|--------|------------------------------|
| Authorization Code Flow   | ✅     | Primary flow                 |
| PKCE S256 Required        | ✅     | Mandatory for public clients |
| Exact Redirect URI        | ✅     | No wildcards                 |
| state Parameter           | ✅     | CSRF protection              |
| No Implicit Grant         | ✅     | Not supported                |
| No Password Grant         | ✅     | Not supported                |
| Sender-Constrained Tokens | ✅     | DPoP, mTLS supported         |
| Short-Lived Tokens        | ⚠️     | Configurable, not enforced   |
| Refresh Token Rotation    | ❌     | Not implemented              |

---

### RFC 9701: JWT Response for OAuth Token Introspection

**Status**: Not Implemented

**Required for**: Enhanced introspection security

JWT-formatted introspection responses.

| Feature                    | Status | Notes                            |
|----------------------------|--------|----------------------------------|
| JWT Introspection Response | ❌     | Signed response from AS          |
| Response Claims            | ❌     | iss, aud, exp, iat, active, etc. |
| Signature Verification     | ❌     | RS validates JWT signature       |

---

## JWT/JWS/JWKS Specifications

### RFC 7519: JSON Web Token (JWT)

**Status**: Implemented

JSON Web Token parsing and claims.

| Feature           | Status | Notes                   |
|-------------------|--------|-------------------------|
| JWT Parsing       | ✅     | go-jose library         |
| Claims Validation | ✅     | iss, sub, aud, exp, iat |
| Clock Skew        | ✅     | Configurable tolerance  |

**Implementation**:

- `rp/idtoken.go` - ID Token parsing and validation

---

### RFC 7515: JSON Web Signature (JWS)

**Status**: Implemented

JSON Web Signature for token signing.

| Algorithm | Status | Notes                |
|-----------|--------|----------------------|
| RS256     | ✅     | RSA with SHA-256     |
| RS384     | ✅     | RSA with SHA-384     |
| RS512     | ✅     | RSA with SHA-512     |
| PS256     | ✅     | RSA-PSS with SHA-256 |
| PS384     | ✅     | RSA-PSS with SHA-384 |
| PS512     | ✅     | RSA-PSS with SHA-512 |
| ES256     | ✅     | ECDSA with SHA-256   |
| ES384     | ✅     | ECDSA with SHA-384   |
| ES512     | ✅     | ECDSA with SHA-512   |

**Implementation**:

- `rp/idtoken.go` - Signature verification
- `rp/par.go` - Client assertion signing
- `rp/dpop.go` - DPoP proof signing

---

### RFC 7517: JSON Web Key (JWK)

**Status**: Implemented

JSON Web Key and Key Set handling.

| Feature           | Status | Notes             |
|-------------------|--------|-------------------|
| JWKS Fetching     | ✅     | Remote key set    |
| Key Rotation      | ✅     | Automatic refresh |
| Key Caching       | ✅     | ETag support, TTL |
| Single Key Lookup | ✅     | By kid            |

**Implementation**:

- `jwks/remote_keyset.go` - Remote key set
- `jwks/http_fetch.go` - HTTP fetching with caching

---

## Related Specifications

### RFC 7033: WebFinger

**Status**: Implemented

WebFinger protocol for issuer discovery.

| Feature              | Status | Notes                 |
|----------------------|--------|-----------------------|
| WebFinger Request    | ✅     | .well-known/webfinger |
| Issuer Link Relation | ✅     | OpenID Connect issuer |
| Resource Types       | ✅     | acct:, https: URLs    |

**Implementation**:

- `oidc/webfinger.go` - WebFinger discovery

---

## FAPI Specifications

### FAPI 1.0 Advanced

**Status**: Not Implemented

Financial-grade API Part 2: Advanced security profile.

| Feature                     | Status | Notes                          |
|-----------------------------|--------|--------------------------------|
| private_key_jwt Auth        | ✅     | Required client auth method    |
| tls_client_auth             | ✅     | Alternative client auth method |
| mTLS Sender Constraint      | ✅     | Required for access tokens     |
| PAR                         | ✅     | Pushed Authorization Requests  |
| PKCE                        | ✅     | Required with PAR              |
| JAR                         | ❌     | Signed request object required |
| JARM                        | ❌     | JWT response mode required     |
| Hybrid Flow (code id_token) | ❌     | response_type=code id_token    |
| PS256/ES256 Only            | ✅     | RS256 forbidden for signing    |
| nonce Required              | ✅     | For OIDC flows                 |

**Required Algorithms**:

- ID Token: PS256 or ES256
- Request Object: PS256 or ES256
- Client Assertion: PS256 or ES256
- RS256: NOT permitted

**Required Specifications**:

- All OAuth 2.0 Core
- OpenID Connect Core 1.0
- PKCE (RFC 7636)
- PAR (RFC 9126)
- mTLS (RFC 8705)
- JAR (RFC 9101)
- JARM
- private_key_jwt (RFC 7523)

---

### FAPI 2.0 Security Profile

**Status**: Implemented (Conformance Testing)

Financial-grade API security profile.

| Feature                 | Status | Notes                |
|-------------------------|--------|----------------------|
| private_key_jwt         | ✅     | JWT client assertion |
| tls_client_auth         | ✅     | mTLS client auth     |
| DPoP Sender Constraint  | ✅     | RFC 9449             |
| mTLS Sender Constraint  | ✅     | RFC 8705             |
| PAR                     | ✅     | Pushed Authorization |
| Authorization Code Flow | ✅     | With PKCE            |

**Conformance Profiles Tested**:

- `fapi2-security-profile-final-client-test-plan`
- `plain_fapi` variant

**Implementation**:

- `conformance/harness/` - Conformance test harness
- `rp/auth_method.go` - Client authentication methods
- `rp/dpop.go` - DPoP support
- `rp/par.go` - PAR support

---

### FAPI 2.0 Message Signing

**Status**: Implemented (Conformance Testing)

FAPI 2.0 profile with signed protocol messages.

| Feature              | Status | Notes                          |
|----------------------|--------|--------------------------------|
| All Security Profile | ✅     | Final profile support          |
| JAR                  | ✅     | Signed authorization requests  |
| JARM                 | ✅     | Signed authorization responses |
| PS256/ES256 Signing  | ✅     | Conformance-tested             |

**Conformance Profiles Tested**:

- `fapi2-message-signing-final-client-test-plan`
- `plain_fapi` variant
- `fapi2-ms-final-plain-fapi-jar4`
- `fapi2-ms-final-plain-fapi-jarm4`

**Implementation**:

- `rp/request_object.go` - JAR request object construction and signing
- `rp/jarm.go` - JARM validation and callback normalization
- `rp/par.go` - PAR transport for signed request objects
- `conformance/harness/matrix.go` - message-signing final matrices
- `conformance/harness/execute.go` - negative-case handling for JARM tests

**Required for**:

- Integrity protection of authorization requests
- Integrity protection of authorization responses
- Prevention of request/response tampering

---

### FAPI 2.0 Grant Management

**Status**: Not Implemented

OAuth extension for grant lifecycle management.

| Feature                   | Status | Notes                      |
|---------------------------|--------|----------------------------|
| Grant Management Endpoint | ❌     | Query/update/revoke grants |
| Grant Identifier          | ❌     | grant_id for reuse         |
| Grant Update              | ❌     | Rolling/updating grants    |

**Purpose**:

- Reuse existing grants/consent
- Manage long-lived consent
- Regulatory compliance for consent tracking

---

### OpenID Connect for Identity Assurance

**Status**: Not Implemented

**Required for**: Identity-proofing ecosystems

Verified identity claims for identity assurance.

| Feature             | Status | Notes                      |
|---------------------|--------|----------------------------|
| verified_claims     | ❌     | Verified identity claims   |
| Evidence Structures | ❌     | Identity proofing evidence |
| Trust Framework     | ❌     | Trust framework metadata   |

---

## OAuth 2.1 Specification

### OAuth 2.1 (draft-ietf-oauth-v2-1)

**Status**: Implemented

Consolidated OAuth 2.0 with security best practices.

| Feature                     | Status | Notes                            |
|-----------------------------|--------|----------------------------------|
| Authorization Code Flow     | ✅     | Primary flow (mandatory)         |
| PKCE Required               | ✅     | S256 mandatory                   |
| No Implicit Grant           | ✅     | Not supported                    |
| No Password Grant           | ✅     | Not supported                    |
| Exact Redirect URI Matching | ✅     | Enforced                         |
| state Parameter             | ✅     | CSRF protection                  |
| Client Credentials Grant    | ✅     | Supported                        |
| Refresh Token Grant         | ⚠️     | Supported, rotation not enforced |
| Sender-Constrained Tokens   | ✅     | DPoP, mTLS supported             |
| TLS Everywhere              | ✅     | HTTPS enforced                   |

**Implementation Notes**:

- Lanyard is OAuth 2.1 compliant for Authorization Code flow
- PKCE is mandatory and enforced
- Legacy flows (implicit, password) are not supported

---

## Client Authentication Methods

| Method              | Status | Specification   | Notes            | FAPI 1.0 Adv | FAPI 2.0 |
|---------------------|--------|-----------------|------------------|--------------|----------|
| client_secret_basic | ✅     | RFC 6749 §2.3.1 | HTTP Basic Auth  | ❌           | ❌       |
| client_secret_post  | ✅     | RFC 6749 §2.3.1 | Form parameters  | ❌           | ❌       |
| private_key_jwt     | ✅     | RFC 7523        | JWT assertion    | ✅           | ✅       |
| tls_client_auth     | ✅     | RFC 8705        | mTLS certificate | ✅           | ✅       |

**Implementation**:

- `rp/auth_method.go` - Authentication method definitions
- `rp/token_exchange.go` - Auth method handling

**FAPI Note**: FAPI profiles require asymmetric client authentication (private_key_jwt or tls_client_auth). Shared-secret methods (client_secret_basic, client_secret_post) are not permitted.

---

## Sender Constraint Methods

| Method | Status | Specification | Notes               | FAPI 1.0 Adv | FAPI 2.0 |
|--------|--------|---------------|---------------------|--------------|----------|
| mTLS   | ✅     | RFC 8705      | Certificate-bound   | ✅ Required  | ✅       |
| DPoP   | ✅     | RFC 9449      | Proof-of-possession | ❌           | ✅       |

**FAPI 1.0 Advanced**: mTLS sender constraint is required for access tokens.

**FAPI 2.0**: Either mTLS or DPoP sender constraint is required.

---

## Conformance Testing

### OpenID Foundation Conformance Suite

**Status**: Active

Lanyard includes automated conformance testing against the OpenID Foundation conformance suite.

**Latest Verified Results**:

| Profile                   | Variant         | Module/Test                                            | Result               | Notes                                                                                                                                           |
|---------------------------|-----------------|--------------------------------------------------------|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| FAPI 2.0 Security Profile | `plain_fapi-01` | `fapi2-security-profile-final-client-test-happy-path`  | ✅ Passed            | Verified after fixing the RP to call the suite `accounts_endpoint` during the FAPI happy path.                                                  |
| FAPI 2.0 Security Profile | `plain_fapi-01` | `fapi2-security-profile-final-client-test-invalid-iss` | ⚠️ Behavior observed | RP rejected the invalid issuer with `id token validation failed: issuer mismatch`, but the full module result was not captured in this session. |
| FAPI 2.0 Security Profile | `plain_fapi-02` | DPoP sender-constrained flow                           | ❌ Failing           | Suite reported `Couldn't parse incoming_dpop_proof from incoming_request as a JWT`; DPoP proof generation still needs investigation.            |

**Test Profiles**:

- `oidc-rp` - OpenID Connect Core RP tests
- `fapi-rp` - FAPI 2.0 RP tests
- `all-rp` - All available RP profiles

**Test Plans**:

- `oidcc-client-basic-certification-test-plan` - Basic RP profile
- `fapi2-security-profile-final-client-test-plan` - FAPI 2.0 Security Profile

**Implementation**:

- `conformance/harness/` - Test harness
- `conformance/README.md` - Setup and execution guide
- `conformance/SUITE_API.md` - Suite API documentation

---

## Summary Table

### Implemented Specifications

| Specification                           | RFC/Standard          | Status |
|-----------------------------------------|-----------------------|--------|
| OpenID Connect Core 1.0                 | OpenID                | ✅     |
| OpenID Connect Discovery 1.0            | OpenID                | ✅     |
| OAuth 2.0 Authorization Framework       | RFC 6749              | ✅     |
| OAuth 2.0 Bearer Token Usage            | RFC 6750              | ✅     |
| OAuth 2.0 PKCE                          | RFC 7636              | ✅     |
| OAuth 2.0 Authorization Server Metadata | RFC 8414              | ✅     |
| OAuth 2.0 Token Exchange                | RFC 8693              | ✅     |
| OAuth 2.0 Mutual-TLS Client Auth        | RFC 8705              | ✅     |
| OAuth 2.0 Pushed Authorization Requests | RFC 9126              | ✅     |
| OAuth 2.0 DPoP                          | RFC 9449              | ✅     |
| JWT Profile for OAuth 2.0               | RFC 7523              | ✅     |
| OAuth 2.1                               | draft-ietf-oauth-v2-1 | ✅     |
| JSON Web Token                          | RFC 7519              | ✅     |
| JSON Web Signature                      | RFC 7515              | ✅     |
| JSON Web Key                            | RFC 7517              | ✅     |
| WebFinger                               | RFC 7033              | ✅     |
| FAPI 2.0 Security Profile               | OpenID FAPI           | ✅     |

### Not Implemented (Required for Target Profiles)

| Specification                           | RFC/Standard | Required For                                |
|-----------------------------------------|--------------|---------------------------------------------|
| JWT Secured Authorization Request (JAR) | RFC 9101     | FAPI 1.0 Advanced, FAPI 2.0 Message Signing |
| JARM                                    | OpenID       | FAPI 1.0 Advanced, FAPI 2.0 Message Signing |
| Resource Indicators                     | RFC 8707     | FAPI 2.0 Grant Management                   |
| PoP Key Semantics (cnf claim)           | RFC 7800     | DPoP/mTLS sender constraint                 |
| JWT Introspection Response              | RFC 9701     | Enhanced introspection                      |
| Refresh Token Rotation                  | RFC 9700     | OAuth 2.0 Security BCP                      |
| Hybrid Flow (code id_token)             | OpenID Core  | FAPI 1.0 Advanced                           |
| FAPI 1.0 Advanced                       | OpenID FAPI  | Full FAPI 1.0 Advanced profile              |
| FAPI 2.0 Message Signing                | OpenID FAPI  | FAPI 2.0 with message signing               |
| FAPI 2.0 Grant Management               | OpenID FAPI  | Grant lifecycle management                  |
| OpenID Connect for Identity Assurance   | OpenID       | Identity-proofing ecosystems                |

---

## Legend

- ✅ Fully implemented
- ⚠️ Partially implemented or configurable
- ❌ Not implemented
