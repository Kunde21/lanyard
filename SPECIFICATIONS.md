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

- `metadata/discovery.go` - Provider discovery
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

- `metadata/provider.go` - Provider metadata
- `metadata/validate.go` - Metadata validation
- `metadata/webfinger.go` - WebFinger discovery

---

### JARM (JWT Secured Authorization Response Mode)

**Status**: Implemented

**Required for**: FAPI 1.0 Advanced, FAPI 2.0 Message Signing

JWT-wrapped authorization responses for integrity protection.

| Feature             | Status | Notes                           |
|---------------------|--------|---------------------------------|
| query.jwt mode      | ✅     | JWT in query parameter          |
| fragment.jwt mode   | ✅     | JWT in fragment                 |
| form_post.jwt mode  | ✅     | JWT in form POST                |
| Response JWT Claims | ✅     | iss, aud, exp, iat, code, state |
| Response Signature  | ✅     | AS-signed response verification |

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

- `metadata/well_known.go` - Well-known URL construction
- `metadata/authorization_server.go` - Authorization server metadata
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
- `metadata/authorization_server.go` - MTLSEndpointAliases
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

**Status**: Implemented

Audience-restricted access tokens via target resource server indicators.

| Feature                | Status | Notes                                             |
|------------------------|--------|---------------------------------------------------|
| resource Parameter     | ✅     | Authorization request (query + request object)    |
| Multiple Resources     | ✅     | Repeated `resource` parameter                     |
| Token Endpoint Support | ✅     | client_credentials, refresh_token, token_exchange |
| Per-Request Override   | ✅     | `WithTokenResources` via context                  |
| Resource Validation    | ✅     | Absolute URI, no fragment                         |
| invalid_target Error   | ⚠️     | Propagated via standard token error path          |

**Implementation**:

- `rp/resource_indicators.go` - Validation and parameter helpers
- `rp/options.go` - `WithResources`, `SetResources`
- `rp/token_source.go` - `WithTokenResources` (per-request context override)
- `rp/authrequest.go`, `rp/par.go`, `rp/request_object.go` - Authorization request wiring
- `rp/client_credentials.go`, `rp/refresh_token.go`, `rp/token_exchange.go` - Token endpoint wiring

**Purpose**:

- Binds access tokens to specific resource servers
- Prevents token misuse across APIs
- Foundation for fine-grained authorization and FAPI 2.0 Grant Management

---

### RFC 7800: Proof-of-Possession Key Semantics for JWTs

**Status**: Implemented

**Required for**: DPoP/mTLS sender constraint

Defines the `cnf` (confirmation) claim binding a JWT to a proof-of-possession key.

| Feature                | Status | Notes                                              |
|------------------------|--------|----------------------------------------------------|
| cnf Claim Parsing      | ✅     | All members: jkt, x5t#S256, jwk, jku, x5c, x5u, x5t, kid, jwe |
| JWK Thumbprint (jkt)   | ✅     | RFC 7638 via go-jose, RSA + EC P-256/384/521       |
| X.509 Cert (x5t#S256)  | ✅     | SHA-256 DER thumbprint for mTLS                    |
| DPoP Binding Verify    | ✅     | Confirmation.VerifyDPoPBinding (constant-time)     |
| mTLS Binding Verify    | ✅     | Confirmation.VerifyMTLSBinding (constant-time)     |
| ID Token cnf           | ✅     | Parsed on id_token, exposed via CallbackResult.Cnf |
| Access Token cnf       | ⚠️     | ParseAccessTokenConfirmation decodes WITHOUT signature verification |
| Introspection cnf      | ✅     | Parsed on IntrospectionResponse; passthrough, no auto enforcement |

**Implementation**:

- `rp/confirmation.go` - `Confirmation` type, `JWKThumbprint`, `X509CertThumbprint`, `Verify*Binding`, `ParseAccessTokenConfirmation`
- `rp/idtoken.go` - `cnf` on id_token claims
- `rp/dpop.go` - canonical JWK construction shared with thumbprint computation, `RP.DPoPKeyThumbprint`

**Purpose**:

- Binds access tokens to proof-of-possession keys
- Used by DPoP (JWK thumbprint) and mTLS (certificate thumbprint)
- Callers verify binding via `Confirmation.Verify*` methods

---

### RFC 9101: JWT Secured Authorization Request (JAR)

**Status**: Implemented

**Required for**: FAPI 1.0 Advanced, FAPI 2.0 Message Signing

JWT-secured authorization request parameters.

| Feature                | Status | Notes                          |
|------------------------|--------|--------------------------------|
| Request Object JWT     | ✅     | Signed authorization request   |
| request Parameter      | ✅     | JWT in authorization request   |
| Request Object Claims  | ✅     | response_type, client_id, etc. |
| Signature Verification | ✅     | AS validates JWT signature     |

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
| Refresh Token Rotation    | ✅     | RefreshTokenSource + ErrRefreshTokenRejected |

---

### FAPI 2.0 Grant Management (draft-ietf-oauth-grant-management)

**Status**: Implemented

Explicit grant lifecycle management: reference, create, merge, replace,
query, and revoke grants via grant_id.

| Feature                        | Status | Notes                                                   |
|--------------------------------|--------|---------------------------------------------------------|
| Authorization Request Params   | ✅     | grant_id, grant_management_action (query, PAR, JAR)     |
| Actions                        | ✅     | create, merge, replace + FAPI ID1 update alias          |
| action_required Enforcement    | ✅     | grant_management_action_required metadata              |
| Token Response grant_id        | ✅     | Token.GrantID, CallbackResult.GrantID                   |
| Query API (GET)                | ✅     | RP.QueryGrant / NewGrantManager, Bearer token           |
| Revoke API (DELETE)            | ✅     | RP.RevokeGrant                                          |
| Grant Status                   | ✅     | scopes+resource (both spellings), claims, RAR details, timestamps |
| invalid_grant_id Error         | ✅     | ErrInvalidGrantID at callback                           |
| Refresh Invalidation Handling  | ✅     | RefreshTokenSource.Replace after merge/replace          |
| DPoP on Grant API              | ✅     | Proof bound to the grant management access token        |

**Implementation**:

- `rp/grant_management_request.go` - actions, validation, authorization request parameters
- `rp/grant_management.go` - GrantManager, QueryGrant, RevokeGrant, GrantStatus
- `rp/options.go` - SetGrantManagementAction, SetGrantID

---

### OpenID Connect for Identity Assurance 1.0

**Status**: Implemented

Request and consume verified end-user claims with verification metadata.

| Feature                        | Status | Notes                                                        |
|--------------------------------|--------|--------------------------------------------------------------|
| Claims Request Parameter       | ✅     | WithClaims/SetClaims (OIDC Core 5.5, query + PAR + JAR)      |
| verified_claims Request        | ✅     | Typed filters incl. evidence/check_details, value/values/max_age |
| Claim Sets (Array Form)        | ✅     | Different verification requirements per set                  |
| ID Token Delivery              | ✅     | CallbackResult.VerifiedClaims                               |
| UserInfo Delivery              | ✅     | ParseVerifiedClaims (object or array)                        |
| Verification Metadata          | ✅     | Typed trust framework/level, evidence, check details + DecodeRaw |
| max_age Freshness              | ✅     | Verification.FreshFor (section 5.5.2 semantics)              |
| OP Metadata                    | ✅     | trust frameworks, evidence, documents (both method spellings) |

**Implementation**:

- `rp/claims_parameter.go` plumbing in `rp/options.go`, `rp/authrequest.go`, `rp/par.go`, `rp/request_object.go`
- `rp/identity_assurance_request.go` - request builders
- `rp/identity_assurance.go` - response types, parsing, freshness

---

### RFC 7591/7592: OAuth 2.0 Dynamic Client Registration (+ Management)

**Status**: Implemented

Self-registration of clients at the authorization server and lifecycle
management of the resulting registration.

| Feature                        | Status | Notes                                                  |
|--------------------------------|--------|--------------------------------------------------------|
| Registration (POST)            | ✅     | Registrar.Register, initial access token support       |
| Client Metadata Request        | ✅     | ClientMetadata incl. software_statement passthrough    |
| Registration Response          | ✅     | ClientRegistration + DecodeRaw; SecretExpired (0=never) |
| Read Management (GET)          | ✅     | Registrar.Read with registration access token          |
| Update / Secret Rotation (PUT) | ✅     | Registrar.Update; ClientUpdate requires client_id      |
| Delete (DELETE)                | ✅     | Registrar.Delete                                       |
| Error Codes                    | ✅     | invalid_redirect_uri, invalid_client_metadata, etc. via *OAuthError |
| MTLS Registration Alias        | ✅     | mtls_endpoint_aliases.registration_endpoint            |
| RP Bridging                    | ✅     | ClientRegistration.Options() into New                  |

**Implementation**:

- `rp/dynamic_registration.go` - ClientMetadata, ClientRegistration, Registrar, ClientUpdate
- `rp/options.go` - WithInitialAccessToken

---

### RFC 7662: OAuth 2.0 Token Introspection

**Status**: Implemented

Resource-server style token state queries.

| Feature                      | Status | Notes                                                   |
|------------------------------|--------|---------------------------------------------------------|
| Introspection Endpoint       | ✅     | `NewIntrospector`, `RP.IntrospectToken`                 |
| Client Auth Methods          | ✅     | All supported methods + introspection-specific metadata |
| active:false Handling        | ✅     | Returned as successful response, not an error           |
| cnf Claim                    | ✅     | RFC 7800 binding parsed (see RFC 7800 section)          |

---

### RFC 9701: JWT Response for OAuth Token Introspection

**Status**: Implemented

**Required for**: Enhanced introspection security

JWT-formatted introspection responses, requested via `PreferJWTResponse`
(`Accept: application/token-introspection+jwt`).

| Feature                     | Status | Notes                                                    |
|-----------------------------|--------|----------------------------------------------------------|
| Signed Response             | ✅     | Signature, typ, alg allowlist verified against AS JWKS   |
| Response Claims             | ✅     | iss, aud, iat (required), token_introspection             |
| Signature Verification      | ✅     | kid lookup; exactly-one-key rule for kid-less tokens      |
| Encrypted (Nested JWT)      | ✅     | With `WithIntrospectionDecryptionKey`; safe alg allowlist |
| Provider Algorithm Metadata | ✅     | introspection_signing_alg_values_supported enforced       |

**Implementation**:

- `rp/introspection.go` - `validateIntrospectionJWT` (signed), `decryptIntrospectionJWE` (nested)
- `rp/options.go` - `WithIntrospectionDecryptionKey` (RSA-OAEP, RSA-OAEP-256, ECDH-ES family; RSA1_5 rejected)

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

- `metadata/webfinger.go` - WebFinger discovery

---

## FAPI Specifications

### FAPI 1.0 Advanced

**Status**: Implemented (Conformance Verified)

Financial-grade API Part 2: Advanced security profile.

| Feature                     | Status | Notes                          |
|-----------------------------|--------|--------------------------------|
| private_key_jwt Auth        | ✅     | Required client auth method    |
| tls_client_auth             | ✅     | Alternative client auth method |
| mTLS Sender Constraint      | ✅     | Required for access tokens     |
| PAR                         | ✅     | Pushed Authorization Requests  |
| PKCE                        | ✅     | Required with PAR              |
| JAR                         | ✅     | Signed request object required |
| JARM                        | ✅     | JWT response mode required     |
| Hybrid Flow (code id_token) | ✅     | response_type=code id_token    |
| PS256/ES256 Only            | ✅     | RS256 forbidden for signing    |
| nonce Required              | ✅     | For OIDC flows                 |

**Conformance Profiles Tested**:

- `fapi1-advanced-final-client-test-plan`
- `fapi1-adv-final-first4`
- `fapi1-adv-final-all12`

**Verification**:

- smoke matrix: `4/4` plans passed
- full `all12` matrix: `12/12` plans passed

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

**Status**: Implemented (Conformance Verified)

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
- `fapi2-sp-final-plain-fapi-all16`

**Verification**:

- full `all16` matrix: `16/16` plans passed

**Implementation**:

- `conformance/harness/` - Conformance test harness
- `rp/auth_method.go` - Client authentication methods
- `rp/dpop.go` - DPoP support
- `rp/par.go` - PAR support

---

### FAPI 2.0 Message Signing

**Status**: Implemented (Conformance Verified)

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
- `fapi2-ms-final-plain-fapi-all32`

**Verification**:

- `jar4` smoke matrix: `4/4` plans passed
- `jarm4` smoke matrix: `4/4` plans passed
- full `all32` matrix: `32/32` plans passed

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
| client_secret_jwt   | ✅     | RFC 7523        | HMAC JWT assertion | ❌         | ❌       |
| private_key_jwt     | ✅     | RFC 7523        | JWT assertion    | ✅           | ✅       |
| tls_client_auth     | ✅     | RFC 8705        | mTLS certificate | ✅           | ✅       |
| self_signed_tls_client_auth | ✅ | OpenID / RFC 8705 ecosystem | Self-signed client cert over mTLS | ❌ | ❌ |

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

| Profile | Scope | Result | Notes |
|---------|-------|--------|-------|
| OpenID Connect Core RP | `oidcc-client-basic-certification-test-plan` | ✅ Passed | Included in the full suite run. |
| OpenID Connect Config RP | `oidcc-config-cert-all42` | ✅ Passed | `42/42` plans, `252/252` tests passed. |
| FAPI 1.0 Advanced Final | `fapi1-adv-final-all12` | ✅ Passed | `12/12` plans, `156/156` tests passed. |
| FAPI 2.0 Security Profile Final | `fapi2-sp-final-plain-fapi-all16` | ✅ Passed | `16/16` plans, `216/216` tests passed. |
| FAPI 2.0 Message Signing Final | `fapi2-ms-final-plain-fapi-all32` | ✅ Passed | `32/32` plans, `528/528` tests passed. |
| Full RP preset | `all-rp-full` | ✅ Passed | `104/104` plans, `1180/1180` tests passed. |

**Test Profiles**:

- `oidc-rp` - OpenID Connect Core RP tests
- `fapi-rp` - FAPI RP tests
- `all-rp` - All available RP profiles

**Test Plans**:

- `oidcc-client-basic-certification-test-plan` - Basic RP profile
- `oidcc-client-config-certification-test-plan` - OIDC configuration matrix profile
- `oidcc-client-formpost-basic-certification-test-plan` - OIDC form_post profile
- `fapi1-advanced-final-client-test-plan` - FAPI 1.0 Advanced Final
- `fapi2-security-profile-final-client-test-plan` - FAPI 2.0 Security Profile
- `fapi2-message-signing-final-client-test-plan` - FAPI 2.0 Message Signing Final

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
| PoP Key Semantics (cnf claim)           | RFC 7800              | ✅     |
| OAuth 2.0 Authorization Server Metadata | RFC 8414              | ✅     |
| OAuth 2.0 Token Exchange                | RFC 8693              | ✅     |
| OAuth 2.0 Mutual-TLS Client Auth        | RFC 8705              | ✅     |
| OAuth 2.0 Resource Indicators           | RFC 8707              | ✅     |
| OAuth 2.0 Pushed Authorization Requests | RFC 9126              | ✅     |
| OAuth 2.0 Token Introspection           | RFC 7662              | ✅     |
| Dynamic Client Registration + Mgmt     | RFC 7591/7592         | ✅     |
| FAPI 2.0 Grant Management               | OpenID FAPI / IETF draft | ✅  |
| JWT Introspection Response              | RFC 9701              | ✅     |
| OAuth 2.0 DPoP                          | RFC 9449              | ✅     |
| JWT Profile for OAuth 2.0               | RFC 7523              | ✅     |
| OAuth 2.1                               | draft-ietf-oauth-v2-1 | ✅     |
| JSON Web Token                          | RFC 7519              | ✅     |
| JSON Web Signature                      | RFC 7515              | ✅     |
| JSON Web Key                            | RFC 7517              | ✅     |
| WebFinger                               | RFC 7033              | ✅     |
| FAPI 1.0 Advanced                       | OpenID FAPI           | ✅     |
| FAPI 2.0 Security Profile               | OpenID FAPI           | ✅     |
| FAPI 2.0 Message Signing                | OpenID FAPI           | ✅     |
| OpenID Connect for Identity Assurance   | OpenID                | ✅     |
| JWT Secured Authorization Request (JAR) | RFC 9101              | ✅     |
| JARM                                    | OpenID                | ✅     |

### Not Implemented (Required for Target Profiles)

No remaining gaps. All specifications tracked in this document are implemented.

---

## Legend

- ✅ Fully implemented
- ⚠️ Partially implemented or configurable
- ❌ Not implemented
