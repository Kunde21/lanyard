---
type: feature
priority: high
created: 2026-02-22T00:00:00Z
status: implemented
tags: [oidc, discovery, fapi, jwks, metadata, client]
keywords: [OpenID Connect, Discovery, .well-known, openid-configuration, RFC 8414, FAPI, PAR, JARM, JWKS, jwks_uri, issuer, metadata]
patterns: [http client, caching, validation, key rotation, error types, thread safety]
---

# FEATURE-001: Implement OpenID Connect Discovery with FAPI Extensions

## Description

Implement a Go client library for OpenID Connect Discovery that fetches and validates provider metadata from the `.well-known/openid-configuration` endpoint. The implementation must support all FAPI extensions including PAR, JARM, Grant Management, and OIDC for Identity Assurance metadata.

This is a relying party (client) library - it fetches discovery documents from OIDC providers but does not implement OAuth/OIDC protocol flows.

## Context

This is the foundation for a Go OpenID Connect relying party library (lanyard). Discovery is the first step in establishing trust with an OIDC provider, allowing clients to dynamically configure endpoints, capabilities, and cryptographic keys.

FAPI (Financial-grade API) extensions are critical for high-security use cases in financial services and other regulated industries.

## Requirements

### Functional Requirements

**Core Discovery**
- Fetch OIDC Provider metadata from `.well-known/openid-configuration`
- Fetch OAuth Authorization Server metadata per RFC 8414
- Auto-construct well-known URL from issuer URL
- Parse JSON discovery documents into typed Go structures
- Validate discovery documents:
  - Issuer URL must match document source
  - Required fields must be present
  - Field values must be valid (with lenient parsing for unknown fields)

**JWKS Support**
- Fetch JSON Web Key Set from `jwks_uri` endpoint
- Support key rotation with caching and automatic refresh
- Key lookup by `kid` (Key ID)
- Thread-safe key access

**FAPI Extensions Support**
- PAR (Pushed Authorization Requests) metadata fields
- JARM (JWT Secured Authorization Response Mode) metadata fields
- FAPI 2.0 Grant Management metadata fields
- OIDC for Identity Assurance metadata fields
- All other FAPI extension metadata fields

**Caching & Refresh**
- Pluggable cache interface (minimal: Get/Set/Delete)
- Background/async refresh of discovery metadata
- Thread-safe concurrent access to cached data

**Error Handling**
- Rich error types with structured fields:
  - Issuer URL
  - Field name
  - Expected vs actual values
  - Validation error context

### Non-Functional Requirements

**Configuration**
- Custom HTTP client injection
- slog.Logger integration for structured logging

**Thread Safety**
- All public APIs must be safe for concurrent use

**Code Quality**
- Unit tests for parsing, validation, error types
- Integration tests with mock HTTP server
- Compliance tests using spec reference implementations
- Configurable provider list for compliance testing

### Out of Scope

- Authorization code flow implementation
- Token verification
- PAR request implementation (only metadata parsing)
- JARM response handling (only metadata parsing)
- Authorization/token URL building helpers
- Metrics/metrics hooks
- Built-in timeout and retry logic (user provides HTTP client)
- Concurrency-specific tests

## Current State

New project with empty go.mod. No existing discovery implementation.

## Desired State

A production-ready Go package that:
1. Exports a `Client` type for discovery operations
2. Supports both OIDC Provider and OAuth AS metadata with separate types
3. Includes JWKS fetching with key rotation
4. Has a minimal, pluggable cache interface
5. Provides rich validation errors
6. Is thread-safe
7. Includes comprehensive tests and examples

## Research Context

### Specifications to Reference

**Core Specifications**
- OpenID Connect Discovery 1.0 - https://openid.net/specs/openid-connect-discovery-1_0.html
- RFC 8414 - OAuth 2.0 Authorization Server Metadata - https://www.rfc-editor.org/rfc/rfc8414
- RFC 8414 defines `/.well-known/oauth-authorization-server`

**FAPI Specifications**
- FAPI 1.0 Advanced - https://openid.net/specs/openid-financial-api-part-2-1_0.html
- FAPI 2.0 Message Signing - https://openid.bitbucket.io/fapi/fapi-2_0-message-signing.html
- FAPI 2.0 Security Profile - https://openid.bitbucket.io/fapi/fapi-2_0-security-profile.html
- PAR (RFC 9126) - https://www.rfc-editor.org/rfc/rfc9126
- JARM - https://openid.net/specs/openid-financial-api-jarm.html
- Grant Management - https://openid.net/specs/fapi-grant-management.html
- OIDC for Identity Assurance - https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html

**Related Specifications**
- JWKS (RFC 7517) - https://www.rfc-editor.org/rfc/rfc7517
- Well-Known URIs (RFC 8615) - https://www.rfc-editor.org/rfc/rfc8615

### Keywords to Search

- `openid-configuration` - Core discovery endpoint path
- `oauth-authorization-server` - RFC 8414 metadata endpoint
- `issuer` - Provider identifier URL
- `jwks_uri` - URL to JWKS endpoint
- `metadata` - General metadata fields
- `pushed_authorization_request_endpoint` - PAR metadata
- `authorization_signing_alg_values_supported` - JARM metadata
- `grant_management_endpoint` - FAPI 2.0 metadata
- `verified_claims` - OIDC for IDA metadata

### Patterns to Investigate

**Go Patterns**
- Interface design for pluggable cache implementations
- slog.Logger integration patterns
- Thread-safe cache patterns (sync.RWMutex, sync.Map)
- HTTP client injection patterns
- Rich error type design with fmt.Formatter

**Discovery Patterns**
- Well-known URL construction (issuer normalization)
- Issuer validation against discovery document URL
- Required vs optional field handling
- Array field parsing (scopes, response_types, etc.)
- URL field validation

**JWKS Patterns**
- Key caching with TTL
- Key refresh strategies
- kid-based key lookup
- Key rotation handling

### Key Decisions Made

- **Separate types** for OAuth AS and OIDC Provider metadata (not unified)
- **Lenient parsing** - ignore unknown fields, don't reject
- **Minimal cache interface** - Get/Set/Delete only, no TTL/lifecycle in interface
- **slog.Logger** for structured logging (Go 1.21+)
- **Background refresh** - support async discovery metadata refresh
- **Client-only** - no server-side metadata serving
- **No URL helpers** - users build auth URLs themselves

## Success Criteria

### Automated Verification

- [ ] Unit tests pass: `go test ./...`
- [ ] Integration tests with mock HTTP server pass
- [ ] Code formatted: `gofumpt ./...`
- [ ] No vet issues: `go vet ./...`
- [ ] Compliance tests pass against spec reference implementations

### Manual Verification

- [ ] Can fetch discovery from major providers (Google, Okta, etc.)
- [ ] JWKS key rotation works correctly
- [ ] FAPI metadata fields parsed correctly
- [ ] Error messages are clear and actionable
- [ ] Examples compile and run successfully

## Examples to Include

1. **Basic usage** - Simple discovery document fetch
2. **FAPI usage** - Discovery with PAR/JARM metadata access
3. **JWKS key rotation** - Key fetching with rotation handling

## Related Information

- Package should be placed in `pkg/oidc` or `pkg/discovery`
- Consider sub-packages for JWKS (`pkg/jwks`) if complex enough
- Follow existing Go OIDC library patterns (coreos/go-oidc, zitadel/oidc)

## Notes

**Priority Fields from Core Discovery**
- issuer (required)
- authorization_endpoint (required for OIDC)
- token_endpoint
- userinfo_endpoint
- jwks_uri (required)
- response_types_supported (required)
- subject_types_supported (required)
- id_token_signing_alg_values_supported (required)

**Key FAPI Metadata Fields to Support**
- `pushed_authorization_request_endpoint` (PAR)
- `require_pushed_authorization_requests` (PAR)
- `authorization_signing_alg_values_supported` (JARM)
- `authorization_encryption_alg_values_supported` (JARM)
- `grant_management_endpoint` (FAPI 2.0)
- `grant_management_action_supported` (FAPI 2.0)
- `trust_frameworks_supported` (IDA)
- `evidence_supported` (IDA)
- `verified_claims_supported` (IDA)
