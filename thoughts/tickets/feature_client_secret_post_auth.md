---
type: feature
priority: medium
created: 2026-02-24T12:00:00Z
status: implemented
tags: [oauth2, authentication, token-endpoint, client-auth]
keywords: [client_secret_post, client_secret_basic, TokenEndpointAuthMethods, exchangeToken, SetBasicAuth, WithAuthMethod]
patterns: [token exchange, http request auth, client constructor options, provider metadata]
research_document: thoughts/research/2026-02-24_client_secret_post_auth.md
---

# FEATURE-001: Add client_secret_post OAuth2 Client Authentication

## Description

Add support for `client_secret_post` OAuth2 client authentication method in addition to the existing `client_secret_basic`. The client constructor should accept an option to configure the authentication method, with automatic detection from provider metadata and graceful fallback behavior.

## Context

Currently, the library hardcodes `client_secret_basic` authentication in the token exchange flow using `req.SetBasicAuth()`. Some OAuth2/OIDC providers (e.g., Google, Azure AD in certain configurations) prefer or require `client_secret_post`, where credentials are sent in the request body rather than the Authorization header.

The OAuth 2.0 spec defines multiple token endpoint authentication methods, and a production-ready library should support the most common ones.

## Requirements

### Functional Requirements

1. **AuthMethod Type**: Define a typed constant for auth methods
   - `AuthMethodBasic` - existing `client_secret_basic` 
   - `AuthMethodPost` - new `client_secret_post`
   - Design should be extensible for future methods (e.g., `client_secret_jwt`, `private_key_jwt`)

2. **Configuration Option**: Add `WithAuthMethod(AuthMethod)` option to RP constructor
   - Default: auto-detect from provider metadata
   - Explicit override allowed

3. **Auto-Negotiation**: Automatically select auth method from provider's `token_endpoint_auth_methods_supported` metadata
   - Priority order: prefer POST over Basic
   - Validate against provider metadata, return typed error if unsupported

4. **Fallback Behavior**: When metadata unavailable and auto-detect fails
   - Try POST first
   - Fallback to Basic if POST fails
   - Cache successful method in-memory for RP instance lifetime

5. **Detection Timing**: Auth method detection/validation at construction time
   - Fail fast if provider doesn't support chosen method
   - Return typed error for auth method validation failures

6. **Validation**: 
   - Return error at construction if `client_secret_post` selected but no client secret provided

### Non-Functional Requirements

- **Backward Compatibility**: Existing code without auth method specification must work unchanged
- **Performance**: In-memory caching of successful auth method (no external cache needed)
- **Extensibility**: Design pattern should support future auth methods without major refactoring

### Scope Boundaries

**In Scope:**
- Token endpoint authentication only
- `client_secret_basic` and `client_secret_post` methods
- Auto-negotiation from provider metadata
- Full backward compatibility

**Out of Scope:**
- Public client support (`none` auth method)
- Revocation endpoint authentication
- Introspection endpoint authentication
- `client_secret_jwt` or `private_key_jwt` methods (extensible design only)
- Persistent/auth method caching across RP instances

## Current State

**File: `rp/token_exchange.go:26`**
```go
func (r *RP) exchangeToken(ctx context.Context, tokenEndpoint, code, verifier string) (TokenResponse, error) {
    // ...
    req.SetBasicAuth(r.clientID, r.clientSecret)  // Hardcoded client_secret_basic
    // ...
}
```

**File: `rp/rp.go`**
- RP struct has no field for auth method
- No option to configure auth method

**File: `oidc/metadata_oauth_as.go:17-18`**
- `TokenEndpointAuthMethodsSupported` is parsed but not used

## Desired State

1. **New AuthMethod type** in `rp/` package:
   ```go
   type AuthMethod string
   const (
       AuthMethodBasic AuthMethod = "client_secret_basic"
       AuthMethodPost  AuthMethod = "client_secret_post"
   )
   ```

2. **New typed error** for auth method validation:
   ```go
   type AuthMethodError struct {
       Method   AuthMethod
       Supported []string
   }
   ```

3. **Updated RP struct** with auth method field and resolved method cache

4. **New option**: `WithAuthMethod(method AuthMethod) Option`

5. **Updated `exchangeToken`** to use configured/detected auth method

6. **Auto-negotiation logic** at construction time using provider metadata

## Research Context

### Keywords to Search

- `client_secret_post` - OAuth2 spec method name to implement
- `client_secret_basic` - Current implementation to maintain
- `TokenEndpointAuthMethodsSupported` - Metadata field for auto-negotiation
- `exchangeToken` - Function that needs modification
- `SetBasicAuth` - Current auth mechanism to make conditional
- `WithAuthMethod` - New option pattern to follow
- `New(` - Constructor to extend with auth method logic

### Patterns to Investigate

- `req.SetBasicAuth` in `rp/token_exchange.go` - Where auth is applied, needs to become conditional
- `Option` pattern in `rp/options.go` - How to add new configuration option
- `AuthorizationServerMetadata` in `oidc/metadata_oauth_as.go` - Source of supported auth methods
- Error types in `rp/errors.go` - Pattern for typed errors
- Test patterns in `rp/token_exchange_test.go` - How to extend existing tests

### Key Decisions Made

| Decision | Rationale |
|----------|-----------|
| Prefer POST over Basic | More modern, some providers require it |
| Auto-detect from metadata | Reduces configuration burden, matches provider capabilities |
| Fail fast at construction | Better developer experience, catch errors early |
| In-memory cache only | Simplicity, RP instance typically short-lived |
| Typed AuthMethod constants | Type safety, IDE autocomplete, extensible |
| Token endpoint only | Keep scope minimal, other endpoints can follow same pattern later |
| Full backward compatibility | Existing users unaffected, adoption friction minimal |

## Success Criteria

### Automated Verification

- [ ] `go test ./rp/...` passes with new tests for POST auth
- [ ] Existing `TestExchangeTokenRequestShape` continues to pass (Basic auth)
- [ ] New test verifies POST auth sends credentials in body
- [ ] New test verifies auto-negotiation from metadata
- [ ] New test verifies fallback behavior
- [ ] New test verifies error when unsupported method configured
- [ ] New test verifies error when secret missing for secret-based method

### Manual Verification

- [ ] Can create RP with `WithAuthMethod(AuthMethodPost)`
- [ ] Token exchange uses POST body for credentials when configured
- [ ] Existing code without auth method config works unchanged
- [ ] Error message is clear when provider doesn't support configured method

## Related Information

- OAuth 2.0 RFC 6749 Section 2.3.1 (Client Authentication)
- OpenID Connect Discovery 1.0 Section 3 (Metadata)
- `token_endpoint_auth_methods_supported` metadata field

## Notes

### Implementation Hints

1. Add `authMethod AuthMethod` and `resolvedAuthMethod AuthMethod` fields to RP struct
2. Create `resolveAuthMethod()` called during `New()` construction
3. Modify `exchangeToken()` to check `resolvedAuthMethod` and apply appropriate auth
4. For POST: add `client_id` and `client_secret` to form data instead of Authorization header
5. Cache resolved method after first successful token exchange (for fallback scenario)

### Files to Modify

| File | Changes |
|------|---------|
| `rp/rp.go` | Add auth method fields to RP struct, add resolution logic in New() |
| `rp/options.go` | Add `WithAuthMethod` option |
| `rp/token_exchange.go` | Make auth method conditional |
| `rp/errors.go` | Add `AuthMethodError` type |
| `rp/token_exchange_test.go` | Add tests for POST auth and auto-negotiation |
