# RP API Cleanup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Shrink and clarify the public `rp` API by merging `TokenResponse` into `Token`, renaming metadata options, internalizing implementation-shaped exports, and simplifying RP discovery behavior.

**Architecture:** Keep `rp` centered on two caller stories: browser RP flow and client credentials. Use one public token model for all token endpoint responses, move incidental structs behind package-private boundaries, and make constructor-owned provider metadata authoritative so `AuthorizationURL` stops rediscovering on every call.

**Tech Stack:** Go, `go test`, `go doc`, `gofumpt`, existing `oidc`/`rp` packages, standard library HTTP tests

---

### Task 1: Lock in the intended public API with failing tests

**Files:**
- Create: `rp/public_api_external_test.go`
- Modify: `rp/authrequest_test.go`
- Modify: `rp/callback_test.go`
- Modify: `rp/client_credentials_test.go`
- Test: `rp/public_api_external_test.go`

**Step 1: Write the failing external API test**

Create `rp/public_api_external_test.go` with package `rp_test` and compile-time usage of the intended API:

```go
package rp_test

import (
    "context"
    "testing"

    "github.com/Kunde21/lanyard/oidc"
    "github.com/Kunde21/lanyard/rp"
)

func TestPublicAPIOptionNames(t *testing.T) {
    _ = rp.WithProviderMetadata(oidc.ProviderMetadata{})
    _ = rp.WithClientCredentialsProviderMetadata(oidc.ProviderMetadata{})

    tok := rp.Token{
        AccessToken:  "at",
        TokenType:    "Bearer",
        ExpiresIn:    3600,
        IDToken:      "id",
        RefreshToken: "rt",
        Scope:        "openid profile",
    }
    if tok.IDToken == "" {
        t.Fatalf("Token should expose IDToken for authorization code responses")
    }

    _, _ = rp.NewClientCredentials(context.Background(),
        "https://issuer.example.com",
        "client-id",
        "secret",
        rp.WithClientCredentialsProviderMetadata(oidc.ProviderMetadata{}),
    )
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./rp -run TestPublicAPIOptionNames -count=1`
Expected: FAIL because `WithProviderMetadata`, `WithClientCredentialsProviderMetadata`, and expanded `Token` do not exist yet.

**Step 3: Add a regression test for redundant discovery**

Extend `rp/authrequest_test.go` to count discovery calls and assert that `AuthorizationURL` does not perform a second discovery after `New` has already done one.

```go
func TestAuthorizationURLDoesNotRediscoverAfterNew(t *testing.T) {
    // count /.well-known/openid-configuration hits
    // construct RP with real discovery in New
    // call AuthorizationURL once
    // want discoveryCalls == 1
}
```

**Step 4: Add token-shape assertions for callback and client credentials flows**

Update existing tests to assume one shared token model:

- `rp/callback_test.go` should keep validating `IDToken` presence through the unified `Token`
- `rp/client_credentials_test.go` should assert `Token.IDToken == ""` for client credentials responses

**Step 5: Run targeted tests**

Run: `go test ./rp -run 'TestPublicAPIOptionNames|TestAuthorizationURL|TestHandleCallback|TestClientCredentials' -count=1`
Expected: FAIL with missing symbols and old token-shape assumptions.

**Step 6: Commit**

```bash
git add rp/public_api_external_test.go rp/authrequest_test.go rp/callback_test.go rp/client_credentials_test.go
git commit -m "test: lock in rp api cleanup expectations"
```

### Task 2: Rename provider metadata options and preserve constructor behavior

**Files:**
- Modify: `rp/options.go`
- Modify: `rp/client_credentials_options.go`
- Modify: `rp/rp.go`
- Modify: `cmd/example-rp/main.go`
- Modify: `README.md`
- Test: `rp/public_api_external_test.go`

**Step 1: Write the minimal renamed options**

Add the new exported option names and wire them exactly like the current behavior:

```go
func WithProviderMetadata(provider oidc.ProviderMetadata) Option {
    return func(r *RP) {
        r.provider = provider
        r.providerSet = true
    }
}

func WithClientCredentialsProviderMetadata(provider oidc.ProviderMetadata) ClientCredentialsOption {
    return func(c *ClientCredentials) {
        c.provider = provider
        c.providerSet = true
    }
}
```

**Step 2: Keep temporary compatibility aliases during the implementation**

Add thin wrappers so existing in-repo call sites still build while follow-up tasks land:

```go
func WithProviderDiscovery(provider oidc.ProviderMetadata) Option {
    return WithProviderMetadata(provider)
}
```

Apply the same pattern for `WithClientCredentialsProviderDiscovery`.

**Step 3: Update in-repo call sites to the new names**

Replace `WithProviderDiscovery` and `WithClientCredentialsProviderDiscovery` usages in:

- `cmd/example-rp/main.go`
- `rp/auth_method_test.go`
- `rp/callback_test.go`
- any other `rp` tests referencing the old names

**Step 4: Run targeted tests**

Run: `go test ./rp ./cmd/example-rp -run 'TestPublicAPIOptionNames|TestHandleCallbackValidation|TestNew_' -count=1`
Expected: PASS for option renames; other failures may remain for token consolidation and discovery cleanup.

**Step 5: Commit**

```bash
git add rp/options.go rp/client_credentials_options.go rp/rp.go cmd/example-rp/main.go README.md rp/*.go
git commit -m "refactor: rename rp provider metadata options"
```

### Task 3: Merge `TokenResponse` into `Token`

**Files:**
- Modify: `rp/token_source.go`
- Modify: `rp/token.go`
- Modify: `rp/token_exchange.go`
- Modify: `rp/client_credentials.go`
- Modify: `rp/callback.go`
- Modify: `rp/token_exchange_test.go`
- Modify: `rp/client_credentials_test.go`
- Modify: `rp/callback_test.go`
- Test: `rp/public_api_external_test.go`

**Step 1: Expand `Token` to represent token endpoint payloads**

Replace the narrow client-credentials-only `Token` with a superset model:

```go
type Token struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int64  `json:"expires_in"`
    IDToken      string `json:"id_token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    Scope        string `json:"scope,omitempty"`
}
```

**Step 2: Delete the separate public `TokenResponse` type**

Remove the exported struct from `rp/token.go`. If a compatibility bridge is desired during rollout, use a temporary alias:

```go
// Deprecated: use Token.
type TokenResponse = Token
```

If the branch is intentionally fully breaking, remove it outright instead of aliasing.

**Step 3: Update authorization code token exchange to use `Token`**

In `rp/token_exchange.go`, change both signatures and decoding targets:

```go
func (r *RP) exchangeToken(...) (Token, error)
func (r *RP) exchangeTokenOnce(...) (Token, int, string, error)

var tokenResp Token
```

Keep the existing validation flow in `rp/callback.go`, but read `IDToken` and `AccessToken` from the unified `Token`.

**Step 4: Simplify client credentials token decoding**

In `rp/client_credentials.go`, decode directly into `Token` and return it without copying fields into a second token type.

```go
var token Token
status, preview, err := doJSON(req, c.httpClient, func(body io.Reader) error {
    return json.NewDecoder(body).Decode(&token)
})
```

**Step 5: Update tests for the unified token model**

- `rp/client_credentials_test.go`: assert `IDToken` is empty for client credentials
- `rp/callback_test.go`: keep asserting non-empty `IDToken` is required for auth code
- `rp/token_exchange_test.go`: compile against the unified return type

**Step 6: Run focused package tests**

Run: `go test ./rp -run 'TestClientCredentials|TestHandleCallback|TestExchangeToken' -count=1`
Expected: PASS

**Step 7: Commit**

```bash
git add rp/token_source.go rp/token.go rp/token_exchange.go rp/client_credentials.go rp/callback.go rp/*test.go
git commit -m "refactor: unify rp token models"
```

### Task 4: Internalize `PARResponse` and exported DPoP structs

**Files:**
- Modify: `rp/par.go`
- Modify: `rp/dpop.go`
- Modify: `rp/client_credentials.go`
- Modify: `rp/token_exchange.go`
- Modify: `rp/userinfo.go`
- Test: `rp/public_api_external_test.go`

**Step 1: Make PAR transport shape internal**

Rename `PARResponse` to `parResponse` and keep its use local to `rp/par.go`.

```go
type parResponse struct {
    RequestURI string `json:"request_uri"`
    ExpiresIn  int    `json:"expires_in"`
}
```

**Step 2: Make DPoP helper structs internal**

Rename the exported types in `rp/dpop.go`:

```go
type dpopProof struct { ... }
type dpopHeader struct { ... }
type dpopJWK struct { ... }
type dpopPayload struct { ... }
```

Update all references inside the file accordingly.

**Step 3: Run package tests**

Run: `go test ./rp -run 'TestClientCredentials|TestExchangeToken|TestFetchUserInfo' -count=1`
Expected: PASS

**Step 4: Verify godoc surface shrinks**

Run: `go doc ./rp`
Expected: `PARResponse`, `DPoPProof`, `DPoPHeader`, `DPoPJWK`, and `DPoPPayload` no longer appear.

**Step 5: Commit**

```bash
git add rp/par.go rp/dpop.go rp/client_credentials.go rp/token_exchange.go rp/userinfo.go
git commit -m "refactor: hide rp transport implementation types"
```

### Task 5: Stop rediscovery inside `AuthorizationURL` and simplify RP lifecycle

**Files:**
- Modify: `rp/authrequest.go`
- Modify: `rp/rp.go`
- Modify: `rp/rp_test.go`
- Modify: `rp/authrequest_test.go`
- Modify: `cmd/example-rp/main.go`
- Test: `rp/authrequest_test.go`

**Step 1: Remove rediscovery from `AuthorizationURL`**

Use the provider metadata already resolved during `New` or injected via `WithProviderMetadata`:

```go
func (r *RP) AuthorizationURL(ctx context.Context, w http.ResponseWriter, req *http.Request) (string, error) {
    metadata := r.provider
    if metadata.AuthorizationEndpoint == "" {
        return "", fmt.Errorf("%w: authorization endpoint missing", ErrInvalidConfiguration)
    }
    // no discovery call here
}
```

**Step 2: Decide constructor invariants and enforce them**

Keep `New` responsible for ensuring one of these is true before returning:

- provider metadata was supplied and is sufficient
- provider discovery completed successfully

This preserves the guarantee that `RP` is ready for `AuthorizationURL` immediately after construction.

**Step 3: Update or de-emphasize mutable discovery paths**

If removing `Discover`, `DiscoverWithJWKS`, and `DiscoverFromWebFinger` now is too disruptive, mark them as deprecated in doc comments during this task and stop advertising them in examples.

**Step 4: Run targeted tests**

Run: `go test ./rp -run 'TestAuthorizationURL|TestNew_' -count=1`
Expected: PASS, including the discovery call-count regression.

**Step 5: Commit**

```bash
git add rp/authrequest.go rp/rp.go rp/rp_test.go rp/authrequest_test.go cmd/example-rp/main.go
git commit -m "refactor: make rp constructor-owned discovery authoritative"
```

### Task 6: Add package docs and refresh examples/docs

**Files:**
- Create: `rp/doc.go`
- Modify: `README.md`
- Modify: `cmd/example-rp/main.go`
- Test: documentation surface via `go doc`

**Step 1: Add package-level documentation**

Create `rp/doc.go`:

```go
// Package rp implements OpenID Connect relying party flows.
//
// The package exposes two primary entrypoints:
//   - RP for browser-based authorization code flows
//   - ClientCredentials for service-to-service token acquisition
//
// State store implementations are available under rp/store/... packages.
package rp
```

**Step 2: Tighten export comments**

Add or improve doc comments on any remaining exported identifiers that currently show up poorly in `go doc`, especially:

- `NewStaticClientKeyProvider`
- `CallbackResult`
- `Token`
- renamed metadata options
- any deprecated discovery methods that remain exported

**Step 3: Update README examples to the final API**

Refresh snippets so they show:

- `WithProviderMetadata` / `WithClientCredentialsProviderMetadata`
- one `Token` type
- no references to internalized transport structs
- constructor-centric RP usage

**Step 4: Run verification commands**

Run:
- `gofumpt ./...`
- `go test ./...`
- `go doc ./rp`

Expected:
- formatting clean
- full test suite passes
- `go doc ./rp` shows the reduced public surface and package overview

**Step 5: Commit**

```bash
git add rp/doc.go README.md cmd/example-rp/main.go rp/*.go
git commit -m "docs: clarify rp public api"
```

### Task 7: Final compatibility sweep

**Files:**
- Modify: `rp/options.go`
- Modify: `rp/client_credentials_options.go`
- Modify: `rp/rp.go`
- Modify: `thoughts/architecture/2026-03-22_rp_api_cleanup_proposal.md`
- Test: full repository

**Step 1: Remove temporary compatibility bridges if this branch is intentionally breaking**

Delete transitional aliases such as:

```go
func WithProviderDiscovery(provider oidc.ProviderMetadata) Option {
    return WithProviderMetadata(provider)
}
```

Do the same for the client credentials option alias and any temporary `TokenResponse` alias.

**Step 2: If compatibility bridges stay, mark them deprecated clearly**

Use doc comments of the form:

```go
// Deprecated: use WithProviderMetadata.
```

Only keep these if the branch needs a short migration window.

**Step 3: Record the final decision in the architecture note**

Update `thoughts/architecture/2026-03-22_rp_api_cleanup_proposal.md` to reflect whether the implementation shipped as fully breaking or transitionally deprecated.

**Step 4: Run final verification**

Run: `gofumpt ./... && go test ./... && go doc ./rp`
Expected: all commands succeed and godoc matches the target API.

**Step 5: Commit**

```bash
git add rp/options.go rp/client_credentials_options.go rp/rp.go thoughts/architecture/2026-03-22_rp_api_cleanup_proposal.md
git commit -m "chore: finalize rp api cleanup"
```
