# Simplify README API Docs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** Fix stale README examples and nearby API documentation so public examples compile against the current Lanyard API.

**Architecture:** Treat the README snippets as public API examples and protect them with compile-checked examples/tests. Keep changes documentation-focused and minimal: update examples to use the current option-based constructors and current method signatures, then verify README snippets, Go examples, package docs, and tests.

**Tech Stack:** Go 1.25.7, standard `testing` examples, `go test`, `go test ./...`, `go build ./...`, `go doc`, `gofumpt`.

---

## Current Findings

The stale README examples are in `/home/kunde21/development/AI/lanyard/README.md`.

Validated current API from source and docs:

- `/home/kunde21/development/AI/lanyard/rp/rp.go:118`: `func New(ctx context.Context, issuer string, opts ...Option) (*RP, error)`.
- `/home/kunde21/development/AI/lanyard/rp/options.go:15`: `rp.WithClientID("client-id")` is the current way to configure client ID.
- `/home/kunde21/development/AI/lanyard/rp/options.go:21`: `rp.WithClientSecret("client-secret")` is the current way to configure client secret.
- `/home/kunde21/development/AI/lanyard/rp/options.go:27`: `rp.WithRedirectURI("https://rp.example.com/callback")` is the current way to configure redirect URI.
- `/home/kunde21/development/AI/lanyard/rp/options.go:90`: `rp.WithProviderMetadata(provider)` is shared by browser RP and client credentials flows.
- `/home/kunde21/development/AI/lanyard/rp/options.go:199`: `rp.WithStateStore(stateStore)` is still valid.
- `/home/kunde21/development/AI/lanyard/rp/options.go:64`: `rp.WithScopes(...)` is shared by browser RP and client credentials flows.
- `/home/kunde21/development/AI/lanyard/rp/authrequest.go:50`: `func (r *RP) AuthorizationURL(w http.ResponseWriter, req *http.Request, opts ...AuthorizationURLOption) (string, error)`.
- `/home/kunde21/development/AI/lanyard/rp/callback.go:57`: `func (r *RP) HandleCallback(w http.ResponseWriter, req *http.Request) (*CallbackResult, error)`.
- `/home/kunde21/development/AI/lanyard/rp/client_credentials.go:23`: `func NewClientCredentials(ctx context.Context, issuer string, opts ...Option) (*ClientCredentials, error)`.
- `/home/kunde21/development/AI/lanyard/rp/token_source.go:153`: `rp.WithTokenScopes(ctx, ...)` is current for per-request client credentials scopes.
- `/home/kunde21/development/AI/lanyard/rp/public_api_external_test.go:61`: removed symbols include `WithClientCredentialsProviderMetadata`, `WithClientCredentialsSenderConstrain`, `WithOIDCClient`, `WithDiscoveryOIDCClient`, and `WithClientCredentialsOIDCClient`.

Verified current packages before writing this plan:

- `go test ./rp ./metadata ./rp/store/cookie` passed.
- `go doc github.com/Kunde21/lanyard/rp.New` shows the option-based constructor.
- `go doc github.com/Kunde21/lanyard/rp.RP.AuthorizationURL` shows the two-argument method plus variadic authorization URL options.
- `go doc github.com/Kunde21/lanyard/rp.RP.HandleCallback` shows the two-argument method.
- `go doc github.com/Kunde21/lanyard/rp.NewClientCredentials` shows the option-based constructor.

The stale README sections to fix:

- `/home/kunde21/development/AI/lanyard/README.md:85-103` calls `rp.New(ctx, issuer, clientID, clientSecret, redirectURI, opts...)`; this no longer compiles.
- `/home/kunde21/development/AI/lanyard/README.md:110` calls `AuthorizationURL(r.Context(), w, r)`; current signature is `AuthorizationURL(w, r, opts...)`.
- `/home/kunde21/development/AI/lanyard/README.md:121` calls `HandleCallback(r.Context(), w, r)`; current signature is `HandleCallback(w, r)`.
- `/home/kunde21/development/AI/lanyard/README.md:151-158` repeats the stale positional `rp.New` form.
- `/home/kunde21/development/AI/lanyard/README.md:202-209` calls `rp.NewClientCredentials(ctx, issuer, clientID, clientSecret, rp.WithClientCredentialsProviderMetadata(...), rp.WithClientCredentialsScopes(...))`; those option names and positional credentials are removed.

## Task 1: Add Compile-Checked README Example Coverage

**Files:**

- Create: `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go`
- Read: `/home/kunde21/development/AI/lanyard/README.md`
- Read: `/home/kunde21/development/AI/lanyard/rp/example_test.go`
- Read: `/home/kunde21/development/AI/lanyard/rp/public_api_external_test.go`

**Step 1: Write failing compile-checked examples**

Create `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go` in package `rp_test`. Add examples mirroring the README API shapes, but use local `httptest.NewTLSServer` provider metadata to avoid network calls.

Include these test/example functions:

- `Example_readmeBrowserRPFlow()` covering cookie store creation, `rp.New`, `AuthorizationURL`, and the `HandleCallback` handler shape.
- `Example_readmeBrowserRPWithPreloadedProvider()` covering `metadata.Provider` plus `rp.WithProviderMetadata`.
- `Example_readmeDiscoverProvider()` covering `rp.DiscoverProvider` with `rp.WithDiscoveryHTTPClient(server.Client())`.
- `Example_readmeClientCredentialsConstruction()` covering `rp.NewClientCredentials`, `rp.WithClientID`, `rp.WithClientSecret`, `rp.WithProviderMetadata`, `rp.WithScopes`, and `rp.WithTokenScopes`.

Use only construction and method references where possible. Do not perform a real token request in the client credentials example.

Expected current failure before README fixes is either compile failure if the stale README code is copied literally, or no failure if the test is immediately written against the corrected API. If writing corrected examples from the start, still run the test before README edits to establish that the intended replacement code compiles.

**Step 2: Run targeted examples**

Run:

```bash
go test ./rp -run 'Example_readme|TestPublicAPIOptionNames'
```

Expected: pass once the example file uses the current public API. If it fails, fix the example test before editing README text.

**Step 3: Format the new test file**

Run:

```bash
gofumpt -w /home/kunde21/development/AI/lanyard/rp/readme_examples_test.go
```

Expected: no output and a formatted test file.

**Step 4: Re-run targeted examples**

Run:

```bash
go test ./rp -run 'Example_readme|TestPublicAPIOptionNames'
```

Expected: pass.

## Task 2: Update README Usage Snippets to Current API

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/README.md:85-230`
- Reference: `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go`

**Step 1: Update Browser RP Flow constructor**

In `/home/kunde21/development/AI/lanyard/README.md`, replace the positional `rp.New` call with option-based configuration:

```go
return rp.New(
	ctx,
	"https://issuer.example.com",
	rp.WithClientID("client-id"),
	rp.WithClientSecret("client-secret"),
	rp.WithRedirectURI("https://rp.example.com/callback"),
	rp.WithStateStore(stateStore),
	rp.WithScopes("openid", "profile", "email"),
)
```

Keep the note about `rp.WithProviderMetadata(provider)` only if it still accurately states that complete metadata skips discovery.

**Step 2: Update Browser RP Flow handlers**

Replace:

```go
authURL, err := rpClient.AuthorizationURL(r.Context(), w, r)
```

with:

```go
authURL, err := rpClient.AuthorizationURL(w, r)
```

Replace:

```go
result, err := rpClient.HandleCallback(r.Context(), w, r)
```

with:

```go
result, err := rpClient.HandleCallback(w, r)
```

Keep `r.Context()` out of these two method calls because the current methods read the request context from `*http.Request`.

**Step 3: Update Browser RP with Preloaded Provider**

Replace the positional constructor call with:

```go
return rp.New(
	ctx,
	provider.Issuer,
	rp.WithClientID("client-id"),
	rp.WithClientSecret("client-secret"),
	rp.WithRedirectURI("https://rp.example.com/callback"),
	rp.WithProviderMetadata(provider),
)
```

**Step 4: Update Client Credentials Grant**

Replace the stale constructor call with:

```go
client, err := rp.NewClientCredentials(
	ctx,
	provider.Issuer,
	rp.WithClientID("client-id"),
	rp.WithClientSecret("client-secret"),
	rp.WithProviderMetadata(provider),
	rp.WithScopes("api:read", "api:write"),
)
```

Remove all references to removed names:

- `rp.WithClientCredentialsProviderMetadata`
- `rp.WithClientCredentialsScopes`

Keep the `rp.WithTokenScopes(ctx, "admin:all")` per-request scope example.

**Step 5: Review README for removed API names**

Run:

```bash
rg 'WithClientCredentialsProviderMetadata|WithClientCredentialsScopes|WithClientCredentialsSenderConstrain|WithOIDCClient|WithDiscoveryOIDCClient|WithClientCredentialsOIDCClient|AuthorizationURL\(r\.Context\(\)|HandleCallback\(r\.Context\(\)' /home/kunde21/development/AI/lanyard/README.md
```

Expected: no matches.

## Task 3: Ensure README Snippets Stay in Sync with Tests

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/README.md`
- Modify: `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go`

**Step 1: Manually compare README snippets with compile-checked examples**

Compare the README snippets in `/home/kunde21/development/AI/lanyard/README.md:73-230` against `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go`.

Expected: the constructor and method-call shapes match exactly for the public API under documentation:

- `rp.New(ctx, issuer, rp.WithClientID(...), rp.WithClientSecret(...), rp.WithRedirectURI(...), ...)`
- `rpClient.AuthorizationURL(w, r)`
- `rpClient.HandleCallback(w, r)`
- `rp.NewClientCredentials(ctx, issuer, rp.WithClientID(...), rp.WithClientSecret(...), rp.WithProviderMetadata(...), rp.WithScopes(...))`

**Step 2: Keep examples minimal**

If the new test file duplicates too much setup, prefer small local helpers inside `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go`. Do not add production helpers for documentation tests.

**Step 3: Run targeted tests**

Run:

```bash
go test ./rp -run 'Example_readme|TestPublicAPIOptionNames'
```

Expected: pass.

## Task 4: Refresh Adjacent Godoc Only If Needed

**Files:**

- Inspect: `/home/kunde21/development/AI/lanyard/rp/rp.go:107-118`
- Inspect: `/home/kunde21/development/AI/lanyard/rp/authrequest.go:49-50`
- Inspect: `/home/kunde21/development/AI/lanyard/rp/callback.go:56-57`
- Inspect: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go:19-23`
- Inspect: `/home/kunde21/development/AI/lanyard/rp/options.go:15-419`

**Step 1: Check docs with `go doc`**

Run:

```bash
go doc github.com/Kunde21/lanyard/rp.New
go doc github.com/Kunde21/lanyard/rp.RP.AuthorizationURL
go doc github.com/Kunde21/lanyard/rp.RP.HandleCallback
go doc github.com/Kunde21/lanyard/rp.NewClientCredentials
```

Expected: docs mention current behavior and do not imply positional client ID/client secret/redirect URI parameters.

**Step 2: Add minimal missing comments only when required**

If `go vet ./...` or `golint`-style documentation expectations reveal exported identifiers without comments in touched files, add minimal comments starting with the identifier name. Do not broaden this task into a full documentation rewrite.

**Step 3: Re-run `go doc` for any changed symbol**

Run the exact `go doc` command for each changed symbol.

Expected: rendered docs are accurate and concise.

## Task 5: Full Verification

**Files:**

- Verify: `/home/kunde21/development/AI/lanyard/README.md`
- Verify: `/home/kunde21/development/AI/lanyard/rp/readme_examples_test.go`
- Verify: any Go files changed in Task 4

**Step 1: Format Go files**

Run:

```bash
gofumpt -w /home/kunde21/development/AI/lanyard/rp/readme_examples_test.go
```

If Task 4 changed additional Go files, include those exact files in the same command.

Expected: no output.

**Step 2: Run targeted test coverage**

Run:

```bash
go test ./rp ./metadata ./rp/store/cookie
```

Expected: pass.

**Step 3: Run all tests**

Run:

```bash
go test ./...
```

Expected: pass.

**Step 4: Run build verification**

Run:

```bash
go build ./...
```

Expected: pass.

**Step 5: Run vet**

Run:

```bash
go vet ./...
```

Expected: pass.

**Step 6: Verify README no longer references removed API**

Run:

```bash
rg 'WithClientCredentialsProviderMetadata|WithClientCredentialsScopes|WithClientCredentialsSenderConstrain|WithOIDCClient|WithDiscoveryOIDCClient|WithClientCredentialsOIDCClient|AuthorizationURL\(r\.Context\(\)|HandleCallback\(r\.Context\(\)' /home/kunde21/development/AI/lanyard/README.md
```

Expected: no matches.

**Step 7: Verify docs render current signatures**

Run:

```bash
go doc github.com/Kunde21/lanyard/rp.New
go doc github.com/Kunde21/lanyard/rp.RP.AuthorizationURL
go doc github.com/Kunde21/lanyard/rp.RP.HandleCallback
go doc github.com/Kunde21/lanyard/rp.NewClientCredentials
```

Expected: output shows the current signatures and no stale positional API.

**Step 8: Review final diff**

Run:

```bash
git diff -- /home/kunde21/development/AI/lanyard/README.md /home/kunde21/development/AI/lanyard/rp/readme_examples_test.go /home/kunde21/development/AI/lanyard/rp/rp.go /home/kunde21/development/AI/lanyard/rp/authrequest.go /home/kunde21/development/AI/lanyard/rp/callback.go /home/kunde21/development/AI/lanyard/rp/client_credentials.go /home/kunde21/development/AI/lanyard/rp/options.go
```

Expected: changes are limited to README, compile-checked README examples, and any minimal necessary Godoc adjustments.

## Commit Guidance

Make one focused commit after verification passes:

```bash
git add /home/kunde21/development/AI/lanyard/README.md /home/kunde21/development/AI/lanyard/rp/readme_examples_test.go
git add /home/kunde21/development/AI/lanyard/rp/rp.go /home/kunde21/development/AI/lanyard/rp/authrequest.go /home/kunde21/development/AI/lanyard/rp/callback.go /home/kunde21/development/AI/lanyard/rp/client_credentials.go /home/kunde21/development/AI/lanyard/rp/options.go
git commit -m "docs: refresh README API examples"
```

Only stage Go doc files if they were actually modified.
