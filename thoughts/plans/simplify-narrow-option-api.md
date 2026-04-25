# Simplify Narrow Option API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** Make `rp.NewClientCredentials` reject authorization-code-only options with a clear constructor error while keeping `rp.Option` as the shared option type accepted by both `rp.New` and `rp.NewClientCredentials`.

**Architecture:** Split option behavior instead of splitting the public shared option type. All public options implement `Option` by applying shared configuration to `*clientConfig`; browser-flow-only options additionally implement `AuthCodeOption` and apply their RP-specific behavior directly to `*RP`. `rp.New` applies both shared and auth-code behavior, while `rp.NewClientCredentials` rejects `AuthCodeOption` values before applying shared config.

**Tech Stack:** Go, package-level public API tests in `rp_test`, `errors.Is` for sentinel error checks, `github.com/google/go-cmp/cmp` only if assertions need structural diffs.

---

## Context

The current option implementation is in `/home/kunde21/development/AI/lanyard/rp/client_config.go:219-238`:

```go
// Option configures an [RP] or [ClientCredentials] instance.
type Option interface {
	apply(optionTarget)
}

type optionTarget interface {
	config() *clientConfig
}

type optionFunc func(*clientConfig)

func (f optionFunc) apply(t optionTarget) { f(t.config()) }

type rpOptionFunc func(*RP)

func (f rpOptionFunc) apply(t optionTarget) {
	if r, ok := t.(*RP); ok {
		f(r)
	}
}
```

`/home/kunde21/development/AI/lanyard/rp/client_credentials.go:17` currently accepts every `rp.Option`:

```go
func NewClientCredentials(ctx context.Context, issuer string, opts ...Option) (*ClientCredentials, error)
```

Because `rpOptionFunc.apply` silently ignores non-`*RP` targets, calls like this compile and run with no effect:

```go
_, _ = rp.NewClientCredentials(ctx, issuer,
	rp.WithClientID("client-id"),
	rp.WithClientSecret("secret"),
	rp.WithRedirectURI("https://rp.example.com/callback"), // silently ignored today
)
```

Relevant files inspected:

- `/home/kunde21/development/AI/lanyard/rp/client_config.go`
- `/home/kunde21/development/AI/lanyard/rp/options.go`
- `/home/kunde21/development/AI/lanyard/rp/public_api_external_test.go`
- `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- `/home/kunde21/development/AI/lanyard/rp/rp.go`
- `/home/kunde21/development/AI/lanyard/rp/doc.go`
- `/home/kunde21/development/AI/lanyard/examples/basic_discovery/main.go`

The `examples/` tree currently has no Go tests.

---

## Public API Target

Keep the existing `Option` name as the shared option contract for both constructors:

```go
// Option configures shared RP and client credentials settings.
type Option interface {
	applyConfig(*clientConfig)
}
```

Add a browser-flow-specific interface for options that only make sense for authorization-code RP construction:

```go
// AuthCodeOption configures authorization-code RP behavior.
type AuthCodeOption interface {
	Option
	applyAuthCode(*RP)
}
```

Use concrete option types to separate shared config from RP-only behavior:

```go
type optionFunc func(*clientConfig)

func (f optionFunc) applyConfig(c *clientConfig) { f(c) }

type authCodeOptionFunc func(*RP)

func (f authCodeOptionFunc) applyConfig(*clientConfig) {}
func (f authCodeOptionFunc) applyAuthCode(r *RP) { f(r) }
```

Keep both constructor signatures unchanged:

```go
func New(ctx context.Context, issuer string, opts ...Option) (*RP, error)
func NewClientCredentials(ctx context.Context, issuer string, opts ...Option) (*ClientCredentials, error)
```

Change constructor behavior:

- `rp.New` applies `opt.applyConfig(&r.clientConfig)` for every option.
- `rp.New` additionally applies `authOpt.applyAuthCode(r)` when an option satisfies `AuthCodeOption`.
- `rp.NewClientCredentials` returns an `ErrInvalidConfiguration`-wrapped error when any option satisfies `AuthCodeOption`.
- `rp.NewClientCredentials` applies only shared config options to `&c.clientConfig`.

Shared option constructors keep returning `Option`:

- `WithClientID(id string) Option`
- `WithClientSecret(secret string) Option`
- `WithMetadataClient(client *metadata.Client) Option`
- `WithLogger(logger *slog.Logger) Option`
- `WithHTTPClient(client *http.Client) Option`
- `WithScopes(scopes ...string) Option`
- `WithProviderMetadata(provider metadata.Provider) Option`
- `WithAuthMethod(method AuthMethod) Option`
- `WithClientKeyProvider(provider ClientKeyProvider) Option`
- `WithSenderConstrain(mode SenderConstraint) Option`
- `WithDPoPNonceTTL(ttl time.Duration) Option`

Auth-code-only option constructors return `AuthCodeOption`:

- `WithRedirectURI(uri string) AuthCodeOption`
- `WithClockSkew(skew time.Duration) AuthCodeOption`
- `WithStateStore(store StateStore) AuthCodeOption`
- `WithCorrelationStore(store CorrelationStore) AuthCodeOption`
- `WithUserInfoTokenTransport(transport UserInfoTokenTransport) AuthCodeOption`
- `WithRequirePAR(require bool) AuthCodeOption`
- `WithValidateAuthorizationResponseIssuer(validate bool) AuthCodeOption`
- `WithAllowUnsecuredIDTokens(allow bool) AuthCodeOption`
- `WithAuthorizationDetails(details []map[string]any) AuthCodeOption`
- `WithResponseMode(mode string) AuthCodeOption`
- `WithResponseType(responseType string) AuthCodeOption`
- `WithRequestMethod(method string) AuthCodeOption`
- `WithRequestURIMode(handler RequestURIHandler) AuthCodeOption`
- `WithProfile(profile Profile) AuthCodeOption`
- `WithDiscoveryMode(mode DiscoveryMode) AuthCodeOption`

Unexported test hooks can stay unexported and return `Option`:

- `withNow(now func() time.Time) Option`
- `withRandReader(reader io.Reader) Option`

Move the two current cross-target special cases into shared config state:

- `WithScopes` should set `clientConfig.scopesExplicit = true` instead of type-asserting `*RP`.
- `WithProviderMetadata` should set `clientConfig.configuredProvider` and `clientConfig.configuredProviderSet` instead of type-asserting `*RP`.

This means `RP` no longer needs separate `scopesExplicit`, `configuredProvider`, or `configuredProviderSet` fields because it embeds `clientConfig`. `ClientCredentials` may carry those construction-only fields unused; that is acceptable and simpler than adding a second temporary config type.

---

## Migration Notes

Direct calls and option slices using shared options remain source-compatible:

```go
opts := []rp.Option{rp.WithClientID("client-id"), rp.WithClientSecret("secret")}
_, err := rp.NewClientCredentials(ctx, issuer, opts...)
```

Calls that pass browser-flow-only options to `rp.NewClientCredentials` still compile because those values are also `rp.Option`, but they now fail during construction:

```go
_, err := rp.NewClientCredentials(ctx, issuer,
	rp.WithClientID("client-id"),
	rp.WithClientSecret("secret"),
	rp.WithRedirectURI("https://rp.example.com/callback"),
)
// err wraps rp.ErrInvalidConfiguration
```

This is intentionally a runtime validation change, not a compile-time source break.

---

## Task 1: Add Public API Type Assignment Tests First

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/public_api_external_test.go`

**Step 1: Add compile-time assignment checks**

Add a new test near `TestPublicAPIOptionNames`:

```go
func TestPublicAPIOptionTypeAssignments(t *testing.T) {
	var opt rp.Option
	opt = rp.WithClientID("client-id")
	opt = rp.WithClientSecret("secret")
	opt = rp.WithScopes("read")
	opt = rp.WithProviderMetadata(metadata.Provider{})
	opt = rp.WithRedirectURI("https://rp.example.com/callback")
	opt = rp.WithProfile(rp.OIDC)
	_ = opt

	var authOpt rp.AuthCodeOption
	authOpt = rp.WithRedirectURI("https://rp.example.com/callback")
	authOpt = rp.WithProfile(rp.OIDC)
	authOpt = rp.WithRequirePAR(true)
	_ = authOpt
}
```

**Step 2: Keep existing public API smoke calls source-compatible**

The existing direct call to `rp.NewClientCredentials` in `TestPublicAPIOptionNames` should continue compiling with shared options:

```go
_, _ = rp.NewClientCredentials(
	context.Background(),
	"https://issuer.example.com",
	rp.WithClientID("client-id"),
	rp.WithClientSecret("secret"),
	rp.WithProviderMetadata(metadata.Provider{}),
)
```

**Step 3: Run the targeted test and confirm it fails before implementation**

Run:

```bash
go test ./rp -run 'TestPublicAPIOptionNames|TestPublicAPIOptionTypeAssignments' -count=1
```

Expected before implementation: compile failure because `rp.AuthCodeOption` does not exist.

---

## Task 2: Add Constructor Rejection Test

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

**Step 1: Add a test for auth-code-only options**

Add this test in package `rp`:

```go
func TestNewClientCredentialsRejectsAuthCodeOptions(t *testing.T) {
	_, err := NewClientCredentials(context.Background(), "https://issuer.example.com",
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.example.com/callback"),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewClientCredentials() error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "auth-code option") {
		t.Fatalf("NewClientCredentials() error = %v, want auth-code option message", err)
	}
}
```

Add imports only if this file does not already import them:

```go
import (
	"errors"
	"strings"
)
```

**Step 2: Run the targeted test and confirm it fails before implementation**

Run:

```bash
go test ./rp -run TestNewClientCredentialsRejectsAuthCodeOptions -count=1
```

Expected before implementation: the test fails because `WithRedirectURI` is silently ignored and the constructor proceeds to normal validation/discovery behavior.

---

## Task 3: Introduce Shared and Auth-Code Option Interfaces

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/client_config.go:219-238`

**Step 1: Replace the option interface block**

Change the option definitions to:

```go
// Option configures shared RP and client credentials settings.
type Option interface {
	applyConfig(*clientConfig)
}

// AuthCodeOption configures authorization-code RP behavior.
type AuthCodeOption interface {
	Option
	applyAuthCode(*RP)
}

type optionFunc func(*clientConfig)

func (f optionFunc) applyConfig(c *clientConfig) { f(c) }

type authCodeOptionFunc func(*RP)

func (f authCodeOptionFunc) applyConfig(*clientConfig) {}
func (f authCodeOptionFunc) applyAuthCode(r *RP) { f(r) }
```

Delete `optionTarget`, `clientConfig.config()`, and `rpOptionFunc` after all call sites are updated.

**Step 2: Run the positive API test**

Run:

```bash
go test ./rp -run 'TestPublicAPIOptionNames|TestPublicAPIOptionTypeAssignments' -count=1
```

Expected now: compile failures remain because constructors and option implementations still call or implement `apply` instead of `applyConfig` / `applyAuthCode`.

---

## Task 4: Update Constructor Apply Loops

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/rp.go:119-128`
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go:26-28`

**Step 1: Update `rp.New`**

Change the option loop to:

```go
for _, opt := range opts {
	opt.applyConfig(&r.clientConfig)
	if authOpt, ok := opt.(AuthCodeOption); ok {
		authOpt.applyAuthCode(r)
	}
}
```

**Step 2: Update `rp.NewClientCredentials`**

Change the option loop to:

```go
for _, opt := range opts {
	if _, ok := opt.(AuthCodeOption); ok {
		return nil, fmt.Errorf("%w: auth-code option is not valid for client credentials", ErrInvalidConfiguration)
	}
	opt.applyConfig(&c.clientConfig)
}
```

`client_credentials.go` already imports `fmt`, so no import change should be needed.

**Step 3: Run the constructor rejection test**

Run:

```bash
go test ./rp -run TestNewClientCredentialsRejectsAuthCodeOptions -count=1
```

Expected now: still fails to compile until option constructors return and implement the new interfaces.

---

## Task 5: Move RP Construction Flags Into `clientConfig`

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/client_config.go:17-43`
- Modify: `/home/kunde21/development/AI/lanyard/rp/rp.go:68-105`

**Step 1: Add construction fields to `clientConfig`**

Add these fields near the existing scope and provider fields:

```go
scopesExplicit bool

configuredProvider    metadata.Provider
configuredProviderSet bool
```

**Step 2: Remove duplicate fields from `RP`**

Remove these fields from `RP` because they are now embedded through `clientConfig`:

```go
scopesExplicit bool

configuredProvider    metadata.Provider
configuredProviderSet bool
```

**Step 3: Run targeted RP tests**

Run:

```bash
go test ./rp -run 'TestNew_ExplicitScopesMarkedExplicit|TestNew_ScopesExplicit_WithScopesMarksExplicit|TestNew_WithProviderMetadata' -count=1
```

Expected now: compile failures remain until `WithScopes` and `WithProviderMetadata` are updated to write the moved fields through `clientConfig`.

---

## Task 6: Update Shared Option Implementations

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/options.go:15-211`

**Step 1: Keep shared constructors returning `Option`**

Do not change return types for shared options:

```go
func WithClientID(id string) Option
func WithClientSecret(secret string) Option
func WithMetadataClient(client *metadata.Client) Option
func WithLogger(logger *slog.Logger) Option
func WithHTTPClient(client *http.Client) Option
func WithScopes(scopes ...string) Option
func WithProviderMetadata(provider metadata.Provider) Option
func WithAuthMethod(method AuthMethod) Option
func WithClientKeyProvider(provider ClientKeyProvider) Option
func WithSenderConstrain(mode SenderConstraint) Option
func withNow(now func() time.Time) Option
func withRandReader(reader io.Reader) Option
func WithDPoPNonceTTL(ttl time.Duration) Option
```

**Step 2: Update `scopesOption`**

Change `scopesOption` to implement `applyConfig` only:

```go
func (o scopesOption) applyConfig(c *clientConfig) {
	if len(o.scopes) == 0 {
		return
	}
	c.scopes = append([]string(nil), o.scopes...)
	c.scopesExplicit = true
}
```

**Step 3: Update `providerMetadataOption`**

Change `providerMetadataOption` to implement `applyConfig` only:

```go
func (o providerMetadataOption) applyConfig(c *clientConfig) {
	c.provider = mergeConfiguredProvider(c.provider, o.provider)
	c.providerSet = true
	c.configuredProvider = mergeConfiguredProvider(c.configuredProvider, o.provider)
	c.configuredProviderSet = true
}
```

**Step 4: Run targeted shared option tests**

Run:

```bash
go test ./rp -run 'TestNew_ExplicitScopesMarkedExplicit|TestNew_ScopesExplicit_WithScopesMarksExplicit|TestNew_WithProviderMetadata' -count=1
```

Expected now: failures should be limited to auth-code-only option constructors still returning or using the old `rpOptionFunc` type.

---

## Task 7: Update Auth-Code-Only Option Constructors

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/options.go:29-384`

**Step 1: Change auth-code-only return types**

Change these constructors from `Option` to `AuthCodeOption` and from `rpOptionFunc` to `authCodeOptionFunc`:

```go
func WithRedirectURI(uri string) AuthCodeOption
func WithClockSkew(skew time.Duration) AuthCodeOption
func WithStateStore(store StateStore) AuthCodeOption
func WithCorrelationStore(store CorrelationStore) AuthCodeOption
func WithUserInfoTokenTransport(transport UserInfoTokenTransport) AuthCodeOption
func WithRequirePAR(require bool) AuthCodeOption
func WithValidateAuthorizationResponseIssuer(validate bool) AuthCodeOption
func WithAllowUnsecuredIDTokens(allow bool) AuthCodeOption
func WithAuthorizationDetails(details []map[string]any) AuthCodeOption
func WithResponseMode(mode string) AuthCodeOption
func WithResponseType(responseType string) AuthCodeOption
func WithRequestMethod(method string) AuthCodeOption
func WithRequestURIMode(handler RequestURIHandler) AuthCodeOption
func WithProfile(profile Profile) AuthCodeOption
func WithDiscoveryMode(mode DiscoveryMode) AuthCodeOption
```

For example:

```go
func WithRedirectURI(uri string) AuthCodeOption {
	return authCodeOptionFunc(func(r *RP) {
		r.redirectURI = strings.TrimSpace(uri)
	})
}
```

**Step 2: Remove old option target helpers**

After all constructors compile, remove any remaining `rpOptionFunc`, `optionTarget`, `config()`, or `.apply(...)` references.

Use search:

```bash
rg 'rpOptionFunc|optionTarget|func \(c \*clientConfig\) config\(|\.apply\(' rp
```

Expected: no matches for the removed option machinery.

**Step 3: Run targeted public API and constructor tests**

Run:

```bash
go test ./rp -run 'TestPublicAPIOptionNames|TestPublicAPIOptionTypeAssignments|TestNewClientCredentialsRejectsAuthCodeOptions' -count=1
```

Expected: all targeted tests pass.

---

## Task 8: Fix Internal Tests Only If Compilation Requires It

**Files:**

- Inspect and modify only if compilation fails:
- `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- `/home/kunde21/development/AI/lanyard/rp/authrequest_test.go`
- `/home/kunde21/development/AI/lanyard/rp/example_test.go`
- `/home/kunde21/development/AI/lanyard/rp/rp_test.go`

**Step 1: Run package tests**

Run:

```bash
go test ./rp -count=1
```

Expected: either pass or fail with compile errors from tests that assumed the old untyped `apply` internals.

**Step 2: Preserve shared option slices**

Do not change valid client credentials option slices from `[]Option` to a new client-credentials-specific type. This plan intentionally keeps `[]Option` valid for shared options.

**Step 3: Update tests that intentionally pass auth-code options to CC**

If a test passes `WithRedirectURI`, `WithClockSkew`, `WithProfile`, or another `AuthCodeOption` to `NewClientCredentials`, update the expected result to the new constructor error when that is the purpose of the test. Remove the option only when it is irrelevant setup noise.

**Step 4: Rerun package tests**

Run:

```bash
go test ./rp -count=1
```

Expected: pass.

---

## Task 9: Update Package Documentation and Migration Guidance

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/doc.go:33-40`
- Modify: `/home/kunde21/development/AI/lanyard/README.md` only if it claims every `rp.Option` is valid for client credentials.

**Step 1: Clarify option families in package docs**

Replace the `# Options` section in `/home/kunde21/development/AI/lanyard/rp/doc.go` with text like:

```go
// # Options
//
// [New] and [NewClientCredentials] both accept [Option] values for shared
// client configuration such as [WithClientID], [WithClientSecret],
// [WithMetadataClient], [WithScopes], [WithProviderMetadata], and
// [WithSenderConstrain]. Browser-flow-only options such as [WithRedirectURI],
// [WithStateStore], [WithProfile], and [WithRequirePAR] also satisfy
// [AuthCodeOption] and are rejected by [NewClientCredentials].
```

**Step 2: Add a focused migration note only if README needs it**

If `/home/kunde21/development/AI/lanyard/README.md` implies all `rp.Option` values are valid for client credentials, add one sentence near the client credentials example:

```md
`rp.NewClientCredentials` accepts shared `rp.Option` values, but browser-flow-only options such as `rp.WithRedirectURI` are rejected during construction.
```

If README only uses direct valid shared options, leave it unchanged.

**Step 3: Check docs compile**

Run:

```bash
go test ./rp -run TestPublicAPIOptionNames -count=1
```

Expected: pass.

---

## Task 10: Check Examples and Add Coverage Only If Needed

**Files:**

- Inspect: `/home/kunde21/development/AI/lanyard/examples/basic_discovery/main.go`
- Create only if useful: `/home/kunde21/development/AI/lanyard/examples/basic_discovery/main_test.go`

**Step 1: Verify current examples are unaffected**

The inspected example uses only `metadata.NewClient()` and `metadata.Client.DiscoverProvider`; it should not need changes.

Run:

```bash
go test ./examples/...
```

Expected: pass, or `go test` reports packages without test files successfully.

**Step 2: Do not add an example test unless an example imports `rp` options**

If future inspection finds an example that calls `rp.NewClientCredentials`, update it to use shared options. Do not add a synthetic test just for this change; the public API and constructor tests already cover the option surface.

---

## Task 11: Full Verification

**Files:**

- No edits unless verification finds a targeted issue.

**Step 1: Format**

Run:

```bash
gofumpt ./...
```

Expected: no errors.

**Step 2: Vet**

Run:

```bash
go vet ./...
```

Expected: no errors.

**Step 3: Test all packages**

Run:

```bash
go test ./...
```

Expected: all packages pass.

**Step 4: Optional public API doc check**

Run:

```bash
go doc github.com/Kunde21/lanyard/rp.AuthCodeOption
go doc github.com/Kunde21/lanyard/rp.NewClientCredentials
```

Expected: docs clearly distinguish shared options from authorization-code-only options.

---

## Risk Checklist

- Keeping `NewClientCredentials(...opts ...Option)` preserves existing shared option slices and direct calls.
- Auth-code-only options still compile as `Option`, so enforcement is runtime constructor validation rather than compile-time rejection.
- Do not reintroduce silent ignores for auth-code-only options in `NewClientCredentials`; reject them before applying shared config.
- Do not add `ClientCredentialsOption` or `SharedOption`; this plan intentionally keeps one shared public `Option` type plus a narrower `AuthCodeOption` classification.
- Do not add duplicate constructors like `WithClientCredentialsClientID`; the codebase recently removed that style and the goal is simplification.
- Moving `scopesExplicit`, `configuredProvider`, and `configuredProviderSet` into `clientConfig` makes those fields present but unused on `ClientCredentials`; this is acceptable because it avoids a separate construction config and keeps shared options simple.
