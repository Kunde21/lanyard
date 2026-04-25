# Simplify Godoc Source-Of-Truth API Docs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** Improve Godoc coverage and source-of-truth API guidance for the public Lanyard package surface without changing runtime behavior.

**Architecture:** Treat source comments, package docs, examples, and README usage as one documentation system. Keep production code unchanged except for comments and examples, make the root package explain where callers should start, and verify with `go doc`, `go test`, `go vet`, and a documentation-lint command that catches missing exported comments.

**Tech Stack:** Go, Godoc/pkg.go.dev comments, package examples, `go doc`, `go test`, `go vet`, `gofumpt`, `golint` or an equivalent exported-comment linter.

---

## Current Findings

The documentation gap is real but uneven: the main caller packages already have useful package docs, while the root package and lower-level utility packages are thin.

- `/home/kunde21/development/AI/lanyard/doc.go:1` contains only `package lanyard`, so `go doc github.com/Kunde21/lanyard` prints only `package lanyard // import "github.com/Kunde21/lanyard"`.
- `/home/kunde21/development/AI/lanyard/rp/doc.go:1-43` already documents browser sign-in, client credentials, token refresh, provider discovery, and option families. Keep this as the primary source for RP caller stories, but audit exported identifiers for stale or thin comments.
- `/home/kunde21/development/AI/lanyard/metadata/doc.go:1-28` already documents discovery, JWKS integration, and when to use `metadata` directly.
- `/home/kunde21/development/AI/lanyard/jwks/doc.go:1-27` already documents remote key retrieval, caching, and direct use cases.
- `/home/kunde21/development/AI/lanyard/cache/doc.go:1-14` already documents `cache.Store` as the generic in-memory cache backing metadata and JWKS.
- `/home/kunde21/development/AI/lanyard/validateurl/https.go:1` has no package comment. `go doc github.com/Kunde21/lanyard/validateurl` exposes sentinel errors and `ParseHTTPSAbsoluteNoQueryFragment`, but the package purpose is not explained.
- `/home/kunde21/development/AI/lanyard/httputil/fetchjson.go:1` and `/home/kunde21/development/AI/lanyard/httputil/cachettl.go:1` have no package comment. `go doc github.com/Kunde21/lanyard/httputil` exposes low-level JSON fetch and cache TTL helpers without saying they are internal-support style APIs for metadata/JWKS fetchers.
- `/home/kunde21/development/AI/lanyard/README.md:1-260` is broad user-facing documentation. Use it as the tutorial/feature overview, not as the exhaustive API reference. Source comments and examples should be the source of truth for API signatures.
- Existing related plans include `/home/kunde21/development/AI/lanyard/thoughts/plans/godoc-updates.md`, `/home/kunde21/development/AI/lanyard/thoughts/plans/2026-04-11-public-api-simplification-and-godoc-refresh.md`, and `/home/kunde21/development/AI/lanyard/thoughts/plans/simplify-readme-api-docs.md`. Do not duplicate their stale-README work; this plan focuses on Godoc coverage and source-of-truth API docs.

Important worktree note from investigation:

- `/home/kunde21/development/AI/lanyard/doc.go` currently appears as an untracked file in `git status --short`. Before implementing, inspect it and decide whether to keep and edit it or replace it with the package doc described below. Do not delete unrelated user work.

---

## Documentation Principles

- Keep comments factual and API-oriented. Avoid marketing copy in source comments.
- Prefer package docs for caller orientation and identifier comments for precise semantics, defaults, side effects, and error behavior.
- Do not add compatibility wrappers, new public symbols, or runtime behavior changes for documentation.
- Keep the README high level and link readers to package docs for details.
- Use examples only where they compile and clarify a primary caller path.

---

## Task 1: Add Root Package Documentation

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/doc.go`
- Read: `/home/kunde21/development/AI/lanyard/README.md`
- Read: `/home/kunde21/development/AI/lanyard/rp/doc.go`
- Read: `/home/kunde21/development/AI/lanyard/metadata/doc.go`
- Read: `/home/kunde21/development/AI/lanyard/jwks/doc.go`
- Read: `/home/kunde21/development/AI/lanyard/cache/doc.go`

**Step 1: Inspect the existing root `doc.go`**

Run:

```bash
sed -n '1,120p' /home/kunde21/development/AI/lanyard/doc.go
git status --short /home/kunde21/development/AI/lanyard/doc.go
```

Expected: the file currently contains only `package lanyard` and may be untracked.

**Step 2: Add the root package comment**

Update `/home/kunde21/development/AI/lanyard/doc.go` to make the root package a navigation entry point:

```go
// Package lanyard is an OpenID Connect and OAuth 2.0 relying party library.
//
// Most applications should start with the [rp] package, which implements
// browser-based sign-in, callback handling, token refresh, client credentials,
// token exchange, DPoP, mTLS sender-constrained tokens, PAR, JAR, and JARM.
//
// Use [metadata] directly for provider discovery, OAuth 2.0 authorization
// server metadata, WebFinger issuer resolution, or remote JWKS construction
// without building a relying party. Use [jwks] directly when a JWKS URI is
// already known. The [cache] package provides the default generic in-memory
// cache used by metadata and JWKS clients.
//
// The lower-level [validateurl] and [httputil] packages are exported for
// callers that need the same URL validation and HTTP JSON-fetch behavior used
// internally by discovery and key retrieval.
package lanyard
```

**Step 3: Verify root Godoc**

Run:

```bash
go doc github.com/Kunde21/lanyard
```

Expected: output begins with the new package overview and includes references to `rp`, `metadata`, `jwks`, `cache`, `validateurl`, and `httputil`.

---

## Task 2: Add Package Docs For Lower-Level Utility Packages

**Files:**

- Create: `/home/kunde21/development/AI/lanyard/validateurl/doc.go`
- Create: `/home/kunde21/development/AI/lanyard/httputil/doc.go`
- Read: `/home/kunde21/development/AI/lanyard/validateurl/https.go`
- Read: `/home/kunde21/development/AI/lanyard/httputil/fetchjson.go`
- Read: `/home/kunde21/development/AI/lanyard/httputil/cachettl.go`

**Step 1: Add `validateurl` package docs**

Create `/home/kunde21/development/AI/lanyard/validateurl/doc.go`:

```go
// Package validateurl contains URL validation helpers shared by Lanyard
// packages.
//
// The primary helper, [ParseHTTPSAbsoluteNoQueryFragment], accepts only
// absolute HTTPS URLs without query or fragment components. It returns sentinel
// errors such as [ErrInvalidFormat], [ErrInvalidHTTPS], and
// [ErrQueryOrFragment] so callers can classify validation failures with
// errors.Is.
package validateurl
```

**Step 2: Add `httputil` package docs**

Create `/home/kunde21/development/AI/lanyard/httputil/doc.go`:

```go
// Package httputil contains HTTP helpers used by discovery and JWKS clients.
//
// [FetchJSON] applies JSON request headers, handles conditional responses,
// captures bounded error-body previews, and delegates successful response
// decoding to the caller. [CalculateFreshUntil] centralizes Cache-Control and
// Expires handling with a caller-provided fallback TTL.
//
// Most applications should use the higher-level [metadata], [jwks], or [rp]
// packages instead of this package directly.
package httputil
```

**Step 3: Verify package docs**

Run:

```bash
go doc github.com/Kunde21/lanyard/validateurl
go doc github.com/Kunde21/lanyard/httputil
```

Expected: both commands show a package overview before variables/functions/types.

---

## Task 3: Audit Exported Identifier Comments Across Public Packages

**Files:**

- Inspect: `/home/kunde21/development/AI/lanyard/rp/*.go`
- Inspect: `/home/kunde21/development/AI/lanyard/metadata/*.go`
- Inspect: `/home/kunde21/development/AI/lanyard/jwks/*.go`
- Inspect: `/home/kunde21/development/AI/lanyard/cache/*.go`
- Inspect: `/home/kunde21/development/AI/lanyard/validateurl/*.go`
- Inspect: `/home/kunde21/development/AI/lanyard/httputil/*.go`

**Step 1: Generate the exported-symbol inventory**

Run:

```bash
rg -n '^(func|type|const|var) [A-Z]|^func \([^)]*\) [A-Z]' \
  /home/kunde21/development/AI/lanyard/rp \
  /home/kunde21/development/AI/lanyard/metadata \
  /home/kunde21/development/AI/lanyard/jwks \
  /home/kunde21/development/AI/lanyard/cache \
  /home/kunde21/development/AI/lanyard/validateurl \
  /home/kunde21/development/AI/lanyard/httputil
```

Expected: all exported functions, methods, types, constants, and variables are listed for review.

**Step 2: Run an exported-comment linter**

Preferred command if `golint` is available:

```bash
golint ./rp ./metadata ./jwks ./cache ./validateurl ./httputil ./...
```

Alternative if `golint` is not installed and installing tools is acceptable:

```bash
go install golang.org/x/lint/golint@latest
$(go env GOPATH)/bin/golint ./rp ./metadata ./jwks ./cache ./validateurl ./httputil ./...
```

Alternative if no external linter should be installed:

```bash
go vet ./...
go doc -all github.com/Kunde21/lanyard/rp >/tmp/lanyard-rp.godoc
go doc -all github.com/Kunde21/lanyard/metadata >/tmp/lanyard-metadata.godoc
go doc -all github.com/Kunde21/lanyard/jwks >/tmp/lanyard-jwks.godoc
go doc -all github.com/Kunde21/lanyard/cache >/tmp/lanyard-cache.godoc
go doc -all github.com/Kunde21/lanyard/validateurl >/tmp/lanyard-validateurl.godoc
go doc -all github.com/Kunde21/lanyard/httputil >/tmp/lanyard-httputil.godoc
```

Expected with `golint`: no missing-comment reports for exported identifiers in the public packages after this plan is implemented. Existing style warnings outside documentation should be triaged, not fixed opportunistically.

**Step 3: Fix thin or missing comments in place**

For each exported identifier missing a doc comment or using a comment that does not start with the identifier name, add or adjust only the comment.

Prioritize these known thin spots from investigation:

- `/home/kunde21/development/AI/lanyard/validateurl/https.go:9-13`: add comments for `ErrInvalidFormat`, `ErrInvalidHTTPS`, and `ErrQueryOrFragment` if the linter reports them.
- `/home/kunde21/development/AI/lanyard/httputil/fetchjson.go:28-33`: add comments for `DecodeError.Error` and `DecodeError.Unwrap` if needed for consistency with other error types.
- `/home/kunde21/development/AI/lanyard/httputil/fetchjson.go:12-20`: expand `FetchJSONResult` field comments only if `go doc -all` is unclear about `NotModified`, `BodyPreview`, or TTL semantics.
- `/home/kunde21/development/AI/lanyard/rp/*.go`: verify options, profiles, sender-constraining, DPoP nonce helpers, token exchange, refresh token, callback, and discovery comments are current after recent API simplification.
- `/home/kunde21/development/AI/lanyard/metadata/*.go`: verify discovery cache, JWKS cache, WebFinger, well-known URL, and validation error comments include enough behavior for direct callers.
- `/home/kunde21/development/AI/lanyard/jwks/*.go`: verify cache refresh, unknown-`kid` refresh behavior, HTTP status errors, and cache option comments are clear.
- `/home/kunde21/development/AI/lanyard/cache/store.go`: verify comments state the store is concurrency-safe and that callers should construct it with `NewStore`.

**Step 4: Keep comment edits minimal**

Do not alter function signatures, JSON tags, option semantics, defaults, tests, or examples in this task unless a comment is demonstrably stale and an existing test/example must be updated to compile.

---

## Task 4: Align README With Godoc As The Source Of Truth

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/README.md`
- Read: `/home/kunde21/development/AI/lanyard/rp/example_test.go`
- Read: `/home/kunde21/development/AI/lanyard/metadata/example_test.go`
- Read: `/home/kunde21/development/AI/lanyard/jwks/example_test.go`
- Read: `/home/kunde21/development/AI/lanyard/cache/example_test.go`

**Step 1: Add a short API documentation pointer**

Add a concise section near the top of `/home/kunde21/development/AI/lanyard/README.md`, after the intro paragraph and before `## Capabilities`:

```markdown
## API Documentation

The source-of-truth API documentation is the Go package documentation:

- `github.com/Kunde21/lanyard/rp` for relying-party flows and token APIs
- `github.com/Kunde21/lanyard/metadata` for discovery and authorization server metadata
- `github.com/Kunde21/lanyard/jwks` for remote JWKS retrieval
- `github.com/Kunde21/lanyard/cache` for the default in-memory cache

README examples are introductory. Prefer `go doc` or pkg.go.dev for exact signatures, defaults, and option behavior.
```

**Step 2: Do not expand the README into a full API reference**

Keep the README concise. If it starts duplicating option-by-option details already in source comments, move that detail into Godoc instead.

**Step 3: Check for stale source-of-truth claims**

Run:

```bash
rg -n 'source-of-truth|API Documentation|go doc|pkg.go.dev|WithClientCredentialsProviderMetadata|WithClientCredentialsScopes|AuthorizationURL\(r\.Context\(\)|HandleCallback\(r\.Context\(\)' /home/kunde21/development/AI/lanyard/README.md
```

Expected: README contains the new API documentation pointer and no references to removed/stale API shapes.

---

## Task 5: Add Or Refresh Compile-Checked Examples Only Where They Improve Godoc

**Files:**

- Inspect: `/home/kunde21/development/AI/lanyard/rp/example_test.go`
- Inspect: `/home/kunde21/development/AI/lanyard/metadata/example_test.go`
- Inspect: `/home/kunde21/development/AI/lanyard/jwks/example_test.go`
- Inspect: `/home/kunde21/development/AI/lanyard/cache/example_test.go`
- Optional create: `/home/kunde21/development/AI/lanyard/validateurl/example_test.go`
- Optional create: `/home/kunde21/development/AI/lanyard/httputil/example_test.go`

**Step 1: Review existing examples in Godoc**

Run:

```bash
go test ./rp ./metadata ./jwks ./cache -run Example -count=1
go doc -all github.com/Kunde21/lanyard/rp | rg -n '^func Example|^EXAMPLES|New\(|AuthorizationURL|HandleCallback|NewClientCredentials'
go doc -all github.com/Kunde21/lanyard/metadata | rg -n '^func Example|^EXAMPLES|NewClient|DiscoverProvider|RemoteKeySet'
go doc -all github.com/Kunde21/lanyard/jwks | rg -n '^func Example|^EXAMPLES|NewRemoteKeySet|Keys|Key'
go doc -all github.com/Kunde21/lanyard/cache | rg -n '^func Example|^EXAMPLES|NewStore|Get|Set|Delete'
```

Expected: examples compile and cover the main caller paths. If they already do, do not add more examples.

**Step 2: Add utility examples only if package docs remain ambiguous**

If `validateurl` or `httputil` Godoc still feels too abstract, add small examples:

- `/home/kunde21/development/AI/lanyard/validateurl/example_test.go`: demonstrate `ParseHTTPSAbsoluteNoQueryFragment` success and `errors.Is(err, validateurl.ErrQueryOrFragment)`.
- `/home/kunde21/development/AI/lanyard/httputil/example_test.go`: prefer not to add unless a realistic, concise `httptest.Server` example clarifies `FetchJSON` without turning into integration-test noise.

**Step 3: Keep examples deterministic**

Do not call real external issuers or JWKS endpoints. Use `httptest.Server` or simple pure examples.

---

## Task 6: Final Verification

**Files:**

- Verify: `/home/kunde21/development/AI/lanyard/doc.go`
- Verify: `/home/kunde21/development/AI/lanyard/validateurl/doc.go`
- Verify: `/home/kunde21/development/AI/lanyard/httputil/doc.go`
- Verify: `/home/kunde21/development/AI/lanyard/README.md`
- Verify any comment/example files modified during the exported-symbol audit

**Step 1: Format modified Go files**

Run:

```bash
gofumpt -w /home/kunde21/development/AI/lanyard/doc.go \
  /home/kunde21/development/AI/lanyard/validateurl/doc.go \
  /home/kunde21/development/AI/lanyard/httputil/doc.go
```

If additional Go files were modified for comments or examples, include them in the same `gofumpt -w` command.

Expected: no output.

**Step 2: Run targeted tests**

Run:

```bash
go test ./rp ./metadata ./jwks ./cache ./validateurl ./httputil -count=1
```

Expected: all targeted packages pass.

**Step 3: Run full repository verification**

Run:

```bash
go vet ./...
go test ./...
go build ./...
```

Expected: all commands pass.

**Step 4: Run documentation verification**

Run:

```bash
go doc github.com/Kunde21/lanyard
go doc github.com/Kunde21/lanyard/rp
go doc github.com/Kunde21/lanyard/metadata
go doc github.com/Kunde21/lanyard/jwks
go doc github.com/Kunde21/lanyard/cache
go doc github.com/Kunde21/lanyard/validateurl
go doc github.com/Kunde21/lanyard/httputil
```

Expected: each package opens with useful package documentation and no package appears as a bare symbol listing.

**Step 5: Re-run exported-comment lint**

Run the same lint command chosen in Task 3.

Expected: no missing exported-comment issues in `/home/kunde21/development/AI/lanyard/rp`, `/home/kunde21/development/AI/lanyard/metadata`, `/home/kunde21/development/AI/lanyard/jwks`, `/home/kunde21/development/AI/lanyard/cache`, `/home/kunde21/development/AI/lanyard/validateurl`, or `/home/kunde21/development/AI/lanyard/httputil`.

**Step 6: Review the final diff**

Run:

```bash
git diff -- /home/kunde21/development/AI/lanyard/doc.go \
  /home/kunde21/development/AI/lanyard/validateurl \
  /home/kunde21/development/AI/lanyard/httputil \
  /home/kunde21/development/AI/lanyard/rp \
  /home/kunde21/development/AI/lanyard/metadata \
  /home/kunde21/development/AI/lanyard/jwks \
  /home/kunde21/development/AI/lanyard/cache \
  /home/kunde21/development/AI/lanyard/README.md
```

Expected: only documentation comments, package docs, README wording, and optional compile-checked examples changed. No runtime code behavior changed.

---

## Done Criteria

- `go doc github.com/Kunde21/lanyard` shows a meaningful root package overview.
- `go doc` for `rp`, `metadata`, `jwks`, `cache`, `validateurl`, and `httputil` clearly explains each package's role.
- Exported identifiers across the targeted public packages have non-stale comments that start with the identifier name where applicable.
- README points readers to Godoc/pkg.go.dev as the source of truth for exact API signatures.
- `go test ./rp ./metadata ./jwks ./cache ./validateurl ./httputil -count=1` passes.
- `go vet ./...`, `go test ./...`, and `go build ./...` pass.
- The selected documentation linter or manual `go doc -all` audit reports no missing exported-comment gaps in the targeted public packages.
