# Eighth RC preparation pass

Snapshot: `8d38c3b`. Both origin (Gitea) and github reported already up to date.
Worktree was clean before adding this report.

## Outcome: no new blockers found in the reviewed scope

The seventh-review opaque-token issue is fixed. External reproductions for the
fifth, sixth, and seventh reviews pass their expected assertions. Fresh release
gates also pass. This bounded consumer-integration review does not certify the
entire OAuth/OIDC/FAPI implementation or complete the independent security review
that stopped during the fifth pass.

## Remediation verification

Reran `/tmp/lanyard-rc7-refresh-identity.go`:

```
direct refresh error=<nil>
constructor preserves exact=true
source refresh error=<nil>
introspection active=true error=<nil>
Replace preserves exact=true
```

Inspected `rp/refresh_rotation.go` and `rp/introspection.go`: constructor storage,
Replace and introspection transmission preserve original token values, while
truly empty refresh-source input is rejected. Reviewed regression coverage in
`rp/opaque_token_verbatim_test.go`, including rotation, source reconstruction,
wire-value comparison and standalone introspection with a refresh-token hint.

Reran `/tmp/lanyard-rc6-consumer.go`:

- Consumer redirect policy is invoked; ErrUseLastResponse prevents any request
  to the redirect target and the token call reports the 307 response as failure.
- Canceled introspection matches both context.Canceled and
  ErrIntrospectionFailed via errors.Is.

Reran `/tmp/lanyard-rc5-refresh.go`:

- Malformed successful token responses fail with ErrRefreshTokenFailed context.
- The previously stored refresh token is retained rather than replaced by data
  from the malformed response.

Also inspected the documented token lifecycle and persistence contracts in
`rp/doc.go` and `rp/token_source.go`. Explicit persisted empty values remain
separate from missing legacy fields, and retained original raw token data is
explicitly documented as not securely erased by editing exported fields.

## Release gates

All completed successfully:

- `go test -race -count=1 ./...` — `/tmp/lanyard-8d38c3b-race.log`.
- `go vet ./...`.
- `go build ./...`.
- Formatter gate self-tests and repository gofumpt check.
- `git diff --check`.
- Fresh govulncheck v1.8.0 — `/tmp/lanyard-8d38c3b-vuln.log`:
  zero reachable vulnerabilities. The scanner separately notes advisories in
  dependencies that this code does not appear to call; no blanket advisory-free
  assertion is made.
- GitHub CI run 34257522297 succeeded at `8d38c3b`.

`conformance/README.md:84-91` records all five presets passing at `0f46722`
(70 plans, zero failures). Subsequent commits in this snapshot add documentation.
No conformance run was started, changed or independently certified in this pass.

## Nonblocking documentation polish

- `SECURITY.md:9-12` could name an exact private reporting address or advisory
  link instead of asking consumers to find the owner's contact details.
- `rp/doc.go:53-58` describes rotation too categorically. Clarify that source-level
  serialization applies to callers sharing the same RefreshTokenSource instance;
  it does not coordinate multiple processes or independently reconstructed
  sources. A production example should show application-managed expiry and
  durable storage of the most recent refresh token.

These are documentation improvements, not newly demonstrated implementation
blockers. The separate independent security-review gap should remain explicit
in the release decision rather than being silently closed by positive tests.

No implementation, dependency or CI changes were made. No new subagent review
was launched. This report is the only new repository file from this pass.
