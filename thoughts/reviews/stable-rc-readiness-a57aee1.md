# Seventh RC preparation pass

Snapshot: `a57aee1`. Both origin (Gitea) and github were already up to date.
The existing untracked sixth-review report was preserved without modification.

## Outcome

Previous sixth-review findings are fixed on the checked paths. One P2 consumer
interoperability issue remains: opaque refresh-token values are normalized by
some public APIs. Fix this before freezing the token lifecycle contract.
No new high-severity issue was established in this bounded pass; this is not an
independent security certification or completion of the previously interrupted
security-worker review.

## R1 — P2: opaque token values are altered by refresh source and introspection

Locations:

- `rp/refresh_rotation.go:36-39`: NewRefreshTokenSource assigns TrimSpace back
  to the supplied refresh token before storing it.
- `rp/refresh_rotation.go:76-79`: Replace trims the replacement token.
- `rp/introspection.go:322`: the request builder trims the submitted token.

Refresh tokens are opaque credentials, not user-entered labels. RFC 6749
Appendix A.17 defines refresh-token as 1*VSCHAR, which permits ASCII space
(VSCHAR = %x20-7E). A provider-issued token with leading or trailing spaces is
therefore valid and must be transmitted exactly. Introspection can receive
refresh tokens, including through the refresh_token token-type hint.

External reproduction: `/tmp/lanyard-rc7-refresh-identity.go`, using the fixture
refresh token `" refresh-token "` and a TLS server that recognizes that exact
value. The same RP and token produced:

```
direct refresh error=<nil>
constructor preserves exact=false
source refresh error=refresh token request failed: refresh token was rejected: oauth error invalid_grant (HTTP 400)
introspection active=false error=<nil>
Replace preserves exact=false
```

The token works through RP.RefreshToken, but wrapping it in RefreshTokenSource
changes its identity. Replace has the same defect. Introspection silently submits
a different value and obtains an inactive result. Typical URL-safe/base64 tokens
are unaffected; this is a valid-input interoperability defect, not a credential
leak or demonstrated authentication bypass.

Minimal remediation: preserve the original token bytes when storing and sending
these values; keep validation separate from normalization. Avoid rejecting
otherwise valid values solely because TrimSpace is empty. Add external-API tests
covering exact constructor storage, Replace, direct refresh/source equivalence,
rotation followed by persistence/reconstruction, and introspection with a
refresh_token hint. Distinguish truly empty input from valid nonempty opaque
credentials; do not change token-type-hint normalization as part of this fix.

## Previous findings checked

Reran `/tmp/lanyard-rc6-consumer.go` against this snapshot:

- Consumer CheckRedirect is invoked once; ErrUseLastResponse prevents target
  requests (target-hits=0) and the token operation reports the 307 as an error.
- Canceled introspection now matches both context.Canceled and
  ErrIntrospectionFailed through errors.Is.
- Source inspection of `rp/http.go:67-86` confirms the library minimum redirect
  restrictions run before consulting the consumer callback.
- Regression tests exist for permitted consumer redirects, introspection
  cancellation/deadline/fallback causes, grant-management cancellation, and
  verbatim client_id preservation.

## Release checks

- Fresh `go test -race -count=1 ./...`: passed.
  `/tmp/lanyard-a57aee1-race.log`.
- Fresh `go vet ./...` and `go build ./...`: passed.
- Fresh govulncheck: zero reachable vulnerabilities.
  `/tmp/lanyard-a57aee1-vuln.log`. The scan still notes advisories in imported
  dependencies that the code does not appear to call; this is not a claim that
  all transitive dependencies are advisory-free.
- GitHub CI run 34244741304 succeeded at `a57aee1`.
- `conformance/README.md:74` onward records five-preset re-verification at
  `9d77ae7`, with 70 plans and zero failures. No conformance suite was started
  or modified in this pass.

Scope: parent read-only consumer integration and release-readiness review.
No subagent was launched or represented as completing the outstanding independent
security review. No implementation/configuration changes or commits were made;
only this new review report was added.
