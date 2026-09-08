# Sixth RC preparation pass

Snapshot: `5971c96`. Both origin (Gitea) and github reported already up to date.

## Outcome

The fifth-review malformed-success finding is fixed. Two P2 consumer integration
issues remain below; address them before freezing the RC's HTTP/error contracts.
No new high-severity issue was established in this bounded pass. This does not
complete the independent security review interrupted during the fifth pass.

## R1 — P2: sensitive HTTP helper discards consumer redirect policy

Location: `rp/http.go:60-75`.

`doSensitiveRequest` clones the supplied HTTP client, then replaces CheckRedirect
without consulting the consumer's callback. Its own HTTPS/same-host restriction
is useful, but it silently weakens a consumer's stricter no-redirect policy.

External reproduction `/tmp/lanyard-rc6-consumer.go` configures a client with
CheckRedirect returning http.ErrUseLastResponse, then performs a client-credentials
request against an HTTPS endpoint issuing a same-origin 307 redirect:

```
redirect err=<nil> target-hits=1 custom-policy-calls=0
```

The redirected endpoint receives the POST despite the consumer's policy to stop
at the initial response. This can defeat application-specific path restrictions
or redirect accounting. The library's cross-origin/downgrade restrictions still
apply; no cross-origin credential leak is claimed for this finding.

Fix: enforce the library's minimum redirect restrictions first, then consult the
original CheckRedirect callback if nonnil. Honor ErrUseLastResponse and other
errors without permitting the callback to weaken the minimum policy. Preserve
caller client immutability. Regression tests should cover same-origin rejection,
permitted redirects, callback errors, ErrUseLastResponse, and continued rejection
of downgrade/cross-origin redirects even with a permissive callback.

## R2 — P2: introspection and grant-management wrappers erase error causes

Locations: `rp/introspection.go:234-245`,
`rp/grant_management.go:225-226,252-254`.

The wrappers preserve their operation sentinel with %w but stringify the actual
cause with %v. As a result, consumers cannot distinguish request cancellation,
deadline expiration, or typed network errors via errors.Is/errors.As.

The same external reproduction invokes introspection with an already-canceled
context and gets:

```
introspection canceled=false sentinel=true error=token introspection failed: ... context canceled
```

Cancellation itself still stops the request; the defect is loss of machine-readable
cause information. This harms retry policies and request-cancellation handling,
and is inconsistent with the already-corrected token/refresh API wrappers.
Grant-management query/revoke have the same source-level wrapping defect; their
network cancellation path was not separately executed in this pass.

Fix: preserve both the operation sentinel and underlying cause (for example,
`fmt.Errorf("%w: %w", sentinel, err)`). Add canceled/deadline/typed transport error
tests for introspection (including its auth fallback) and grant query/revoke.
Check intermediate wrappers as well so fixing the outermost error is sufficient.

## Verification

- Previous reproduction `/tmp/lanyard-rc5-refresh.go` now returns
  `refresh token request failed: token response missing required access_token or token_type`
  and leaves CurrentRefreshToken at `valid-refresh`.
- Common grant validator checks required fields on both initial and fallback
  successes (`rp/token_exchange.go:64-99`).
- Fresh `go test -race -count=1 ./...` passed:
  `/tmp/lanyard-5971c96-race.log`.
- Fresh `go vet ./...` and `go build ./...` passed.
- Fresh govulncheck reports zero reachable vulnerabilities:
  `/tmp/lanyard-5971c96-vuln.log`. It still notes advisories in dependencies not
  apparently called by this code; this is not a blanket advisory-free assertion.
- GitHub CI run 34239354966 succeeded at `5971c96`.
- `conformance/README.md:65-72` records all five presets passing at `6cffd2b`.
  No conformance processes or presets were started/changed during this pass.
- AFT inspection completed but reported incomplete authoritative LSP diagnostic
  coverage; actual Go checks above are the verification gate.

Scope: parent review of token lifecycle, HTTP client integration, and public
error contracts. No security-subagent review was launched or counted as complete.
No code or configuration was changed; only this review report was added.
