# Fifth RC preparation pass

Revision: `11dce18`. Push reported origin/master already up to date.

## Outcome: one confirmed integration defect; security review incomplete

Do not treat this pass as release sign-off. The independent security worker
terminated with a provider-side safety error and returned no review. No findings
or clean security assessment are inferred from that unfinished work.

## R1 — P2: refresh accepts malformed success and adopts its refresh token

Locations: `rp/refresh_token.go:41-52`, `rp/token_exchange.go:57-89`,
`rp/refresh_rotation.go:51-60`.

A successful HTTP status with JSON `{"refresh_token":"unexpected-rotation"}`
returns a nil error from RefreshToken despite lacking the required access_token
and token_type fields. RefreshTokenSource then adopts the refresh token from that
invalid response, replacing its previously held value. The caller receives an
unusable token set as apparent success and may persist it or send empty API
credentials. This requires a malformed/noncompliant token-endpoint response;
no malicious-server access bypass is claimed.

External reproduction: `/tmp/lanyard-rc5-refresh.go`.

```
refresh err=<nil> access="" type="" current-refresh="unexpected-rotation"
```

Validate required successful token-response fields before returning success or
mutating rotation state, preferably in the common token-grant path. Wrap malformed
refresh responses with ErrRefreshTokenFailed. Test missing access token, missing
token type, and malformed responses carrying refresh tokens; assert the source
does not adopt invalid response data. Preserve valid omission of refresh_token
and optional expires_in. If the AS has already rotated a token despite returning
an invalid response, the client may need reauthorization; preserving local state
does not guarantee the old token remains usable server-side.

## Completed verification

- Latest CI run [34142860344](https://github.com/Kunde21/lanyard/actions/runs/34142860344)
  succeeded at `11dce18`.
- Parent ran `go test -race -count=1 ./...`: passed.
  Evidence: `/tmp/lanyard-11dce18-parent-race.log`.
- Fresh govulncheck completed successfully with zero reachable vulnerabilities.
  It also reported vulnerabilities in dependencies not apparently called by this
  code; this is not a claim that all dependencies have no advisories.
  Evidence: `/tmp/lanyard-11dce18-govulncheck.log`.
- `conformance/README.md:56-63` records all five presets passing against `3995f7c`.
  No conformance run was started or changed during this pass.
- Parent independently reproduced the refresh defect and checked its source path.
- Repository remained clean at `11dce18` before adding this report. No library,
  test, CI, dependency, or conformance implementation changes were made.

## Remaining release work

Fix and regression-test R1, and complete the independent negative-path security
review that did not finish. Positive test/conformance results alone do not close
that verification gap.
