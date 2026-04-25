# Simplify Token Grant Execution Helper Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce duplicated token grant request execution across authorization code exchange, refresh token exchange, and client credentials without changing public behavior.

**Architecture:** Add one small private helper in `rp/token_exchange.go` that owns token request execution, response decoding, DPoP retry integration, and optional `client_secret_post` to `client_secret_basic` fallback orchestration. Keep grant-specific form construction in the existing grant functions so request shapes, assertion generation, scopes, missing-access-token validation, and exported APIs stay unchanged.

**Tech Stack:** Go, package-local `rp` tests, `github.com/google/go-cmp/cmp`, `go test`, `gofumpt`, `go vet`

---

## Current State

The duplication is concentrated in these exact files:

- `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- `/home/kunde21/development/AI/lanyard/rp/refresh_token.go`
- `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- `/home/kunde21/development/AI/lanyard/rp/dpop.go`

Existing tests already cover the behavior that must be preserved:

- `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`
- `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`
- `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- `/home/kunde21/development/AI/lanyard/rp/dpop_test.go`
- `/home/kunde21/development/AI/lanyard/rp/dpop_usage_test.go`

Specific duplicated behavior to preserve:

- `AuthMethodPost` falls back to `AuthMethodBasic` only when `allowMethodFallback` is true and the first response status is `400` or `401`.
- Successful fallback updates cached auth method state with `setAuthMethodState(AuthMethodBasic, false)`.
- Successful first request while fallback is allowed updates auth method state with the original method and disables fallback.
- Non-OK responses include `token endpoint returned status <status>: <preview>` wrapped with the flow-specific sentinel error.
- Transport/request/decode errors are wrapped as `<flow sentinel>: <underlying error>`.
- DPoP proofs are attached only when the existing flow says to use DPoP.
- DPoP nonce challenges are retried through `doRequestWithDPoPRetry`.
- Successful DPoP nonce responses are cached for the token endpoint.
- Client credentials still rejects a `200` token response missing `access_token`.
- Authorization code and refresh token continue returning `Token` by value; client credentials continues returning `*Token`.

## Non-Goals

- Do not change exported APIs.
- Do not introduce generics.
- Do not merge grant-specific form creation into a large framework.
- Do not change client assertion construction in `rp/par.go` or `rp/client_credentials.go`.
- Do not change `doRequestWithDPoPRetry` behavior beyond its call site shape unless a failing test proves it is necessary.

### Task 1: Add Regression Tests Around Shared Fallback Semantics

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`

**Step 1: Add or tighten tests for failed fallback preview preservation**

Add one focused test per public flow only if the current coverage is missing an assertion. Keep tests small and use existing helpers.

Target names:

```go
func TestExchangeTokenFallbackFailureUsesRetryPreview(t *testing.T) {}
func TestRefreshToken_FallbackFailureUsesRetryPreview(t *testing.T) {}
func TestClientCredentials_Token_FallbackFailureUsesRetryPreview(t *testing.T) {}
```

Each test should configure provider metadata with no auth methods so `allowMethodFallback` is true, return `401` from the first `client_secret_post` request, return `400` with body `retry failed` from the fallback `client_secret_basic` request, and assert:

```go
if !errors.Is(err, ErrTokenExchangeFailed) { ... } // authorization code only
if !strings.Contains(err.Error(), "token endpoint returned status 400: retry failed") { ... }
```

Use the flow-specific sentinel for refresh token and client credentials:

- `ErrRefreshTokenFailed`
- `ErrClientCredentialsFailed`

**Step 2: Run the new tests and verify they pass before refactoring**

Run: `go test ./rp -run 'TestExchangeTokenFallbackFailureUsesRetryPreview|TestRefreshToken_FallbackFailureUsesRetryPreview|TestClientCredentials_Token_FallbackFailureUsesRetryPreview' -count=1`

Expected: PASS. These are characterization tests; if a proposed assertion fails, update the assertion to match current behavior before refactoring.

**Step 3: Commit the tests**

```bash
git add /home/kunde21/development/AI/lanyard/rp/token_exchange_test.go /home/kunde21/development/AI/lanyard/rp/refresh_token_test.go /home/kunde21/development/AI/lanyard/rp/client_credentials_test.go
git commit -m "test: characterize token grant fallback failures"
```

### Task 2: Introduce A Minimal Shared Token Execution Helper

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/dpop_test.go`

**Step 1: Add private helper types in `rp/token_exchange.go`**

Add small unexported types near `buildTokenRequest`:

```go
type tokenGrantResult struct {
	token   Token
	status  int
	preview string
}

type tokenGrantExecutor func(method AuthMethod) (tokenGrantResult, error)
```

Do not expose these types outside package `rp`.

**Step 2: Add shared fallback orchestration**

Add one helper that takes the existing auth state functions implicitly through `clientConfig`:

```go
func executeTokenGrant(config *clientConfig, run tokenGrantExecutor) (Token, error) {
	method, allowFallback := config.authMethodState()

	result, err := run(method)
	if err != nil {
		return Token{}, err
	}
	if result.status == http.StatusOK {
		if allowFallback {
			config.setAuthMethodState(method, false)
		}
		return result.token, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(result.status) {
		retryResult, retryErr := run(AuthMethodBasic)
		if retryErr != nil {
			return Token{}, retryErr
		}
		if retryResult.status == http.StatusOK {
			config.setAuthMethodState(AuthMethodBasic, false)
			return retryResult.token, nil
		}

		return Token{}, tokenEndpointStatusError(retryResult.status, retryResult.preview)
	}

	return Token{}, tokenEndpointStatusError(result.status, result.preview)
}
```

Add the status error helper in the same file:

```go
func tokenEndpointStatusError(status int, preview string) error {
	return fmt.Errorf("token endpoint returned status %d: %s", status, preview)
}
```

Important: this helper intentionally does not wrap the flow-specific sentinel. Callers must keep wrapping with `ErrTokenExchangeFailed`, `ErrRefreshTokenFailed`, or `ErrClientCredentialsFailed` so public error behavior remains flow-specific.

**Step 3: Run focused package tests**

Run: `go test ./rp -run 'TestExchangeTokenFallback|TestRefreshToken_Fallback|TestClientCredentials_Token_Fallback' -count=1`

Expected: PASS.

### Task 3: Move Authorization Code Exchange To The Shared Helper

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`

**Step 1: Refactor `(*RP).exchangeToken` only**

Replace the duplicated fallback block in `/home/kunde21/development/AI/lanyard/rp/token_exchange.go` with:

```go
func (r *RP) exchangeToken(ctx context.Context, tokenEndpoint, code, verifier string) (Token, error) {
	tokenResp, err := executeTokenGrant(&r.clientConfig, func(method AuthMethod) (tokenGrantResult, error) {
		tokenResp, status, preview, err := r.exchangeTokenOnce(ctx, tokenEndpoint, code, verifier, method, "")
		return tokenGrantResult{token: tokenResp, status: status, preview: preview}, err
	})
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	return tokenResp, nil
}
```

Do not change `exchangeTokenOnce` in this task.

**Step 2: Run authorization-code tests**

Run: `go test ./rp -run 'TestExchangeToken' -count=1`

Expected: PASS.

**Step 3: Run DPoP authorization-code tests**

Run: `go test ./rp -run 'TestExchangeToken_RetriesWithDpopNonce|TestExchangeToken_StoresNonceFromSuccessfulResponse' -count=1`

Expected: PASS.

### Task 4: Move Refresh Token Exchange To The Shared Helper

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/refresh_token.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`

**Step 1: Refactor `(*RP).RefreshToken` only**

Keep the empty refresh token and missing token endpoint validation unchanged. Replace only the duplicated fallback block with:

```go
	tokenResp, err := executeTokenGrant(&r.clientConfig, func(method AuthMethod) (tokenGrantResult, error) {
		tokenResp, status, preview, err := r.refreshTokenOnce(ctx, tokenEndpoint, refreshToken, method, "")
		return tokenGrantResult{token: tokenResp, status: status, preview: preview}, err
	})
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrRefreshTokenFailed, err)
	}
	return tokenResp, nil
```

Do not change `refreshTokenOnce` in this task.

**Step 2: Run refresh token tests**

Run: `go test ./rp -run 'TestRefreshToken' -count=1`

Expected: PASS.

**Step 3: Run DPoP refresh token test**

Run: `go test ./rp -run 'TestRefreshToken_RetriesWithDpopNonce' -count=1`

Expected: PASS.

### Task 5: Move Client Credentials To The Shared Helper Without Changing Its Public Return Type

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

**Step 1: Refactor `(*ClientCredentials).Token`**

Use the shared helper internally, then return a pointer copy to preserve the existing `Token(ctx context.Context) (*Token, error)` API:

```go
func (c *ClientCredentials) Token(ctx context.Context) (*Token, error) {
	token, err := executeTokenGrant(&c.clientConfig, func(method AuthMethod) (tokenGrantResult, error) {
		tokenResp, status, preview, err := c.requestToken(ctx, method)
		if tokenResp == nil {
			return tokenGrantResult{status: status, preview: preview}, err
		}
		return tokenGrantResult{token: *tokenResp, status: status, preview: preview}, err
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClientCredentialsFailed, err)
	}
	return &token, nil
}
```

Keep `requestToken` returning `(*Token, int, string, error)` for now. This avoids mixing public return-shape cleanup with the shared execution refactor.

**Step 2: Run client credentials tests**

Run: `go test ./rp -run 'TestClientCredentials' -count=1`

Expected: PASS.

**Step 3: Verify missing access token behavior**

Run: `go test ./rp -run 'TestClientCredentials_Token_ErrorCases' -count=1`

Expected: PASS, including the missing `access_token` case.

### Task 6: Optionally Extract Only The Shared Single-Request Execution

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/refresh_token.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/dpop_test.go`

Only do this task if Tasks 2-5 leave obvious duplication in `exchangeTokenOnce`, `refreshTokenOnce`, and `requestToken` without making the helper too abstract.

**Step 1: Add a small request execution helper**

Target helper shape in `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`:

```go
type tokenRequestExecution struct {
	buildRequest func() (*http.Request, error)
	attachDPoP   func(req *http.Request, nonce string) error
	storeNonce   func(resp *http.Response)
	httpClient   *http.Client
	useDPoP      bool
	cachedNonce  string
}

func executeTokenRequest(cfg tokenRequestExecution) (Token, int, string, error) {
	var tokenResp Token
	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: cfg.buildRequest,
		attachDPoP:   cfg.attachDPoP,
		handleResponse: func(body io.Reader) error {
			payload, err := io.ReadAll(body)
			if err != nil {
				return fmt.Errorf("failed to read token response: %w", err)
			}
			return parseTokenResponse(payload, &tokenResp)
		},
		storeNonce:    cfg.storeNonce,
		successStatus: http.StatusOK,
		httpClient:    cfg.httpClient,
		useDPoP:       cfg.useDPoP,
		cachedNonce:   cfg.cachedNonce,
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return Token{}, 0, "", fmt.Errorf("failed to decode token response: %w", decodeErr.Err)
		}
		return Token{}, 0, "", fmt.Errorf("failed to execute token request: %w", err)
	}
	return tokenResp, status, preview, nil
}
```

**Step 2: Replace the `doRequestWithDPoPRetry` blocks in each single-request function**

Update these functions to call `executeTokenRequest` after their grant-specific form is complete:

- `(*RP).exchangeTokenOnce` in `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- `(*RP).refreshTokenOnce` in `/home/kunde21/development/AI/lanyard/rp/refresh_token.go`
- `(*ClientCredentials).requestToken` in `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`

For client credentials, keep this post-processing after the helper returns:

```go
if status != http.StatusOK {
	return nil, status, preview, nil
}
if token.AccessToken == "" {
	return nil, status, "", fmt.Errorf("token response missing access_token")
}
return &token, status, "", nil
```

**Step 3: Run all token grant and DPoP tests**

Run: `go test ./rp -run 'TestExchangeToken|TestRefreshToken|TestClientCredentials|Test.*DPoP' -count=1`

Expected: PASS.

If this task requires awkward parameters or causes tests to become less readable, stop after Task 5 and leave this duplication in place. The minimal win is shared fallback orchestration.

### Task 7: Format, Verify, And Commit

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/refresh_token.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

**Step 1: Format changed Go files**

Run: `gofumpt -w /home/kunde21/development/AI/lanyard/rp/token_exchange.go /home/kunde21/development/AI/lanyard/rp/refresh_token.go /home/kunde21/development/AI/lanyard/rp/client_credentials.go /home/kunde21/development/AI/lanyard/rp/token_exchange_test.go /home/kunde21/development/AI/lanyard/rp/refresh_token_test.go /home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

Expected: command exits `0`.

**Step 2: Run focused package verification**

Run: `go test ./rp -count=1`

Expected: PASS.

**Step 3: Run full repository verification**

Run: `go test ./... -count=1`

Expected: PASS.

Run: `go vet ./...`

Expected: PASS.

**Step 4: Review the diff for accidental behavior changes**

Run: `git diff -- /home/kunde21/development/AI/lanyard/rp/token_exchange.go /home/kunde21/development/AI/lanyard/rp/refresh_token.go /home/kunde21/development/AI/lanyard/rp/client_credentials.go /home/kunde21/development/AI/lanyard/rp/token_exchange_test.go /home/kunde21/development/AI/lanyard/rp/refresh_token_test.go /home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

Expected: diff shows a small private helper plus call-site replacement, with grant-specific form construction preserved.

**Step 5: Commit implementation**

```bash
git add /home/kunde21/development/AI/lanyard/rp/token_exchange.go /home/kunde21/development/AI/lanyard/rp/refresh_token.go /home/kunde21/development/AI/lanyard/rp/client_credentials.go /home/kunde21/development/AI/lanyard/rp/token_exchange_test.go /home/kunde21/development/AI/lanyard/rp/refresh_token_test.go /home/kunde21/development/AI/lanyard/rp/client_credentials_test.go
git commit -m "refactor: share token grant execution"
```

## Final Acceptance Criteria

- The duplicated fallback branches are removed from `(*RP).exchangeToken`, `(*RP).RefreshToken`, and `(*ClientCredentials).Token`.
- A single private helper owns fallback decision-making and auth method cache updates.
- Grant-specific form fields remain in the grant-specific functions.
- DPoP nonce retry and nonce caching behavior remains covered and passing.
- Client credentials still errors on `200` responses without `access_token`.
- Error sentinels remain flow-specific: `ErrTokenExchangeFailed`, `ErrRefreshTokenFailed`, and `ErrClientCredentialsFailed`.
- `go test ./... -count=1` passes.
- `go vet ./...` passes.
