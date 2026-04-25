# Simplify Token Request Builder Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** Remove the duplicated token request envelope builders used by authorization-code token exchange and client-credentials token requests without changing grant-specific form behavior.

**Architecture:** Extract one unexported helper in `rp/token_exchange.go` (or a new small `rp/token_request.go` if preferred during implementation) that builds the shared HTTP POST request from endpoint, form values, auth method, client ID, and client secret. Keep all grant-specific form population in `(*RP).exchangeTokenOnce` and `(*ClientCredentials).requestToken`, because those differ by grant type and auth method.

**Tech Stack:** Go, `net/http`, `net/url`, existing `rp` package tests with `github.com/google/go-cmp/cmp`.

---

## Current Review Findings

The simplification is still worthwhile, but only for the request envelope. `rp/token_exchange.go:13-27` and `rp/client_credentials.go:170-184` duplicate the same logic:

- Create a POST request with `http.NewRequestWithContext`.
- Encode `url.Values` as `application/x-www-form-urlencoded`.
- Set the `Content-Type` header.
- Apply HTTP Basic auth for `AuthMethodBasic`.
- Do nothing for TLS client auth methods.

Do not attempt to merge full token form construction. `rp/token_exchange.go:59-102` and `rp/client_credentials.go:97-124` are intentionally different:

- Authorization code sets `grant_type`, `code`, `redirect_uri`, and `code_verifier`.
- Client credentials sets `grant_type`, optional `scope`, and context-specific scope overrides.
- Client assertion construction differs (`RP` has issuer fallback handling; `ClientCredentials` signs for `provider.TokenEndpoint`).

## Task 1: Add Focused Builder Tests

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`

**Step 1: Write a failing test for the shared request envelope**

Add a table-driven test near the existing token request-shape tests. Keep it in package `rp` so it can call the unexported helper once it exists.

Test cases should cover:

- `AuthMethodBasic` sets `Authorization: Basic ...` and does not mutate form values.
- `AuthMethodPost` sets no `Authorization` header and preserves body values, including `client_secret` if the caller put it in the form.
- `AuthMethodSelfSignedTLSClientAuth` sets no `Authorization` header and preserves `client_id` if the caller put it in the form.

Use this shape:

```go
func TestBuildTokenRequestEnvelope(t *testing.T) {
	tests := []struct {
		name              string
		method            AuthMethod
		form              url.Values
		wantAuthorization string
	}{
		{
			name:   "basic auth header",
			method: AuthMethodBasic,
			form: url.Values{
				"grant_type": {"authorization_code"},
			},
			wantAuthorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret")),
		},
		{
			name:   "post auth keeps form credentials",
			method: AuthMethodPost,
			form: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"client"},
				"client_secret": {"secret"},
			},
		},
		{
			name:   "self signed tls auth keeps caller supplied client id",
			method: AuthMethodSelfSignedTLSClientAuth,
			form: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildTokenRequestEnvelope(context.Background(), "https://issuer.test/token", tc.form, tc.method, "client", "secret")
			if err != nil {
				t.Fatalf("buildTokenRequestEnvelope() failed: %v", err)
			}

			if diff := cmp.Diff(http.MethodPost, req.Method); diff != "" {
				t.Fatalf("method mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff("https://issuer.test/token", req.URL.String()); diff != "" {
				t.Fatalf("url mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff("application/x-www-form-urlencoded", req.Header.Get("Content-Type")); diff != "" {
				t.Fatalf("content type mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantAuthorization, req.Header.Get("Authorization")); diff != "" {
				t.Fatalf("authorization mismatch (-want +got):\n%s", diff)
			}

			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("ReadAll() failed: %v", err)
			}
			gotForm, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("ParseQuery() failed: %v", err)
			}
			if diff := cmp.Diff(tc.form, gotForm); diff != "" {
				t.Fatalf("form mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
```

**Step 2: Run the focused test and verify it fails**

Run:

```bash
go test ./rp -run TestBuildTokenRequestEnvelope
```

Expected: FAIL because `buildTokenRequestEnvelope` is undefined.

## Task 2: Extract the Shared Builder

**Files:**

- Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`

**Step 1: Add the unexported helper**

Add this helper in `rp/token_exchange.go` near the existing `(*RP).buildTokenRequest`, or in a new file only if import cycles or readability make that cleaner:

```go
func buildTokenRequestEnvelope(ctx context.Context, tokenEndpoint string, form url.Values, method AuthMethod, clientID, clientSecret string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	switch method {
	case AuthMethodBasic:
		req.SetBasicAuth(clientID, clientSecret)
	case AuthMethodTLSClientAuth, AuthMethodSelfSignedTLSClientAuth:
	}

	return req, nil
}
```

**Step 2: Update `(*RP).buildTokenRequest`**

Replace the method body at `/home/kunde21/development/AI/lanyard/rp/token_exchange.go:13-27` with:

```go
func (r *RP) buildTokenRequest(ctx context.Context, tokenEndpoint string, form url.Values, method AuthMethod) (*http.Request, error) {
	return buildTokenRequestEnvelope(ctx, tokenEndpoint, form, method, r.clientID, r.clientSecret)
}
```

Keep the method for now because `(*RP).exchangeTokenOnce` already passes it into the DPoP retry builder, and removing it would increase churn.

**Step 3: Update `(*ClientCredentials).buildTokenRequest`**

Replace the method body at `/home/kunde21/development/AI/lanyard/rp/client_credentials.go:170-184` with:

```go
func (c *ClientCredentials) buildTokenRequest(ctx context.Context, method AuthMethod, form url.Values) (*http.Request, error) {
	return buildTokenRequestEnvelope(ctx, c.provider.TokenEndpoint, form, method, c.clientID, c.clientSecret)
}
```

**Step 4: Clean imports**

After the extraction, `/home/kunde21/development/AI/lanyard/rp/client_credentials.go` should no longer need `net/url` solely for `buildTokenRequest` if `requestToken` still uses `url.Values`; it currently does use `url.Values`, so keep `net/url`.

`/home/kunde21/development/AI/lanyard/rp/client_credentials.go` may no longer need `strings` only if scope joining were moved, but it still uses `strings.Join`; keep it.

Do not remove `fmt`, `net/http`, `net/url`, or `strings` from `/home/kunde21/development/AI/lanyard/rp/token_exchange.go`; the helper and existing code still need them.

**Step 5: Run the focused helper test**

Run:

```bash
go test ./rp -run TestBuildTokenRequestEnvelope
```

Expected: PASS.

## Task 3: Verify Grant-Specific Behavior Did Not Change

**Files:**

- Test: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

**Step 1: Run authorization-code request-shape tests**

Run:

```bash
go test ./rp -run 'TestExchangeTokenRequestShape|TestExchangeTokenFallbackFromPostToBasicAndCaches'
```

Expected: PASS. These tests guard Basic header behavior, post-auth body credentials, TLS client auth body shape, and fallback from post to basic.

**Step 2: Run client-credentials request-shape tests**

Run:

```bash
go test ./rp -run 'TestClientCredentials_Token_(BasicAuth|PostAuth|SelfSignedTLSClientAuth)'
```

Expected: PASS. These tests guard Basic header behavior, post-auth body credentials, and self-signed TLS body shape.

**Step 3: Run DPoP retry regression tests**

Run:

```bash
go test ./rp -run 'TestExchangeToken_RetriesWithDpopNonce|TestClientCredentials_Token_DPoP'
```

Expected: PASS. The shared builder must continue to return a fresh request body for each DPoP retry.

## Task 4: Full Refactor Verification

**Files:**

- Verify all repository code.

**Step 1: Format**

Run:

```bash
gofumpt ./...
```

Expected: no output or only formatted files from this refactor.

**Step 2: Vet**

Run:

```bash
go vet ./...
```

Expected: PASS with no diagnostics.

**Step 3: Test everything**

Run:

```bash
go test ./...
```

Expected: PASS.

## Non-Goals

- Do not merge authorization-code and client-credentials form construction.
- Do not change public APIs.
- Do not change DPoP retry logic.
- Do not change auth method resolution or fallback behavior.
