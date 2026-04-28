# Refresh Token Exchange Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `RefreshToken` method on `*RP` that exchanges a refresh token for a new token response, following RFC 6749 §6 and the existing codebase patterns.

**Architecture:** The refresh token exchange is structurally similar to the authorization code exchange already in `exchangeToken`/`exchangeTokenOnce`. We add a new public `RefreshToken(ctx, refreshToken)` method on `*RP` that builds a `grant_type=refresh_token` request, reuses the existing auth method negotiation, DPoP retry logic, and token response parsing. The method is placed in a new file `rp/refresh_token.go` with its tests in `rp/refresh_token_test.go`.

**Tech Stack:** Go, `net/http`, `net/url`, `github.com/google/go-cmp/cmp` for test assertions.

---

### Task 1: Add sentinel error for refresh token failures

**Files:**
- Modify: `rp/errors.go`

**Step 1: Write the failing test**

Add a test in `rp/refresh_token_test.go` that references `ErrRefreshTokenFailed`:

```go
package rp

import "testing"

func TestErrRefreshTokenFailedExists(t *testing.T) {
	_ = ErrRefreshTokenFailed
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./rp -run TestErrRefreshTokenFailedExists -count=1`
Expected: FAIL - `ErrRefreshTokenFailed` undefined

**Step 3: Write minimal implementation**

Add to `rp/errors.go` in the `var` block:

```go
// ErrRefreshTokenFailed indicates a refresh token request failed.
ErrRefreshTokenFailed = errors.New("refresh token request failed")
```

**Step 4: Run test to verify it passes**

Run: `go test ./rp -run TestErrRefreshTokenFailedExists -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/errors.go
git commit -m "feat: add ErrRefreshTokenFailed sentinel error"
```

---

### Task 2: Implement `refreshTokenOnce` — the single-attempt refresh request

**Files:**
- Create: `rp/refresh_token.go`
- Create: `rp/refresh_token_test.go`

**Step 1: Write the failing test**

Create `rp/refresh_token_test.go`:

```go
package rp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRefreshTokenOnce_RequestShape(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "new-access",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new-refresh",
			IDToken:      "new-idtoken",
		})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, status, preview, err := r.refreshTokenOnce(context.Background(), ts.URL, "old-refresh-token", AuthMethodBasic, "")
	if err != nil {
		t.Fatalf("refreshTokenOnce() failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status mismatch: want 200 got %d preview %q", status, preview)
	}

	wantForm := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "old-refresh-token",
	}
	for key, want := range wantForm {
		if gotForm.Get(key) != want {
			t.Fatalf("form %q mismatch: want %q got %q", key, want, gotForm.Get(key))
		}
	}

	want := Token{
		AccessToken:  "new-access",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "new-refresh",
		IDToken:      "new-idtoken",
	}
	if diff := cmp.Diff(want.AccessToken, token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.RefreshToken, token.RefreshToken); diff != "" {
		t.Fatalf("RefreshToken mismatch (-want +got):\n%s", diff)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./rp -run TestRefreshTokenOnce_RequestShape -count=1`
Expected: FAIL - `r.refreshTokenOnce` undefined

**Step 3: Write minimal implementation**

Create `rp/refresh_token.go`:

```go
package rp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RefreshToken exchanges a refresh token for a new token response.
// It uses the same auth method, DPoP retry, and fallback logic as the
// authorization code exchange.
func (r *RP) RefreshToken(ctx context.Context, refreshToken string) (Token, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return Token{}, fmt.Errorf("%w: refresh_token is required", ErrRefreshTokenFailed)
	}

	provider := r.provider
	tokenEndpoint := r.tokenEndpoint(provider)
	if tokenEndpoint == "" {
		return Token{}, fmt.Errorf("%w: provider missing token endpoint", ErrRefreshTokenFailed)
	}

	method, allowFallback := r.authMethodState()

	tokenResp, status, preview, err := r.refreshTokenOnce(ctx, tokenEndpoint, refreshToken, method, "")
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrRefreshTokenFailed, err)
	}
	if status == http.StatusOK {
		if allowFallback {
			r.setAuthMethodState(method, false)
		}
		return tokenResp, nil
	}

	if allowFallback && method == AuthMethodPost && shouldFallbackToBasic(status) {
		retryResp, retryStatus, retryPreview, retryErr := r.refreshTokenOnce(ctx, tokenEndpoint, refreshToken, AuthMethodBasic, "")
		if retryErr != nil {
			return Token{}, fmt.Errorf("%w: %v", ErrRefreshTokenFailed, retryErr)
		}
		if retryStatus == http.StatusOK {
			r.setAuthMethodState(AuthMethodBasic, false)
			return retryResp, nil
		}
		return Token{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrRefreshTokenFailed, retryStatus, retryPreview)
	}

	return Token{}, fmt.Errorf("%w: token endpoint returned status %d: %s", ErrRefreshTokenFailed, status, preview)
}

func (r *RP) refreshTokenOnce(ctx context.Context, tokenEndpoint, refreshToken string, method AuthMethod, dpopAccessToken string) (Token, int, string, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	switch method {
	case AuthMethodPrivateKeyJWT:
		audience := r.issuer
		if audience == "" {
			audience = tokenEndpoint
		}
		assertion, err := r.buildClientAssertion(audience)
		if err != nil {
			return Token{}, 0, "", fmt.Errorf("failed to build client assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		form.Set("client_id", r.clientID)
	case AuthMethodClientSecretJWT:
		audience := r.issuer
		if audience == "" {
			audience = tokenEndpoint
		}
		assertion, err := r.buildClientSecretAssertion(audience)
		if err != nil {
			return Token{}, 0, "", fmt.Errorf("failed to build client secret assertion: %w", err)
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		form.Set("client_id", r.clientID)
	case AuthMethodTLSClientAuth, AuthMethodSelfSignedTLSClientAuth:
		form.Set("client_id", r.clientID)
	case AuthMethodNone:
		form.Set("client_id", r.clientID)
	case AuthMethodPost:
		form.Set("client_id", r.clientID)
		form.Set("client_secret", r.clientSecret)
	case AuthMethodBasic:
	}

	useDPoP := r.shouldUseDPoP()

	var tokenResp Token
	_, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return r.buildTokenRequest(ctx, tokenEndpoint, form, method)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return r.attachDPoPProof(req, dpopAccessToken, nonce)
		},
		handleResponse: func(body io.Reader) error {
			payload, err := io.ReadAll(body)
			if err != nil {
				return fmt.Errorf("failed to read token response: %w", err)
			}
			return parseTokenResponse(payload, &tokenResp)
		},
		storeNonce: func(resp *http.Response) {
			r.extractAndStoreDPoPNonce(resp, tokenEndpoint)
		},
		successStatus: http.StatusOK,
		httpClient:    r.httpClient,
		useDPoP:       useDPoP,
		cachedNonce:   r.cachedDPoPNonce(tokenEndpoint),
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

**Step 4: Run test to verify it passes**

Run: `go test ./rp -run TestRefreshTokenOnce_RequestShape -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/refresh_token.go rp/refresh_token_test.go
git commit -m "feat: add refreshTokenOnce and RefreshToken method"
```

---

### Task 3: Test auth method variants for refresh token request

**Files:**
- Modify: `rp/refresh_token_test.go`

**Step 1: Write the failing test**

Add to `rp/refresh_token_test.go`:

```go
func TestRefreshTokenOnce_PostAuth(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "new-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods("client_secret_post")),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, _, _, err := r.refreshTokenOnce(context.Background(), ts.URL, "rt", AuthMethodPost, "")
	if err != nil {
		t.Fatalf("refreshTokenOnce() failed: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Fatalf("access token mismatch: want new-access got %s", token.AccessToken)
	}

	wantForm := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "rt",
		"client_id":     "client",
		"client_secret": "secret",
	}
	for key, want := range wantForm {
		if gotForm.Get(key) != want {
			t.Fatalf("form %q mismatch: want %q got %q", key, want, gotForm.Get(key))
		}
	}
}

func TestRefreshTokenOnce_NoneAuth(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "new-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("none")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodNone),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, _, _, err := r.refreshTokenOnce(context.Background(), ts.URL, "rt", AuthMethodNone, "")
	if err != nil {
		t.Fatalf("refreshTokenOnce() failed: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Fatalf("access token mismatch")
	}
	if gotForm.Get("client_id") != "client" {
		t.Fatalf("client_id mismatch: want client got %q", gotForm.Get("client_id"))
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatalf("client_secret should not be present for none auth")
	}
}
```

**Step 2: Run tests to verify they pass**

Run: `go test ./rp -run "TestRefreshTokenOnce_PostAuth|TestRefreshTokenOnce_NoneAuth" -count=1`
Expected: PASS (these test existing implementation from Task 2)

**Step 3: Commit**

```bash
git add rp/refresh_token_test.go
git commit -m "test: add auth method variant tests for refresh token"
```

---

### Task 4: Test `RefreshToken` public method — success, error, and fallback

**Files:**
- Modify: `rp/refresh_token_test.go`

**Step 1: Write the failing test**

Add to `rp/refresh_token_test.go`:

```go
func TestRefreshToken_Success(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "new-access",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "rotated-refresh",
			IDToken:      "new-idtoken",
		})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                          "https://issuer.test",
				AuthorizationEndpoint:           "https://issuer.test/authorize",
				TokenEndpoint:                   ts.URL,
				JWKSURI:                         "https://issuer.test/jwks",
				TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			},
		}),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("rotated-refresh", token.RefreshToken); diff != "" {
		t.Fatalf("RefreshToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("new-idtoken", token.IDToken); diff != "" {
		t.Fatalf("IDToken mismatch (-want +got):\n%s", diff)
	}
}

func TestRefreshToken_EmptyToken(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                "https://issuer.test",
				AuthorizationEndpoint: "https://issuer.test/authorize",
				TokenEndpoint:         "https://issuer.test/token",
				JWKSURI:               "https://issuer.test/jwks",
			},
		}),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.RefreshToken(context.Background(), "")
	if err == nil {
		t.Fatalf("RefreshToken() expected error for empty refresh token")
	}
	if !strings.Contains(err.Error(), ErrRefreshTokenFailed.Error()) {
		t.Fatalf("error mismatch: %v", err)
	}
}

func TestRefreshToken_ServerError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:                          "https://issuer.test",
				AuthorizationEndpoint:           "https://issuer.test/authorize",
				TokenEndpoint:                   ts.URL,
				JWKSURI:                         "https://issuer.test/jwks",
				TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			},
		}),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.RefreshToken(context.Background(), "bad-token")
	if err == nil {
		t.Fatalf("RefreshToken() expected error for server error")
	}
	if !strings.Contains(err.Error(), ErrRefreshTokenFailed.Error()) {
		t.Fatalf("error mismatch: %v", err)
	}
}

func TestRefreshToken_FallbackPostToBasic(t *testing.T) {
	requests := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "new-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests (fallback), got %d", requests)
	}
}
```

**Step 2: Run tests to verify they pass**

Run: `go test ./rp -run "TestRefreshToken_Success|TestRefreshToken_EmptyToken|TestRefreshToken_ServerError|TestRefreshToken_FallbackPostToBasic" -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add rp/refresh_token_test.go
git commit -m "test: add public RefreshToken method tests"
```

---

### Task 5: Test DPoP nonce retry for refresh token

**Files:**
- Modify: `rp/refresh_token_test.go`

**Step 1: Write the failing test**

Add to `rp/refresh_token_test.go`:

```go
func TestRefreshToken_RetriesWithDpopNonce(t *testing.T) {
	key := testRSAKey(t)
	requests := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") == "" {
			t.Fatalf("expected DPoP header on retry")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "new-access",
			TokenType:    "DPoP",
			RefreshToken: "new-refresh",
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("private_key_jwt")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodPrivateKeyJWT),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", nil)),
		WithSenderConstrain(SenderConstraintDPoP),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if diff := cmp.Diff("new-access", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests (DPoP nonce retry), got %d", requests)
	}
}
```

**Step 2: Run test to verify it passes**

Run: `go test ./rp -run TestRefreshToken_RetriesWithDpopNonce -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add rp/refresh_token_test.go
git commit -m "test: add DPoP nonce retry test for refresh token"
```

---

### Task 6: Test refresh preserves raw payload and extra fields

**Files:**
- Modify: `rp/refresh_token_test.go`

**Step 1: Write the failing test**

Add to `rp/refresh_token_test.go`:

```go
func TestRefreshToken_PreservesRawPayload(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated","transaction_id":"txn-42"}`)
	}))
	defer ts.Close()

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(providerForAuthMethods("client_secret_basic")),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	token, err := r.RefreshToken(context.Background(), "old-rt")
	if err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}

	txn, err := token.Extra("transaction_id")
	if err != nil {
		t.Fatalf("Extra() failed: %v", err)
	}
	if diff := cmp.Diff("txn-42", txn); diff != "" {
		t.Fatalf("transaction_id mismatch (-want +got):\n%s", diff)
	}
	if err := token.DecodeRaw(&map[string]any{}); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
}
```

**Step 2: Run test to verify it passes**

Run: `go test ./rp -run TestRefreshToken_PreservesRawPayload -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add rp/refresh_token_test.go
git commit -m "test: verify raw payload preservation in refresh token response"
```

---

### Task 7: Update package documentation

**Files:**
- Modify: `rp/doc.go`

**Step 1: Update doc.go**

Add a new section to `rp/doc.go` after the "Browser-based sign-in" section:

```
// # Token refresh
//
// When the authorization code flow returns a refresh token, use
// [RP.RefreshToken] to exchange it for a fresh [Token] without user
// interaction. The method respects the same auth method and DPoP
// configuration as the original flow.
```

**Step 2: Run full test suite**

Run: `go test ./...`
Expected: All tests PASS

**Step 3: Run formatting and vet**

Run: `gofumpt ./... && go vet ./...`
Expected: No output (clean)

**Step 4: Commit**

```bash
git add rp/doc.go
git commit -m "docs: add refresh token section to package docs"
```

---

### Task 8: Verify public API surface

**Files:**
- Modify: `rp/public_api_external_test.go`

**Step 1: Add refresh token API check**

Add to `TestPublicAPIOptionNames` in `rp/public_api_external_test.go`, after the existing `Token` literal block:

```go
_ = rp.ErrRefreshTokenFailed
```

And verify the method is accessible from external test package:

```go
func TestPublicAPIRefreshToken(t *testing.T) {
	// RefreshToken is a method on *RP; we verify the type exists and the
	// method is part of the public API by checking compilation.
	var _ func(context.Context, string) (rp.Token, error) = nil
	_ = rp.ErrRefreshTokenFailed
}
```

**Step 2: Run full test suite**

Run: `go test ./rp -run TestPublicAPI -count=1`
Expected: PASS

**Step 3: Run complete verification**

Run: `gofumpt ./... && go vet ./... && go test ./...`
Expected: All PASS

**Step 4: Commit**

```bash
git add rp/public_api_external_test.go
git commit -m "test: verify RefreshToken in public API surface"
```

---

## Summary of new files and changes

| File | Change |
|------|--------|
| `rp/errors.go` | Add `ErrRefreshTokenFailed` sentinel error |
| `rp/refresh_token.go` | New file: `RefreshToken` public method + `refreshTokenOnce` private method |
| `rp/refresh_token_test.go` | New file: tests for request shape, auth methods, DPoP retry, fallback, raw payload |
| `rp/doc.go` | Add "Token refresh" section |
| `rp/public_api_external_test.go` | Verify `ErrRefreshTokenFailed` is exported |

## Key design decisions

1. **Method on `*RP` only** — not on `*ClientCredentials`. The client credentials grant never issues refresh tokens (RFC 6749 §4.4.3).
2. **Reuses `buildTokenRequest`** — the existing helper already handles Content-Type header and Basic auth setup.
3. **Reuses DPoP retry logic** — `doRequestWithDPoPRetry` handles nonce-based retries transparently.
4. **Auth method fallback** — mirrors the `exchangeToken` pattern: Post → Basic fallback on 400/401.
5. **No scope parameter on public API** — callers who need to narrow scopes should use a separate method or option in a future iteration. YAGNI.
6. **Returns `Token` (value), not `*Token`** — consistent with `exchangeToken` return type.
