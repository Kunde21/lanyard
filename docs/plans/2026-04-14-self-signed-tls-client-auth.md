# self_signed_tls_client_auth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `self_signed_tls_client_auth` as a first-class client authentication method, distinct from `tls_client_auth` per RFC 8705.

**Architecture:** `self_signed_tls_client_auth` behaves identically to `tls_client_auth` at the HTTP layer (client_id in body, TLS cert via transport, mTLS endpoint aliases), but is a separate `AuthMethod` constant because providers may advertise only one or the other, and validation requirements differ. Both methods share the same request-shape logic — the difference is purely in how the server validates the certificate (JWKS x5c match vs DN/SAN).

**Tech Stack:** Go, existing `rp` package, `github.com/google/go-cmp/cmp` for test assertions.

---

### Task 1: Add `AuthMethodSelfSignedTLSClientAuth` constant

**Files:**
- Modify: `rp/auth_method.go:10-17`
- Test: `rp/auth_method_test.go`

**Step 1: Write the failing test**

Add a test that references the new constant:

```go
func TestAuthMethodSelfSignedTLSClientAuth_ConstantValue(t *testing.T) {
	if diff := cmp.Diff(AuthMethod("self_signed_tls_client_auth"), AuthMethodSelfSignedTLSClientAuth); diff != "" {
		t.Fatalf("constant mismatch (-want +got):\n%s", diff)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestAuthMethodSelfSignedTLSClientAuth_ConstantValue ./rp/`
Expected: FAIL — `AuthMethodSelfSignedTLSClientAuth` undefined

**Step 3: Write minimal implementation**

In `rp/auth_method.go`, add the constant after `AuthMethodTLSClientAuth`:

```go
AuthMethodSelfSignedTLSClientAuth AuthMethod = "self_signed_tls_client_auth"
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestAuthMethodSelfSignedTLSClientAuth_ConstantValue ./rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/auth_method.go rp/auth_method_test.go
git commit -m "feat(rp): add AuthMethodSelfSignedTLSClientAuth constant"
```

---

### Task 2: Update `methodSupported` for bidirectional cross-support

**Files:**
- Modify: `rp/auth_method.go:49-74`
- Test: `rp/auth_method_test.go`

**Step 1: Write the failing tests**

```go
func TestMethodSupported_SelfSignedTLSClientAuth(t *testing.T) {
	tests := []struct {
		name     string
		method   AuthMethod
		supported []string
		want     bool
	}{
		{
			name:     "exact match",
			method:   AuthMethodSelfSignedTLSClientAuth,
			supported: []string{"self_signed_tls_client_auth"},
			want:     true,
		},
		{
			name:     "self_signed matched when provider has tls_client_auth",
			method:   AuthMethodSelfSignedTLSClientAuth,
			supported: []string{"tls_client_auth"},
			want:     true,
		},
		{
			name:     "tls_client_auth matched when provider has self_signed",
			method:   AuthMethodTLSClientAuth,
			supported: []string{"self_signed_tls_client_auth"},
			want:     true,
		},
		{
			name:     "self_signed not matched by unrelated methods",
			method:   AuthMethodSelfSignedTLSClientAuth,
			supported: []string{"client_secret_post"},
			want:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := methodSupported(tc.method, tc.supported)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("methodSupported mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestMethodSupported_SelfSignedTLSClientAuth ./rp/`
Expected: FAIL — "self_signed matched when provider has tls_client_auth" returns false

**Step 3: Write implementation**

Replace the existing `tls_client_auth` cross-support block in `methodSupported` (`rp/auth_method.go:61-67`) with bidirectional logic:

```go
if want == "tls_client_auth" || want == "self_signed_tls_client_auth" {
	for _, current := range supported {
		if current == "tls_client_auth" || current == "self_signed_tls_client_auth" {
			return true
		}
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestMethodSupported_SelfSignedTLSClientAuth ./rp/`
Expected: PASS

**Step 5: Run existing tests to verify no regression**

Run: `go test ./rp/`
Expected: PASS

**Step 6: Commit**

```bash
git add rp/auth_method.go rp/auth_method_test.go
git commit -m "feat(rp): bidirectional cross-support between tls_client_auth and self_signed_tls_client_auth in methodSupported"
```

---

### Task 3: Update `validateResolvedAuthMethod` for self-signed TLS client auth

**Files:**
- Modify: `rp/client_config.go:117-144`
- Test: `rp/auth_method_test.go`

**Step 1: Write the failing test**

```go
func TestNew_SelfSignedTLSClientAuth_RequiresClientKeyProviderWithTLSCert(t *testing.T) {
	_, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("self_signed_tls_client_auth")),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth),
	)
	if err == nil {
		t.Fatalf("New() expected error when no client key provider")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestNew_SelfSignedTLSClientAuth_RequiresClientKeyProviderWithTLSCert ./rp/`
Expected: FAIL — "unsupported token endpoint auth method"

**Step 3: Write implementation**

In `rp/client_config.go` `validateResolvedAuthMethod`, add a case before `default:`:

```go
case AuthMethodSelfSignedTLSClientAuth:
	if c.clientKeyProvider == nil || c.clientKeyProvider.TLSCertificate() == nil {
		return fmt.Errorf("%w: tls certificate is required for token endpoint auth method %q", ErrInvalidConfiguration, method)
	}
	return nil
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestNew_SelfSignedTLSClientAuth_RequiresClientKeyProviderWithTLSCert ./rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/client_config.go rp/auth_method_test.go
git commit -m "feat(rp): validate self_signed_tls_client_auth requires TLS certificate"
```

---

### Task 4: Update auth method negotiation preference to include self_signed_tls_client_auth

**Files:**
- Modify: `rp/client_config.go:76-115`
- Test: `rp/auth_method_test.go`

**Step 1: Write the failing test**

```go
func TestNew_AutoNegotiatesSelfSignedTLSClientAuthWhenAdvertised(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods("self_signed_tls_client_auth")),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if diff := cmp.Diff(AuthMethodSelfSignedTLSClientAuth, r.resolvedAuthMethod); diff != "" {
		t.Fatalf("resolved auth method mismatch (-want +got):\n%s", diff)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestNew_AutoNegotiatesSelfSignedTLSClientAuthWhenAdvertised ./rp/`
Expected: FAIL — negotiates to `AuthMethodTLSClientAuth` instead of `AuthMethodSelfSignedTLSClientAuth`

**Step 3: Write implementation**

In `rp/client_config.go` `resolveAuthMethodFromProvider`, add a new preference case after the `AuthMethodTLSClientAuth` check (line ~91):

```go
case methodSupported(AuthMethodSelfSignedTLSClientAuth, supported):
	resolved = AuthMethodSelfSignedTLSClientAuth
```

Place it between the `AuthMethodTLSClientAuth` and `AuthMethodPost` preference cases so the full preference order becomes:
`private_key_jwt` → `tls_client_auth` → `self_signed_tls_client_auth` → `client_secret_post` → `client_secret_basic`

**Step 4: Run test to verify it passes**

Run: `go test -run TestNew_AutoNegotiatesSelfSignedTLSClientAuthWhenAdvertised ./rp/`
Expected: PASS

**Step 5: Run all auth method tests**

Run: `go test -run TestNew ./rp/`
Expected: PASS

**Step 6: Commit**

```bash
git add rp/client_config.go rp/auth_method_test.go
git commit -m "feat(rp): auto-negotiate self_signed_tls_client_auth when advertised"
```

---

### Task 5: Update token exchange for self_signed_tls_client_auth

**Files:**
- Modify: `rp/token_exchange.go:13-28` (buildTokenRequest)
- Modify: `rp/token_exchange.go:60-103` (exchangeTokenOnce)
- Test: `rp/token_exchange_test.go`

**Step 1: Write the failing test**

```go
func TestExchangeTokenRequestShape_SelfSignedTLSClientAuth(t *testing.T) {
	var gotForm url.Values

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("self_signed_tls_client_auth")
	provider.TokenEndpoint = ts.URL

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = r.exchangeToken(context.Background(), ts.URL, "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeToken() failed: %v", err)
	}

	wantForm := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"redirect_uri":  "https://rp.test/callback",
		"code_verifier": "verifier",
		"client_id":     "client",
	}
	for key, want := range wantForm {
		if gotForm.Get(key) != want {
			t.Fatalf("form %q mismatch: want %q got %q", key, want, gotForm.Get(key))
		}
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatalf("client_secret should not be present for self_signed_tls_client_auth")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestExchangeTokenRequestShape_SelfSignedTLSClientAuth ./rp/`
Expected: FAIL — `AuthMethodSelfSignedTLSClientAuth` not handled in switch

**Step 3: Write implementation**

In `rp/token_exchange.go` `buildTokenRequest`, add after the `AuthMethodTLSClientAuth` case:

```go
case AuthMethodSelfSignedTLSClientAuth:
```

In `rp/token_exchange.go` `exchangeTokenOnce`, add after the `AuthMethodTLSClientAuth` case (line 94-95):

```go
case AuthMethodSelfSignedTLSClientAuth:
	form.Set("client_id", r.clientID)
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestExchangeTokenRequestShape_SelfSignedTLSClientAuth ./rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/token_exchange.go rp/token_exchange_test.go
git commit -m "feat(rp): handle self_signed_tls_client_auth in token exchange"
```

---

### Task 6: Update client credentials for self_signed_tls_client_auth

**Files:**
- Modify: `rp/client_credentials.go:97-123` (requestToken)
- Modify: `rp/client_credentials.go:169-183` (buildTokenRequest)
- Test: `rp/client_credentials_test.go`

**Step 1: Write the failing test**

```go
func TestClientCredentials_Token_SelfSignedTLSClientAuth(t *testing.T) {
	var requestBody string
	var authHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "self-signed-mtls-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	provider := clientCredentialsProvider(server.URL, AuthMethodSelfSignedTLSClientAuth)

	client, err := NewClientCredentials(ctx, "https://auth.example.com",
		WithClientID("client-id"),
		WithProviderMetadata(provider),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	token, err := client.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error: %v", err)
	}

	if token.AccessToken != "self-signed-mtls-token" {
		t.Errorf("expected self-signed-mtls-token, got: %s", token.AccessToken)
	}
	if authHeader != "" {
		t.Errorf("expected no Authorization header for self_signed_tls_client_auth, got: %s", authHeader)
	}
	if !strings.Contains(requestBody, "client_id=client-id") {
		t.Errorf("expected client_id in body, got: %s", requestBody)
	}
	if strings.Contains(requestBody, "client_secret=") {
		t.Errorf("client_secret should not be in body for self_signed_tls_client_auth, got: %s", requestBody)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestClientCredentials_Token_SelfSignedTLSClientAuth ./rp/`
Expected: FAIL

**Step 3: Write implementation**

In `rp/client_credentials.go` `requestToken`, add after the `AuthMethodPrivateKeyJWT` case in the switch (before `AuthMethodPost`):

```go
case AuthMethodSelfSignedTLSClientAuth:
```

In `rp/client_credentials.go` `buildTokenRequest`, add after the `AuthMethodTLSClientAuth` case:

```go
case AuthMethodSelfSignedTLSClientAuth:
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestClientCredentials_Token_SelfSignedTLSClientAuth ./rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/client_credentials.go rp/client_credentials_test.go
git commit -m "feat(rp): handle self_signed_tls_client_auth in client credentials"
```

---

### Task 7: Update mTLS endpoint alias routing for self_signed_tls_client_auth

**Files:**
- Modify: `rp/endpoints.go:30-36`
- Test: `rp/callback_test.go` (add test for MTLS alias with self_signed_tls_client_auth)

**Step 1: Write the failing test**

In `rp/callback_test.go`, add a test that verifies the mTLS token endpoint alias is used when `AuthMethodSelfSignedTLSClientAuth` is the resolved method. Follow the pattern of the existing `TestCallback_MTLSAliasForTokenEndpoint` test but use `self_signed_tls_client_auth`.

```go
func TestCallback_MTLSAliasForTokenEndpoint_SelfSignedTLSClientAuth(t *testing.T) {
	var gotTokenURL string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokenURL = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken: "access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IDToken:     "idtoken",
		})
	}))
	defer ts.Close()

	provider := providerForAuthMethods("self_signed_tls_client_auth")
	provider.TokenEndpoint = ts.URL + "/token"
	provider.MTLSEndpointAliases.TokenEndpoint = ts.URL + "/mtls/token"

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(nil, "", "", &tls.Certificate{})),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/callback?code=abc&state=def", nil)
	w := httptest.NewRecorder()
	r.HandleCallback(w, req, "verifier", func(tok Token) { _ = tok })

	if gotTokenURL != "/mtls/token" {
		t.Fatalf("token endpoint path = %q, want /mtls/token", gotTokenURL)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestCallback_MTLSAliasForTokenEndpoint_SelfSignedTLSClientAuth ./rp/`
Expected: FAIL — uses `/token` instead of `/mtls/token`

**Step 3: Write implementation**

In `rp/endpoints.go`, update `usesMTLSForPAR` and `usesMTLSForTokenEndpoint`:

```go
func (r *RP) usesMTLSForPAR() bool {
	return r.resolvedAuthMethod == AuthMethodTLSClientAuth || r.resolvedAuthMethod == AuthMethodSelfSignedTLSClientAuth
}

func (r *RP) usesMTLSForTokenEndpoint() bool {
	return r.resolvedAuthMethod == AuthMethodTLSClientAuth || r.resolvedAuthMethod == AuthMethodSelfSignedTLSClientAuth || r.senderConstrain == SenderConstraintMTLS
}
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestCallback_MTLSAliasForTokenEndpoint_SelfSignedTLSClientAuth ./rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/endpoints.go rp/callback_test.go
git commit -m "feat(rp): route to mTLS endpoint aliases for self_signed_tls_client_auth"
```

---

### Task 8: Update DPoP support check for self_signed_tls_client_auth

**Files:**
- Modify: `rp/dpop.go:194-196`
- Test: `rp/dpop_usage_test.go`

**Step 1: Write the failing test**

```go
func TestIsDPoPSupported_SelfSignedTLSClientAuth(t *testing.T) {
	if !isDPoPSupported(AuthMethodSelfSignedTLSClientAuth) {
		t.Fatalf("isDPoPSupported should return true for self_signed_tls_client_auth")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestIsDPoPSupported_SelfSignedTLSClientAuth ./rp/`
Expected: FAIL — returns false

**Step 3: Write implementation**

In `rp/dpop.go`, update `isDPoPSupported`:

```go
func isDPoPSupported(method AuthMethod) bool {
	return method == AuthMethodPrivateKeyJWT || method == AuthMethodTLSClientAuth || method == AuthMethodSelfSignedTLSClientAuth
}
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestIsDPoPSupported_SelfSignedTLSClientAuth ./rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add rp/dpop.go rp/dpop_usage_test.go
git commit -m "feat(rp): enable DPoP for self_signed_tls_client_auth"
```

---

### Task 9: Update example RP runtime for self_signed_tls_client_auth

**Files:**
- Modify: `cmd/example-rp/runtime_resolution.go:258-271`

**Step 1: Write the failing test**

In `cmd/example-rp/runtime_resolution_test.go`, add a test that verifies `self_signed_tls_client_auth` resolves to `AuthMethodSelfSignedTLSClientAuth` (not `AuthMethodTLSClientAuth`):

```go
func TestAuthMethodForRuntime_SelfSignedTLSClientAuth(t *testing.T) {
	cfg := rpRuntimeConfig{ClientAuthType: "self_signed_tls_client_auth"}
	got, ok := authMethodForRuntime(cfg)
	if !ok {
		t.Fatalf("expected auth method to resolve")
	}
	if diff := cmp.Diff(rp.AuthMethodSelfSignedTLSClientAuth, got); diff != "" {
		t.Fatalf("auth method mismatch (-want +got):\n%s", diff)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestAuthMethodForRuntime_SelfSignedTLSClientAuth ./cmd/example-rp/`
Expected: FAIL — currently maps to `AuthMethodTLSClientAuth`

**Step 3: Write implementation**

In `cmd/example-rp/runtime_resolution.go` `authMethodForRuntime`, split the combined case:

```go
case "tls_client_auth", "mtls":
	return rp.AuthMethodTLSClientAuth, true
case "self_signed_tls_client_auth":
	return rp.AuthMethodSelfSignedTLSClientAuth, true
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestAuthMethodForRuntime_SelfSignedTLSClientAuth ./cmd/example-rp/`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/example-rp/runtime_resolution.go cmd/example-rp/runtime_resolution_test.go
git commit -m "feat(example-rp): resolve self_signed_tls_client_auth to dedicated auth method"
```

---

### Task 10: Update public API external test and run full verification

**Files:**
- Modify: `rp/public_api_external_test.go`
- No code changes needed in `rp/` itself (all previous tasks cover it)

**Step 1: Add `AuthMethodSelfSignedTLSClientAuth` to the public API surface test**

In `rp/public_api_external_test.go`, add after the existing `AuthMethod` constant references:

```go
_ = rp.AuthMethodSelfSignedTLSClientAuth
```

**Step 2: Run the full test suite**

Run: `go test ./...`
Expected: PASS

**Step 3: Run lint and format**

Run: `gofumpt ./... && go vet ./...`
Expected: clean

**Step 4: Commit**

```bash
git add rp/public_api_external_test.go
git commit -m "test(rp): add AuthMethodSelfSignedTLSClientAuth to public API surface test"
```

---

## Summary of changes

| File | Change |
|------|--------|
| `rp/auth_method.go` | Add `AuthMethodSelfSignedTLSClientAuth` constant; update `methodSupported` for bidirectional cross-support |
| `rp/client_config.go` | Add validation and negotiation for `AuthMethodSelfSignedTLSClientAuth` |
| `rp/token_exchange.go` | Handle `AuthMethodSelfSignedTLSClientAuth` in `buildTokenRequest` and `exchangeTokenOnce` |
| `rp/client_credentials.go` | Handle `AuthMethodSelfSignedTLSClientAuth` in `requestToken` and `buildTokenRequest` |
| `rp/endpoints.go` | Include `AuthMethodSelfSignedTLSClientAuth` in mTLS endpoint alias routing |
| `rp/dpop.go` | Include `AuthMethodSelfSignedTLSClientAuth` in `isDPoPSupported` |
| `cmd/example-rp/runtime_resolution.go` | Map `self_signed_tls_client_auth` to `AuthMethodSelfSignedTLSClientAuth` |
| `rp/auth_method_test.go` | Tests for constant, `methodSupported`, validation, negotiation |
| `rp/token_exchange_test.go` | Test token exchange request shape |
| `rp/client_credentials_test.go` | Test client credentials request shape |
| `rp/callback_test.go` | Test mTLS alias routing |
| `rp/dpop_usage_test.go` | Test DPoP support |
| `rp/public_api_external_test.go` | Public API surface test |
| `cmd/example-rp/runtime_resolution_test.go` | Test runtime auth method resolution |
