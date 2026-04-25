# Simplify Client Assertion Signing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix malformed `private_key_jwt` client assertions for `ClientCredentials` and consolidate private-key client assertion signing so RP token/PAR flows and client-credentials flows share one correct implementation.

**Architecture:** Replace the manual `header.payload` construction in `rp/client_credentials.go` with the same go-jose compact JWS construction pattern currently used by `rp/par.go`. Extract one package-private helper in `rp` that builds and signs private-key JWT client assertions from explicit inputs: client ID, audience, key provider, clock, and random reader. Keep public APIs unchanged.

**Tech Stack:** Go, `github.com/go-jose/go-jose/v4`, `go test`, `go vet`, `gofumpt`, package-local tests under `rp`

---

## Findings

- `rp/client_credentials.go:186-225` manually JSON-encodes a JWT header and claims, builds `header.payload`, calls `signClientAssertion`, then returns `payload + "." + signature`.
- `rp/client_credentials.go:228-245` uses `jose.NewSigner(...).Sign([]byte(input)).CompactSerialize()`, which returns a complete three-segment compact JWS. Appending that to the existing `header.payload` yields a malformed assertion with five segments instead of the required three.
- `rp/client_credentials_test.go:430-478` only checks that `client_assertion` exists in the token request body, so the malformed compact JWT is not detected.
- `rp/par.go:156-204` signs the JSON claims directly with go-jose and returns `sig.CompactSerialize()`, which has the correct compact JWS shape.
- `rp/par.go:156-204`, `rp/refresh_token.go:60-71`, and `rp/token_exchange.go:69-80` already share `(*RP).buildClientAssertion(audience string)` for RP flows.
- `rp/client_credentials.go:186-245` duplicates private-key client assertion behavior instead of reusing a common builder.
- Relevant spec expectations: JWT client assertions for `private_key_jwt` are sent as `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion=<compact JWT>`; the assertion is a signed JWT with `iss`, `sub`, `aud`, `exp`, and `jti` claims. Token endpoint authentication uses the token endpoint as the audience in OAuth client assertion profiles, while existing RP/PAR tests currently assert issuer audience for PAR/RP flows.

## Task 1: Add a Failing Regression Test for ClientCredentials Assertions

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`

**Step 1: Strengthen the existing private_key_jwt test**

Update `TestClientCredentials_PrivateKeyJWT` in `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go:430-478` so it parses the form body and validates the actual assertion.

Add imports if missing:

```go
import "github.com/go-jose/go-jose/v4"
```

After the existing request body checks, parse the form and verify the compact JWS:

```go
values, err := url.ParseQuery(requestBody)
if err != nil {
	t.Fatalf("ParseQuery(requestBody) failed: %v", err)
}

assertion := values.Get("client_assertion")
parts := strings.Split(assertion, ".")
if len(parts) != 3 {
	t.Fatalf("client_assertion should be a compact JWT with 3 parts, got %d: %q", len(parts), assertion)
}

parsed, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
if err != nil {
	t.Fatalf("ParseSigned(client_assertion) failed: %v", err)
}

payload, err := parsed.Verify(keyProvider.PrivateKey().(*rsa.PrivateKey).Public())
if err != nil {
	t.Fatalf("Verify(client_assertion) failed: %v", err)
}

var claims map[string]any
if err := json.Unmarshal(payload, &claims); err != nil {
	t.Fatalf("Unmarshal(client_assertion claims) failed: %v", err)
}

if got := claims["iss"]; got != "client-id" {
	t.Fatalf("client_assertion iss = %#v, want client-id", got)
}
if got := claims["sub"]; got != "client-id" {
	t.Fatalf("client_assertion sub = %#v, want client-id", got)
}
if got := claims["aud"]; got != server.URL+"/token" {
	t.Fatalf("client_assertion aud = %#v, want token endpoint", got)
}
if claims["jti"] == "" {
	t.Fatal("client_assertion jti is empty")
}
```

Use the concrete key returned by `createTestKeyProvider()` carefully. If the test cannot access the public key through the interface cleanly, inline RSA key generation in this test and pass it to `NewStaticClientKeyProvider(key, "test-key", "RS256", nil)` so verification can use `key.Public()`.

**Step 2: Run the failing test**

Run:

```bash
go test ./rp -run TestClientCredentials_PrivateKeyJWT -count=1
```

Expected before implementation: FAIL because `client_assertion` is not a three-part compact JWT or `jose.ParseSigned` cannot parse the malformed assertion.

## Task 2: Extract One Private-Key Client Assertion Builder

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/par.go`
- Modify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/par_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`
- Test: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`

**Step 1: Add the shared helper near the existing assertion code**

In `/home/kunde21/development/AI/lanyard/rp/par.go`, replace the private-key assertion construction body with a helper that accepts dependencies explicitly.

Target helper shape:

```go
func buildPrivateKeyClientAssertion(clientID, audience string, keyProvider ClientKeyProvider, now time.Time, randReader io.Reader) (string, error) {
	if keyProvider == nil {
		return "", fmt.Errorf("%w: client key provider not configured", ErrInvalidConfiguration)
	}

	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": generateJTI(randReader),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	alg := signatureAlgorithm(keyProvider.SigningAlgorithm())
	if alg == "" {
		return "", fmt.Errorf("unsupported signing algorithm: %s", keyProvider.SigningAlgorithm())
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: keyProvider.PrivateKey()}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"typ": "JWT",
			"kid": keyProvider.KeyID(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	sig, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return sig.CompactSerialize()
}
```

Preserve existing `generateJTI` behavior for this pass. Do not introduce a new exported API.

**Step 2: Rewire `(*RP).buildClientAssertion`**

Change `/home/kunde21/development/AI/lanyard/rp/par.go:156-204` to delegate only:

```go
func (r *RP) buildClientAssertion(audience string) (string, error) {
	return buildPrivateKeyClientAssertion(r.clientID, audience, r.clientKeyProvider, time.Now(), r.randReader)
}
```

This keeps RP behavior unchanged while eliminating the duplicated switch over algorithms. `time.Now()` preserves the current RP clock behavior.

**Step 3: Rewire `(*ClientCredentials).buildClientAssertion`**

Change `/home/kunde21/development/AI/lanyard/rp/client_credentials.go:186-225` to delegate to the shared helper:

```go
func (c *ClientCredentials) buildClientAssertion() (string, error) {
	return buildPrivateKeyClientAssertion(c.clientID, c.provider.TokenEndpoint, c.clientKeyProvider, c.now(), c.randReader)
}
```

Delete `/home/kunde21/development/AI/lanyard/rp/client_credentials.go:228-245` (`signClientAssertion`) because no caller should remain.

**Step 4: Clean imports**

After deleting manual construction in `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`, remove now-unused imports:

```go
"crypto"
"encoding/base64"
"time"

"github.com/go-jose/go-jose/v4"
```

Keep imports required by the rest of the file.

In `/home/kunde21/development/AI/lanyard/rp/par.go`, keep `crypto`, `encoding/base64`, `encoding/json`, `fmt`, `io`, `time`, and `github.com/go-jose/go-jose/v4` if still used by assertion and key helper code.

**Step 5: Run the targeted test again**

Run:

```bash
go test ./rp -run TestClientCredentials_PrivateKeyJWT -count=1
```

Expected after implementation: PASS.

## Task 3: Preserve Existing RP Assertion Behavior

**Files:**
- Modify: `/home/kunde21/development/AI/lanyard/rp/par_test.go`
- Optional Modify: `/home/kunde21/development/AI/lanyard/rp/token_exchange_test.go`
- Optional Modify: `/home/kunde21/development/AI/lanyard/rp/refresh_token_test.go`

**Step 1: Strengthen PAR verification if needed**

`/home/kunde21/development/AI/lanyard/rp/par_test.go:21-86` already asserts the PAR assertion is a three-part compact JWT and has `aud == "https://issuer.test"`. Add signature verification only if it can be done without duplicating a large helper.

Target minimal check:

```go
parsed, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.PS256})
if err != nil {
	t.Fatalf("ParseSigned(client_assertion) failed: %v", err)
}
if _, err := parsed.Verify(privateKey.Public()); err != nil {
	t.Fatalf("Verify(client_assertion) failed: %v", err)
}
```

**Step 2: Run RP assertion-related tests**

Run:

```bash
go test ./rp -run 'TestAuthorizationURL_UsesClientAssertionFormFieldsForPAR|TestAuthorizationURL_SignedRequestObjectPAR|TestRefreshToken_PrivateKeyJWT|TestExchangeToken_PrivateKeyJWT' -count=1
```

Expected: PASS. If a test name differs, use `go test ./rp -run 'PrivateKeyJWT|ClientAssertion|SignedRequestObjectPAR' -count=1` to cover the same behavior.

**Step 3: Do not change audience semantics in this refactor**

Keep existing RP audience selection in `/home/kunde21/development/AI/lanyard/rp/par.go`, `/home/kunde21/development/AI/lanyard/rp/refresh_token.go`, and `/home/kunde21/development/AI/lanyard/rp/token_exchange.go` unless a separate conformance issue explicitly requires changing it. This plan focuses on malformed ClientCredentials assertions and duplicate signing code.

## Task 4: Full Verification and Formatting

**Files:**
- Verify: `/home/kunde21/development/AI/lanyard/rp/client_credentials.go`
- Verify: `/home/kunde21/development/AI/lanyard/rp/par.go`
- Verify: `/home/kunde21/development/AI/lanyard/rp/client_credentials_test.go`
- Verify: `/home/kunde21/development/AI/lanyard/rp/par_test.go`

**Step 1: Format**

Run:

```bash
gofumpt ./rp
```

Expected: command exits 0 and only formats intended files.

**Step 2: Run focused tests**

Run:

```bash
go test ./rp -run 'ClientCredentials_PrivateKeyJWT|ClientAssertion|PrivateKeyJWT|SignedRequestObjectPAR' -count=1
```

Expected: PASS.

**Step 3: Run package tests**

Run:

```bash
go test ./rp -count=1
```

Expected: PASS.

**Step 4: Run project verification**

Run:

```bash
```

Expected: PASS.

**Step 5: Inspect the final diff**

Run:

```bash
git diff -- rp/client_credentials.go rp/par.go rp/client_credentials_test.go rp/par_test.go
```

Expected: the diff shows one shared private-key assertion builder, `ClientCredentials` using it, removal of `signClientAssertion`, and regression tests proving the client credentials assertion is parseable/verifiable as a three-part compact JWT.

## Non-Goals

- Do not add new public API.
- Do not change client-secret JWT assertion signing in `/home/kunde21/development/AI/lanyard/rp/par.go:214-249` unless tests reveal a direct regression.
- Do not change mTLS, DPoP, Basic, or Post authentication behavior.
- Do not change RP token/PAR audience semantics in the same patch; keep this fix narrowly scoped to malformed `ClientCredentials` assertions and duplicated private-key signing.
