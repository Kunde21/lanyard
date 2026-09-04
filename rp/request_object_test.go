package rp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
)

func TestBuildSignedRequestObject_ContainsExpectedClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	provider := NewStaticClientKeyProvider(key, "test-kid-1", "PS256", nil)
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	r := &RP{
		clientConfig: clientConfig{
			issuer:            "https://example.com",
			clientID:          "client-1",
			scopes:            []string{"openid", "profile"},
			clientKeyProvider: provider,
			now:               func() time.Time { return fixedNow },
			randReader:        strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI:  "https://rp.example.com/callback",
		responseMode: "query.jwt",
	}

	signed, err := r.buildSignedRequestObject("test-state", "test-nonce", "challenge-value", "", nil, nil, "", nil)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	claims := decodeRequestObjectPayload(t, signed)

	wantClaims := map[string]any{
		"iss":                   "client-1",
		"aud":                   "https://example.com",
		"client_id":             "client-1",
		"response_type":         "code",
		"redirect_uri":          "https://rp.example.com/callback",
		"scope":                 "openid profile",
		"state":                 "test-state",
		"nonce":                 "test-nonce",
		"code_challenge":        "challenge-value",
		"code_challenge_method": "S256",
		"response_mode":         "query.jwt",
		"iat":                   float64(fixedNow.Unix()),
		"nbf":                   float64(fixedNow.Unix()),
		"exp":                   float64(fixedNow.Add(5 * time.Minute).Unix()),
	}

	for k, want := range wantClaims {
		got, ok := claims[k]
		if !ok {
			t.Errorf("missing claim %q", k)
			continue
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("claim %q mismatch (-want +got):\n%s", k, diff)
		}
	}

	if _, ok := claims["jti"]; !ok {
		t.Error("missing jti claim")
	}

	verifyRequestObjectSignature(t, signed, key.Public())
}

func TestBuildSignedRequestObject_OmitsNonceWithoutOpenIDScope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	provider := NewStaticClientKeyProvider(key, "test-kid-2", "PS256", nil)

	r := &RP{
		clientConfig: clientConfig{
			issuer:            "https://example.com",
			clientID:          "client-1",
			scopes:            []string{"accounts"},
			clientKeyProvider: provider,
			now:               func() time.Time { return time.Now().UTC() },
			randReader:        strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.example.com/callback",
	}

	signed, err := r.buildSignedRequestObject("state", "nonce", "challenge", "", nil, nil, "", nil)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	claims := decodeRequestObjectPayload(t, signed)
	if _, ok := claims["nonce"]; ok {
		t.Error("nonce should be omitted when openid scope is not present")
	}
}

func TestBuildSignedRequestObject_UsesConfiguredResponseType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	r := &RP{
		clientConfig: clientConfig{
			issuer:            "https://example.com",
			clientID:          "client-1",
			scopes:            []string{"openid"},
			clientKeyProvider: NewStaticClientKeyProvider(key, "kid", "PS256", nil),
			now:               func() time.Time { return time.Now().UTC() },
			randReader:        strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI:  "https://rp.example.com/callback",
		responseType: "code id_token",
	}

	signed, err := r.buildSignedRequestObject("state", "nonce", "challenge", "", nil, nil, "", nil)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	claims := decodeRequestObjectPayload(t, signed)
	if got := claims["response_type"]; got != "code id_token" {
		t.Fatalf("response_type = %#v, want %q", got, "code id_token")
	}
}

func TestBuildSignedRequestObject_RequiresKeyProvider(t *testing.T) {
	r := &RP{
		clientConfig: clientConfig{
			issuer:     "https://example.com",
			clientID:   "client-1",
			scopes:     []string{"openid"},
			now:        func() time.Time { return time.Now().UTC() },
			randReader: strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.example.com/callback",
	}

	_, err := r.buildSignedRequestObject("state", "nonce", "challenge", "", nil, nil, "", nil)
	if err == nil {
		t.Fatal("expected error without key provider")
	}
}

func TestBuildSignedRequestObject_ES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	provider := NewStaticClientKeyProvider(key, "ec-kid", "ES256", nil)

	r := &RP{
		clientConfig: clientConfig{
			issuer:            "https://example.com",
			clientID:          "client-1",
			scopes:            []string{"openid"},
			clientKeyProvider: provider,
			now:               func() time.Time { return time.Now().UTC() },
			randReader:        strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.example.com/callback",
	}

	signed, err := r.buildSignedRequestObject("state", "nonce", "challenge", "", nil, nil, "", nil)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	parsed, err := jose.ParseSigned(signed, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse signed request object: %v", err)
	}

	if parsed.Signatures[0].Header.Algorithm != string(jose.ES256) {
		t.Errorf("algorithm = %q, want ES256", parsed.Signatures[0].Header.Algorithm)
	}
	if parsed.Signatures[0].Header.KeyID != "ec-kid" {
		t.Errorf("kid = %q, want %q", parsed.Signatures[0].Header.KeyID, "ec-kid")
	}

	verifyRequestObjectSignature(t, signed, key.Public())
}

func TestBuildSignedRequestObject_AuthorizationDetails(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	provider := NewStaticClientKeyProvider(key, "kid", "PS256", nil)

	r := &RP{
		clientConfig: clientConfig{
			issuer:            "https://example.com",
			clientID:          "client-1",
			scopes:            []string{"openid"},
			clientKeyProvider: provider,
			now:               func() time.Time { return time.Now().UTC() },
			randReader:        strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.example.com/callback",
	}

	details := `[{"type":"account_information"}]`
	signed, err := r.buildSignedRequestObject("state", "nonce", "challenge", details, nil, nil, "", nil)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	claims := decodeRequestObjectPayload(t, signed)
	want := []any{map[string]any{"type": "account_information"}}
	if diff := cmp.Diff(want, claims["authorization_details"]); diff != "" {
		t.Errorf("authorization_details mismatch (-want +got):\n%s", diff)
	}
}

func TestSigningAlgorithm_Unsupported(t *testing.T) {
	got := signatureAlgorithm("HS256")
	if got != "" {
		t.Errorf("signatureAlgorithm(HS256) = %q, want empty", got)
	}
}

func TestIsStandardRequestObjectClaim(t *testing.T) {
	standardClaims := []string{
		"iss", "aud", "client_id", "response_type", "redirect_uri", "scope",
		"state", "nonce", "code_challenge", "code_challenge_method",
		"authorization_details", "response_mode", "iat", "nbf", "exp", "jti",
	}
	for _, claim := range standardClaims {
		if !isStandardRequestObjectClaim(claim) {
			t.Errorf("isStandardRequestObjectClaim(%q) = false, want true", claim)
		}
	}
	if isStandardRequestObjectClaim("custom_param") {
		t.Error("isStandardRequestObjectClaim(custom_param) = true, want false")
	}
}

func decodeRequestObjectPayload(t *testing.T, signed string) map[string]any {
	t.Helper()

	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatalf("request object should have 3 parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	return claims
}

func verifyRequestObjectSignature(t *testing.T, signed string, pubKey any) {
	t.Helper()

	parsed, err := jose.ParseSigned(signed, []jose.SignatureAlgorithm{jose.PS256, jose.RS256, jose.ES256, jose.PS384, jose.ES384})
	if err != nil {
		t.Fatalf("failed to parse signed request object: %v", err)
	}

	_, err = parsed.Verify(pubKey)
	if err != nil {
		t.Fatalf("failed to verify request object signature: %v", err)
	}
}

func TestBuildSignedRequestObject_IncludesResourceArray(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	provider := NewStaticClientKeyProvider(key, "test-kid-1", "PS256", nil)
	fixedNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	r := &RP{
		clientConfig: clientConfig{
			issuer:            "https://example.com",
			clientID:          "client-1",
			scopes:            []string{"openid"},
			clientKeyProvider: provider,
			now:               func() time.Time { return fixedNow },
			randReader:        strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.example.com/callback",
	}

	signed, err := r.buildSignedRequestObject(
		"state", "nonce", "challenge", "",
		[]string{"https://api.example.com/", "https://payments.example.com/"},
		nil, "", nil,
	)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	claims := decodeRequestObjectPayload(t, signed)

	want := []any{"https://api.example.com/", "https://payments.example.com/"}
	if diff := cmp.Diff(want, claims["resource"]); diff != "" {
		t.Fatalf("resource claim mismatch (-want +got):\n%s", diff)
	}
}
