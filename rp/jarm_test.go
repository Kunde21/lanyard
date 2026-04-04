package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
)

func TestIsJARMResponse(t *testing.T) {
	tests := []struct {
		name   string
		params callbackParams
		want   bool
	}{
		{name: "has response param", params: callbackParams{Response: "eyJhbG.eyJz.abc"}, want: true},
		{name: "no response param", params: callbackParams{Code: "abc", State: "xyz"}, want: false},
		{name: "empty response param", params: callbackParams{Response: ""}, want: false},
		{name: "whitespace response", params: callbackParams{Response: "  "}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &RP{}
			got := r.isJARMResponse(tc.params)
			if got != tc.want {
				t.Errorf("isJARMResponse() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseJARMResponse_ValidatesAndExtractsClaims(t *testing.T) {
	key := jarmTestRSAKey(t)
	now := time.Now().UTC()

	claims := map[string]any{
		"iss":   "https://issuer.test",
		"aud":   "client-1",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"code":  "auth-code-123",
		"state": "state-xyz",
	}

	jwksServer, signed := newJARMTestServer(t, key, "signing-key-1", claims)
	defer jwksServer.Close()

	r := newJARMTestRP(t, jwksServer, "client-1", now)
	parsed, err := r.parseJARMResponse(context.Background(), signed)
	if err != nil {
		t.Fatalf("parseJARMResponse() failed: %v", err)
	}

	if diff := cmp.Diff("auth-code-123", parsed.Code); diff != "" {
		t.Errorf("code mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("state-xyz", parsed.State); diff != "" {
		t.Errorf("state mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://issuer.test", parsed.Iss); diff != "" {
		t.Errorf("iss mismatch (-want +got):\n%s", diff)
	}
}

func TestParseJARMResponse_RejectsExpired(t *testing.T) {
	key := jarmTestRSAKey(t)
	now := time.Now().UTC()

	claims := map[string]any{
		"iss":   "https://issuer.test",
		"aud":   "client-1",
		"exp":   now.Add(-10 * time.Minute).Unix(),
		"iat":   now.Add(-15 * time.Minute).Unix(),
		"code":  "auth-code-123",
		"state": "state-xyz",
	}

	jwksServer, signed := newJARMTestServer(t, key, "signing-key-1", claims)
	defer jwksServer.Close()

	r := newJARMTestRP(t, jwksServer, "client-1", now)
	_, err := r.parseJARMResponse(context.Background(), signed)
	if err == nil {
		t.Fatal("expected error for expired JARM")
	}
}

func TestParseJARMResponse_RejectsAudienceMismatch(t *testing.T) {
	key := jarmTestRSAKey(t)
	now := time.Now().UTC()

	claims := map[string]any{
		"iss":   "https://issuer.test",
		"aud":   "wrong-client",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"code":  "auth-code-123",
		"state": "state-xyz",
	}

	jwksServer, signed := newJARMTestServer(t, key, "signing-key-1", claims)
	defer jwksServer.Close()

	r := newJARMTestRP(t, jwksServer, "client-1", now)
	_, err := r.parseJARMResponse(context.Background(), signed)
	if err == nil {
		t.Fatal("expected error for JARM audience mismatch")
	}
}

func TestParseJARMResponse_RejectsMissingExp(t *testing.T) {
	key := jarmTestRSAKey(t)
	now := time.Now().UTC()

	claims := map[string]any{
		"iss":   "https://issuer.test",
		"aud":   "client-1",
		"iat":   now.Unix(),
		"code":  "auth-code-123",
		"state": "state-xyz",
	}

	jwksServer, signed := newJARMTestServer(t, key, "signing-key-1", claims)
	defer jwksServer.Close()

	r := newJARMTestRP(t, jwksServer, "client-1", now)
	_, err := r.parseJARMResponse(context.Background(), signed)
	if err == nil {
		t.Fatal("expected error for JARM missing exp")
	}
}

func TestParseJARMResponse_RejectsEmpty(t *testing.T) {
	r := &RP{}
	_, err := r.parseJARMResponse(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty JARM")
	}
}

func TestExtractCallbackParams_IncludesResponseParameter(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		url      string
		body     string
		wantResp string
	}{
		{
			name:     "query parameter",
			method:   http.MethodGet,
			url:      "https://rp.test/callback?response=eyJhbG.test.abc&state=s1",
			wantResp: "eyJhbG.test.abc",
		},
		{
			name:     "form post",
			method:   http.MethodPost,
			url:      "https://rp.test/callback",
			body:     "response=eyJhbG.test.abc&state=s1",
			wantResp: "eyJhbG.test.abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.method == http.MethodPost {
				req = httptest.NewRequest(http.MethodPost, tc.url, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(http.MethodGet, tc.url, nil)
			}

			params := extractCallbackParams(req)
			if diff := cmp.Diff(tc.wantResp, params.Response); diff != "" {
				t.Errorf("Response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func newJARMTestServer(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) (*httptest.Server, string) {
	t.Helper()
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	signed := signJARMToken(t, key, kid, claims)
	return jwksServer, signed
}

func newJARMTestRP(t *testing.T, jwksServer *httptest.Server, clientID string, now time.Time) *RP {
	t.Helper()
	provider := oidc.ProviderMetadata{
		AuthorizationServerMetadata: oidc.AuthorizationServerMetadata{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     "https://issuer.test/token",
			JWKSURI:                           jwksServer.URL,
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		clientID,
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(jwksServer.Client()),
		WithProviderMetadata(provider),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return r
}

func signJARMToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": kid},
	})
	if err != nil {
		t.Fatalf("create JARM signer: %v", err)
	}

	payload, _ := json.Marshal(claims)
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign JARM: %v", err)
	}
	out, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize JARM: %v", err)
	}
	return out
}

func jarmTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}
