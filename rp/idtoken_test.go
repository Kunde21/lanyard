package rp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
)

func TestValidateIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	baseClaims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}

	goodToken := signIDToken(t, key, "kid-1", baseClaims)
	if _, err := r.validateIDToken(context.Background(), goodToken, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}

	missingKIDToken := signIDToken(t, key, "", baseClaims)
	if _, err := r.validateIDToken(context.Background(), missingKIDToken, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() with single signing key and missing kid failed: %v", err)
	}

	unsignedToken := signUnsecuredIDToken(t, baseClaims)

	rNoUnsecured := &RP{
		clientConfig: clientConfig{
			issuer:         issuer,
			clientID:       "client-id",
			httpClient:     ts.Client(),
			metadataClient: r.metadataClient,
			now:            func() time.Time { return now },
		},
		allowUnsecuredIDTokens: false,
	}
	if _, err := rNoUnsecured.validateIDToken(context.Background(), unsignedToken, "nonce-123", issuer+"/jwks", nil); err == nil {
		t.Fatalf("validateIDToken() with alg=none and allowUnsecuredIDTokens=false expected error")
	}

	rAllow := &RP{
		clientConfig: clientConfig{
			issuer:         issuer,
			clientID:       "client-id",
			httpClient:     ts.Client(),
			metadataClient: r.metadataClient,
			now:            func() time.Time { return now },
		},
		allowUnsecuredIDTokens: true,
	}
	if _, err := rAllow.validateIDToken(context.Background(), unsignedToken, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() with alg=none and allowUnsecuredIDTokens=true failed: %v", err)
	}

	rFAPI := &RP{
		clientConfig: clientConfig{
			issuer:         issuer,
			clientID:       "client-id",
			httpClient:     ts.Client(),
			metadataClient: r.metadataClient,
			now:            func() time.Time { return now },
		},
		profile:                profilePlainFAPI,
		allowUnsecuredIDTokens: true,
	}
	if _, err := rFAPI.validateIDToken(context.Background(), unsignedToken, "nonce-123", issuer+"/jwks", nil); err == nil {
		t.Fatalf("validateIDToken() with alg=none and FAPI profile expected error")
	}

	tests := []struct {
		name   string
		claims map[string]any
		nonce  string
		kid    string
	}{
		{name: "issuer mismatch", claims: cloneClaims(baseClaims, "iss", "https://other.test"), nonce: "nonce-123", kid: "kid-1"},
		{name: "audience mismatch", claims: cloneClaims(baseClaims, "aud", []string{"other-client"}), nonce: "nonce-123", kid: "kid-1"},
		{name: "missing exp", claims: removeClaim(baseClaims, "exp"), nonce: "nonce-123", kid: "kid-1"},
		{name: "missing iat", claims: removeClaim(baseClaims, "iat"), nonce: "nonce-123", kid: "kid-1"},
		{name: "expired", claims: cloneClaims(baseClaims, "exp", now.Add(-10*time.Minute).Unix()), nonce: "nonce-123", kid: "kid-1"},
		{name: "iat too far future", claims: cloneClaims(baseClaims, "iat", now.Add(10*time.Minute).Unix()), nonce: "nonce-123", kid: "kid-1"},
		{name: "nonce mismatch", claims: cloneClaims(baseClaims, "nonce", "wrong"), nonce: "nonce-123", kid: "kid-1"},
		{name: "azp required", claims: cloneClaims(baseClaims, "aud", []string{"client-id", "other"}), nonce: "nonce-123", kid: "kid-1"},
		{name: "azp mismatch", claims: cloneClaims(cloneClaims(baseClaims, "aud", []string{"client-id", "other"}), "azp", "other"), nonce: "nonce-123", kid: "kid-1"},
		{name: "unknown kid", claims: baseClaims, nonce: "nonce-123", kid: "other-kid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signIDToken(t, key, tt.kid, tt.claims)
			_, err := r.validateIDToken(context.Background(), token, tt.nonce, issuer+"/jwks", nil)
			if err == nil {
				t.Fatalf("validateIDToken() expected error")
			}
		})
	}
}

func TestValidateIDTokenRejectsAlgorithmNotInProviderList(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":   "https://issuer.test",
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}

	token := signIDTokenWithAlg(t, key, "kid-1", claims, jose.RS256)

	r := &RP{
		clientConfig: clientConfig{
			issuer:     "https://issuer.test",
			clientID:   "client-id",
			httpClient: http.DefaultClient,
			now:        func() time.Time { return now },
		},
	}

	_, err = r.validateIDToken(context.Background(), token, "nonce-123", "", []string{"ES256"})
	if err == nil {
		t.Fatalf("validateIDToken() expected error when algorithm not in provider list")
	}
	if !strings.Contains(err.Error(), "not in provider's advertised algorithms") {
		t.Fatalf("validateIDToken() error = %v, want algorithm mismatch error", err)
	}
}

func TestValidateIDTokenMissingKIDWithMultipleSigningKeysTriesAllKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(key1) failed: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(key2) failed: %v", err)
	}

	pub1 := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key1.PublicKey}
	pub2 := jose.JSONWebKey{KeyID: "kid-2", Algorithm: string(jose.RS256), Use: "sig", Key: &key2.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub1, pub2}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	claims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}

	token := signIDToken(t, key1, "", claims)
	if _, err := r.validateIDToken(context.Background(), token, "nonce-123", issuer+"/jwks", nil); err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}
}

func TestValidateIDToken_DecryptsEncryptedToken(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(signingKey) failed: %v", err)
	}
	decryptionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(decryptionKey) failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithClientKeyProvider(NewStaticClientKeyProvider(decryptionKey, "enc-kid", "PS256", nil)),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	claims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}
	signed := signIDToken(t, signingKey, "kid-1", claims)

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       jose.JSONWebKey{KeyID: "enc-kid", Use: "enc", Key: &decryptionKey.PublicKey},
	}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter() failed: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte(signed))
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	encrypted, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() failed: %v", err)
	}

	if _, err := r.validateIDToken(context.Background(), encrypted, "nonce-123", issuer+"/jwks", []string{"RS256"}); err != nil {
		t.Fatalf("validateIDToken() failed for encrypted token: %v", err)
	}
}

func TestValidateIDToken_RejectsRSA1_5EncryptedToken(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(signingKey) failed: %v", err)
	}
	decryptionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(decryptionKey) failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithClientKeyProvider(NewStaticClientKeyProvider(decryptionKey, "enc-kid", "PS256", nil)),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	claims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}
	signed := signIDToken(t, signingKey, "kid-1", claims)

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.RSA1_5,
		Key:       jose.JSONWebKey{KeyID: "enc-kid", Use: "enc", Key: &decryptionKey.PublicKey},
	}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter() failed: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte(signed))
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	encrypted, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() failed: %v", err)
	}

	if _, err := r.validateIDToken(context.Background(), encrypted, "nonce-123", issuer+"/jwks", nil); err == nil {
		t.Fatal("validateIDToken() expected error for RSA1_5 encrypted token")
	}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signIDTokenWithAlg(t, key, kid, claims, jose.RS256)
}

// signIDTokenPS256 signs with PS256 for FAPI-profile fixtures (FAPI accepts
// only PS256/ES256).
func signIDTokenPS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signIDTokenWithAlg(t, key, kid, claims, jose.PS256)
}

func signIDTokenWithAlg(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any, alg jose.SignatureAlgorithm) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{KeyID: kid, Key: key}}, nil)
	if err != nil {
		t.Fatalf("NewSigner() failed: %v", err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize() failed: %v", err)
	}

	return raw
}

func cloneClaims(src map[string]any, key string, value any) map[string]any {
	copy := make(map[string]any, len(src)+1)
	for k, v := range src {
		copy[k] = v
	}
	copy[key] = value
	return copy
}

func removeClaim(src map[string]any, key string) map[string]any {
	copy := make(map[string]any, len(src))
	for k, v := range src {
		if k == key {
			continue
		}
		copy[k] = v
	}
	return copy
}

func signUnsecuredIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "none"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("Marshal(header) failed: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal(claims) failed: %v", err)
	}

	enc := base64.RawURLEncoding
	return enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payloadJSON) + "."
}

func int64Ptr(v int64) *int64 {
	return &v
}

func TestValidateIDTokenClaims_RejectsOldIatForFAPIProfile(t *testing.T) {
	now := time.Now().UTC()
	claims := idTokenClaims{
		Issuer:  "https://example.com",
		Subject: "sub-1",
		Aud:     audienceClaim{"client-1"},
		Exp:     int64Ptr(now.Add(5 * time.Minute).Unix()),
		Iat:     int64Ptr(now.Add(-7 * 24 * time.Hour).Unix()),
		Nonce:   "nonce-1",
	}

	r := &RP{
		clientConfig: clientConfig{
			issuer:   "https://example.com",
			clientID: "client-1",
			now:      func() time.Time { return now },
		},
		profile:   profilePlainFAPI,
		clockSkew: 5 * time.Minute,
	}

	err := r.validateIDTokenClaims(claims, "nonce-1")
	if err == nil {
		t.Fatal("validateIDTokenClaims() expected error for week-old iat with FAPI profile")
	}
	if !strings.Contains(err.Error(), "iat") {
		t.Fatalf("expected iat-related error, got: %v", err)
	}
}

func TestValidateIDTokenClaims_AllowsOldIatForNonFAPI(t *testing.T) {
	now := time.Now().UTC()
	claims := idTokenClaims{
		Issuer:  "https://example.com",
		Subject: "sub-1",
		Aud:     audienceClaim{"client-1"},
		Exp:     int64Ptr(now.Add(5 * time.Minute).Unix()),
		Iat:     int64Ptr(now.Add(-7 * 24 * time.Hour).Unix()),
		Nonce:   "nonce-1",
	}

	r := &RP{
		clientConfig: clientConfig{
			issuer:   "https://example.com",
			clientID: "client-1",
			now:      func() time.Time { return now },
		},
		profile:   profileOIDC,
		clockSkew: 5 * time.Minute,
	}

	err := r.validateIDTokenClaims(claims, "nonce-1")
	if err != nil {
		t.Fatalf("validateIDTokenClaims() unexpected error for non-FAPI: %v", err)
	}
}

func TestValidateIDToken_ParsesCnfClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	claims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
		"cnf":   map[string]string{"jkt": "thumbprint-value", "x5t#S256": "cert-thumbprint"},
	}
	raw := signIDToken(t, key, "kid-1", claims)

	got, err := r.validateIDToken(context.Background(), raw, "nonce-123", issuer+"/jwks", nil)
	if err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}
	if got.Cnf == nil {
		t.Fatal("expected cnf claim to be parsed, got nil")
	}
	want := &Confirmation{JKT: "thumbprint-value", X5T256: "cert-thumbprint"}
	if diff := cmp.Diff(want, got.Cnf); diff != "" {
		t.Errorf("cnf mismatch (-want +got):\n%s", diff)
	}
}

func TestValidateIDToken_NoCnfClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}

	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	now := time.Now().UTC()
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	claims := map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   []string{"client-id"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"nonce": "nonce-123",
	}
	raw := signIDToken(t, key, "kid-1", claims)

	got, err := r.validateIDToken(context.Background(), raw, "nonce-123", issuer+"/jwks", nil)
	if err != nil {
		t.Fatalf("validateIDToken() failed: %v", err)
	}
	if got.Cnf != nil {
		t.Errorf("expected nil cnf for token without cnf claim, got %+v", got.Cnf)
	}
}

// TestValidateIDToken_UnsignedPolicy: signed verification is the default;
// explicit configuration is honored either way; advertised algorithms apply
// to unsigned tokens with no per-client exceptions.
func TestValidateIDToken_UnsignedPolicy(t *testing.T) {
	claims := map[string]any{
		"iss":   "https://issuer.test",
		"sub":   "sub-123",
		"aud":   []string{"client"},
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "nonce-123",
	}
	unsigned := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(mustJSON(t, claims)) + "."

	newTestRP := func(opts ...AuthCodeOption) *RP {
		r := claimsTestRP(t)
		for _, opt := range opts {
			if opt != nil {
				opt.applyAuthCode(r)
			}
		}
		return r
	}

	// Default: rejected.
	if _, err := newTestRP().validateIDToken(context.Background(), unsigned, "nonce-123", "", nil); err == nil {
		t.Fatal("default accepted unsigned id_token")
	}

	// Explicit opt-in: accepted.
	r := newTestRP(WithAllowUnsecuredIDTokens(true))
	got, err := r.validateIDToken(context.Background(), unsigned, "nonce-123", "", nil)
	if err != nil {
		t.Fatalf("explicit opt-in rejected: %v", err)
	}
	if got.Subject != "sub-123" {
		t.Fatalf("subject = %q", got.Subject)
	}

	// Explicit opt-in but "none" not advertised: rejected.
	if _, err := newTestRP(WithAllowUnsecuredIDTokens(true)).
		validateIDToken(context.Background(), unsigned, "nonce-123", "", []string{"RS256"}); err == nil {
		t.Fatal("unsigned id_token accepted despite not being advertised")
	}

	// No per-client exception: any client ID enforcing the same policy.
	r2 := claimsTestRP(t)
	r2.clientID = "local-dev-client-2"
	if _, err := r2.validateIDToken(context.Background(), unsigned, "nonce-123", "", []string{"RS256"}); err == nil {
		t.Fatal("client-specific bypass still present")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}
	return encoded
}

// TestValidateIDToken_UsesProviderJWKSWihoutDiscovery: with preloaded
// provider metadata, signed-ID-token validation resolves keys from the
// configured jwks_uri and never touches a discovery endpoint (RC review F5).
func TestValidateIDToken_UsesProviderJWKSWihoutDiscovery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()

	// The issuer host serves ONLY /jwks; every discovery request 404s.
	jwksOnly := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	}))
	defer jwksOnly.Close()

	provider := providerForAuthMethods()
	provider.JWKSURI = jwksOnly.URL + "/jwks"

	r, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("a-very-secret-secret-0123456789abcdef"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(jwksOnly.Client()),
		WithProviderMetadata(provider),
		WithDiscoveryMode(DiscoveryDisabled),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	signed := signIDToken(t, key, "kid-1", map[string]any{
		"iss":   "https://issuer.test",
		"sub":   "sub-123",
		"aud":   []string{"client"},
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": "nonce-123",
	})

	claims, err := r.validateIDToken(context.Background(), signed, "nonce-123", "", []string{"RS256"})
	if err != nil {
		t.Fatalf("validateIDToken() failed (discovery was required?): %v", err)
	}
	if claims.Subject != "sub-123" {
		t.Fatalf("subject = %q", claims.Subject)
	}
}

// TestFAPIProfileRejectsDisallowedIDTokenAlgorithms: FAPI profiles accept
// only PS256/ES256 ID tokens even when the provider advertises more (FAPI
// policy audit A1).
func TestFAPIProfileRejectsDisallowedIDTokenAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	now := time.Now().UTC()

	r := claimsTestRP(t, WithProfile(FAPI2SecurityProfile),
		WithAuthMethod(AuthMethodTLSClientAuth),
		WithProviderMetadata(providerWithPAR(providerForAuthMethods("private_key_jwt", "tls_client_auth"), "https://issuer.test/par")),
		WithSenderConstrain(SenderConstraintMTLS),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid", "PS256", testTLSCertificate(key))),
		WithRequestMethod("signed_non_repudiation"),
	)

	rs256 := signIDToken(t, key, "kid", map[string]any{
		"iss": "https://issuer.test", "sub": "sub", "aud": []string{"client"},
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "n",
	})
	if _, err := r.validateIDToken(context.Background(), rs256, "n", "", []string{"RS256", "PS256"}); err == nil {
		t.Fatal("RS256 id_token accepted under FAPI profile")
	}

	ps256 := signIDTokenPS256(t, key, "kid", map[string]any{
		"iss": "https://issuer.test", "sub": "sub", "aud": []string{"client"},
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "n",
	})
	_, psErr := r.validateIDToken(context.Background(), ps256, "n", "", []string{"PS256"})
	if psErr != nil && strings.Contains(psErr.Error(), `expected ["PS256" "ES256"]`) {
		t.Fatalf("PS256 id_token rejected by the algorithm gate: %v", psErr)
	}
}

// TestFAPIProfileEnforcesKeyPolicy: FAPI construction rejects RS256 signing
// material and RSA keys under 2048 bits (FAPI policy audit A2+A4).
func TestFAPIProfileEnforcesKeyPolicy(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey(1024) failed: %v", err)
	}
	strongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(2048) failed: %v", err)
	}

	newFAPI := func(key *rsa.PrivateKey, alg string) (*RP, error) {
		return New(context.Background(), "https://issuer.test",
			WithClientID("client"),
			WithRedirectURI("https://rp.test/callback"),
			WithProviderMetadata(providerWithPAR(providerForAuthMethods(), "https://issuer.test/par")),
			WithProfile(FAPI2SecurityProfile),
			WithAuthMethod(AuthMethodPrivateKeyJWT),
			WithSenderConstrain(SenderConstraintMTLS),
			WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid", alg, testTLSCertificate(strongKey))),
			WithRequestMethod("signed_non_repudiation"),
		)
	}

	if _, err := newFAPI(strongKey, "RS256"); err == nil || !strings.Contains(err.Error(), "PS256 or ES256") {
		t.Fatalf("RS256 signing material err = %v, want PS256/ES256 restriction", err)
	}
	if _, err := newFAPI(weakKey, "PS256"); err == nil || !strings.Contains(err.Error(), "at least 2048") {
		t.Fatalf("weak key err = %v, want 2048-bit floor", err)
	}
	if _, err := newFAPI(strongKey, "PS256"); err != nil {
		t.Fatalf("compliant configuration rejected: %v", err)
	}
}
