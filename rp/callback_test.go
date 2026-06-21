package rp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp/store/memory"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
)

func TestHandleCallbackValidation(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	rec, req := callbackRequest("code", "")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("missing state should return ErrInvalidState, got %v", err)
	}
	rec, req = callbackRequest("", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrMissingCode) {
		t.Fatalf("missing code should return ErrMissingCode, got %v", err)
	}
	rec, req = callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown state should return ErrInvalidState, got %v", err)
	}
}

func TestHandleCallbackFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	issuer := ""
	now := time.Now().UTC()

	var tokenStatus int
	var tokenBody string
	var userInfoBody string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			if tokenStatus != 0 {
				w.WriteHeader(tokenStatus)
				_, _ = w.Write([]byte(tokenBody))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenBody))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(userInfoBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

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

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}
	tokenStatus = http.StatusBadRequest
	tokenBody = `{"error":"invalid_grant"}`
	rec, req := callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("token error should return ErrTokenExchangeFailed, got %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}
	tokenStatus = 0
	tokenBody = `{"access_token":"access","token_type":"Bearer","expires_in":3600}`
	rec, req = callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrIDTokenValidationFailed) {
		t.Fatalf("missing id token should return ErrIDTokenValidationFailed, got %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}
	tokenStatus = 0
	badClaims := map[string]any{"iss": "https://wrong.test", "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
	tokenBody = `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", badClaims) + `"}`
	userInfoBody = `{"sub":"sub-123"}`
	rec, req = callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrIDTokenValidationFailed) {
		t.Fatalf("invalid id token should return ErrIDTokenValidationFailed, got %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}
	goodClaims := map[string]any{"iss": issuer, "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
	tokenBody = `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", goodClaims) + `"}`
	userInfoBody = `{"sub":"other"}`
	rec, req = callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrUserInfoValidationFailed) {
		t.Fatalf("userinfo mismatch should return ErrUserInfoValidationFailed, got %v", err)
	}
}

func TestHandleCallbackStateReplayRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			claims := map[string]any{"iss": issuer, "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
			body := `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", claims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"sub-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

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

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); err != nil {
		t.Fatalf("first HandleCallback() failed: %v", err)
	}

	rec, req = callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replayed state should return ErrInvalidState, got %v", err)
	}
}

func TestHandleCallback_ExposesIDTokenCnfClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""

	// The cnf.jkt the provider places on the id_token (simulating a DPoP-bound
	// identity). We do not need it to match the RP's own key for this test —
	// only that the value round-trips into CallbackResult.Cnf.
	const cnfJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			claims := map[string]any{
				"iss":   issuer,
				"sub":   "sub-123",
				"aud":   []string{"client-id"},
				"exp":   now.Add(5 * time.Minute).Unix(),
				"iat":   now.Unix(),
				"nonce": "nonce-1",
				"cnf":   map[string]string{"jkt": cnfJKT},
			}
			body := `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", claims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"sub-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

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

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest("code", "state")
	result, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}
	if result.Cnf == nil {
		t.Fatalf("expected CallbackResult.Cnf to be populated from id_token cnf claim")
	}
	want := &Confirmation{JKT: cnfJKT}
	if diff := cmp.Diff(want, result.Cnf); diff != "" {
		t.Errorf("CallbackResult.Cnf mismatch (-want +got):\n%s", diff)
	}
}

func TestHandleCallback_UsesMTLSAliasForTokenEndpoint(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""
	var tokenPath string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithMTLSEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token", "/mtls/token":
			tokenPath = r.URL.Path
			claims := map[string]any{"iss": issuer, "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
			body := `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", claims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case "/userinfo", "/mtls/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"sub-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithAuthMethod(AuthMethodTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", &tls.Certificate{})),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}

	if tokenPath != "/mtls/token" {
		t.Fatalf("token path = %q, want /mtls/token", tokenPath)
	}
}

func TestHandleCallback_UsesMTLSAliasForUserInfoWhenSenderConstrainMTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""
	var userInfoPath string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithMTLSEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token", "/mtls/token":
			claims := map[string]any{"iss": issuer, "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
			body := `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", claims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case "/userinfo", "/mtls/userinfo":
			userInfoPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"sub-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithAuthMethod(AuthMethodPost),
		WithSenderConstrain(SenderConstraintMTLS),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequestWithIss("code", "state", issuer)
	if _, err := r.HandleCallback(rec, req); err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}

	if userInfoPath != "/mtls/userinfo" {
		t.Fatalf("userinfo path = %q, want /mtls/userinfo", userInfoPath)
	}
}

func TestHandleCallback_RejectsInvalidAuthorizationResponseIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithValidateAuthorizationResponseIssuer(true),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now, Issuer: issuer}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	// Test: authorization response with invalid iss parameter should be rejected
	query := url.Values{}
	query.Set("code", "code")
	query.Set("state", "state")
	query.Set("iss", "https://wrong-issuer.test")
	req := httptest.NewRequest(http.MethodGet, "https://rp.test/callback?"+query.Encode(), nil)
	rec := httptest.NewRecorder()

	_, err = r.HandleCallback(rec, req)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("HandleCallback() with invalid iss should return ErrInvalidState, got %v", err)
	}
}

func TestHandleCallback_RejectsMissingAuthorizationResponseIssuerWhenValidationEnabled(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""
	tokenCalls := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/token":
			tokenCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithValidateAuthorizationResponseIssuer(true),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{
		CodeVerifier: "verifier",
		Nonce:        "nonce-123",
		CreatedAt:    now,
		Issuer:       issuer,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest("code", "state")
	_, err = r.HandleCallback(rec, req)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("HandleCallback() without iss should return ErrInvalidState when issuer validation is enabled, got %v", err)
	}
	if tokenCalls != 0 {
		t.Fatalf("tokenCalls = %d, want 0", tokenCalls)
	}
}

func callbackRequest(code, state string) (*httptest.ResponseRecorder, *http.Request) {
	return callbackRequestWithIss(code, state, "")
}

func callbackRequestWithIss(code, state, iss string) (*httptest.ResponseRecorder, *http.Request) {
	query := url.Values{}
	if code != "" {
		query.Set("code", code)
	}
	if state != "" {
		query.Set("state", state)
	}
	if iss != "" {
		query.Set("iss", iss)
	}

	requestURL := "https://rp.test/callback"
	if encoded := query.Encode(); encoded != "" {
		requestURL += "?" + encoded
	}

	return httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, requestURL, nil)
}

func callbackRequestWithIDToken(code, state, iss, idToken string) (*httptest.ResponseRecorder, *http.Request) {
	query := url.Values{}
	if code != "" {
		query.Set("code", code)
	}
	if state != "" {
		query.Set("state", state)
	}
	if iss != "" {
		query.Set("iss", iss)
	}
	if idToken != "" {
		query.Set("id_token", idToken)
	}

	requestURL := "https://rp.test/callback"
	if encoded := query.Encode(); encoded != "" {
		requestURL += "?" + encoded
	}

	return httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, requestURL, nil)
}

func providerMetadataJSONWithEndpoints(issuer string) string {
	return `{"issuer":"` + issuer + `","authorization_endpoint":"` + issuer + `/authorize","token_endpoint":"` + issuer + `/token","userinfo_endpoint":"` + issuer + `/userinfo","jwks_uri":"` + issuer + `/jwks","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`
}

func TestHandleCallback_RejectsInvalidAuthorizationResponseIDTokenBeforeTokenExchange(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""
	tokenCalls := 0

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			tokenCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProfile(PlainFAPI),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{
		CodeVerifier: "verifier",
		Nonce:        "nonce-123",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	authzIDToken := signIDToken(t, signingKey, "kid-1", map[string]any{
		"iss":    issuer,
		"sub":    "subject-123",
		"aud":    []string{"client-id"},
		"exp":    now.Add(5 * time.Minute).Unix(),
		"iat":    now.Add(-1 * time.Minute).Unix(),
		"c_hash": "bogus",
		"nonce":  "nonce-123",
		"s_hash": "bogus",
	})

	rec, req := callbackRequestWithIDToken("code", "state", "", authzIDToken)
	_, err = r.HandleCallback(rec, req)
	if !errors.Is(err, ErrIDTokenValidationFailed) {
		t.Fatalf("HandleCallback() error = %v, want ErrIDTokenValidationFailed", err)
	}
	if tokenCalls != 0 {
		t.Fatalf("tokenCalls = %d, want 0", tokenCalls)
	}
}

func TestHandleCallback_RejectsAuthorizationResponseIDTokenWithOldIATBeforeTokenExchange(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""
	tokenCalls := 0

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			tokenCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProfile(PlainFAPI),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{
		CodeVerifier: "verifier",
		Nonce:        "nonce-123",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	authzIDToken := signIDToken(t, signingKey, "kid-1", map[string]any{
		"iss":    issuer,
		"sub":    "subject-123",
		"aud":    []string{"client-id"},
		"exp":    now.Add(5 * time.Minute).Unix(),
		"iat":    now.Add(-7 * 24 * time.Hour).Unix(),
		"c_hash": "bogus",
		"nonce":  "nonce-123",
		"s_hash": "bogus",
	})

	rec, req := callbackRequestWithIDToken("code", "state", "", authzIDToken)
	_, err = r.HandleCallback(rec, req)
	if !errors.Is(err, ErrIDTokenValidationFailed) {
		t.Fatalf("HandleCallback() error = %v, want ErrIDTokenValidationFailed", err)
	}
	if tokenCalls != 0 {
		t.Fatalf("tokenCalls = %d, want 0", tokenCalls)
	}
}

func TestHandleCallback_AllowsOAuthOnlyTokenResponseWithoutIDToken(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithScopes("accounts"),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{
		CodeVerifier: "verifier",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest("code", "state")
	got, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}
	if got.AccessToken != "access" {
		t.Fatalf("AccessToken = %q, want access", got.AccessToken)
	}
}

func TestHandleCallback_UsesConfiguredProviderMetadataForOAuthOnly(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/custom-token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                 issuer,
			AuthorizationEndpoint:  issuer + "/authorize",
			TokenEndpoint:          issuer + "/custom-token",
			ResponseTypesSupported: []string{"code"},
		},
	}

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithScopes("accounts"),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{
		CodeVerifier: "verifier",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequestWithIss("code", "state", issuer)
	got, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}
	if got.AccessToken != "access" {
		t.Fatalf("AccessToken = %q, want access", got.AccessToken)
	}
}

func TestHandleCallback_FAPISkipsUserInfo(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""
	userinfoCalls := 0

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","id_token":"` + signIDToken(t, signingKey, "kid-1", map[string]any{
				"iss":   issuer,
				"sub":   "subject-123",
				"aud":   []string{"client-id"},
				"exp":   now.Add(5 * time.Minute).Unix(),
				"iat":   now.Add(-1 * time.Minute).Unix(),
				"nonce": "nonce-123",
			}) + `"}`))
		case "/userinfo":
			userinfoCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"subject-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithProfile(PlainFAPI),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{
		CodeVerifier: "verifier",
		Nonce:        "nonce-123",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequestWithIss("code", "state", issuer)
	got, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}
	if got.AccessToken != "access" {
		t.Fatalf("AccessToken = %q, want access", got.AccessToken)
	}
	if userinfoCalls != 0 {
		t.Fatalf("userinfoCalls = %d, want 0", userinfoCalls)
	}
}

func providerMetadataJSONWithMTLSEndpoints(issuer string) string {
	return `{"issuer":"` + issuer + `","authorization_endpoint":"` + issuer + `/authorize","token_endpoint":"` + issuer + `/token","userinfo_endpoint":"` + issuer + `/userinfo","jwks_uri":"` + issuer + `/jwks","mtls_endpoint_aliases":{"token_endpoint":"` + issuer + `/mtls/token","userinfo_endpoint":"` + issuer + `/mtls/userinfo","pushed_authorization_request_endpoint":"` + issuer + `/mtls/par"},"pushed_authorization_request_endpoint":"` + issuer + `/par","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`
}

func formPostCallbackRequest(code, state string) (*httptest.ResponseRecorder, *http.Request) {
	return formPostCallbackRequestWithIss(code, state, "")
}

func formPostCallbackRequestWithIss(code, state, iss string) (*httptest.ResponseRecorder, *http.Request) {
	form := url.Values{}
	if code != "" {
		form.Set("code", code)
	}
	if state != "" {
		form.Set("state", state)
	}
	if iss != "" {
		form.Set("iss", iss)
	}

	req := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httptest.NewRecorder(), req
}

func TestExtractCallbackParams_GETWithQuery(t *testing.T) {
	query := url.Values{}
	query.Set("code", "auth-code-1")
	query.Set("state", "state-1")
	query.Set("iss", "https://issuer.test")
	req := httptest.NewRequest(http.MethodGet, "https://rp.test/callback?"+query.Encode(), nil)

	params := extractCallbackParams(req)
	if params.Code != "auth-code-1" {
		t.Fatalf("Code = %q, want %q", params.Code, "auth-code-1")
	}
	if params.State != "state-1" {
		t.Fatalf("State = %q, want %q", params.State, "state-1")
	}
	if params.Iss != "https://issuer.test" {
		t.Fatalf("Iss = %q, want %q", params.Iss, "https://issuer.test")
	}
}

func TestExtractCallbackParams_POSTWithFormBody(t *testing.T) {
	form := url.Values{}
	form.Set("code", "auth-code-2")
	form.Set("state", "state-2")
	form.Set("iss", "https://issuer.test")
	req := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	params := extractCallbackParams(req)
	if params.Code != "auth-code-2" {
		t.Fatalf("Code = %q, want %q", params.Code, "auth-code-2")
	}
	if params.State != "state-2" {
		t.Fatalf("State = %q, want %q", params.State, "state-2")
	}
	if params.Iss != "https://issuer.test" {
		t.Fatalf("Iss = %q, want %q", params.Iss, "https://issuer.test")
	}
}

func TestExtractCallbackParams_POSTWithError(t *testing.T) {
	form := url.Values{}
	form.Set("error", "access_denied")
	form.Set("error_description", "user declined")
	req := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	params := extractCallbackParams(req)
	if params.Error != "access_denied" {
		t.Fatalf("Error = %q, want %q", params.Error, "access_denied")
	}
	if params.ErrorDescription != "user declined" {
		t.Fatalf("ErrorDescription = %q, want %q", params.ErrorDescription, "user declined")
	}
}

func TestExtractCallbackParams_EmptyPOSTBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	params := extractCallbackParams(req)
	if params.Code != "" {
		t.Fatalf("Code = %q, want empty", params.Code)
	}
	if params.State != "" {
		t.Fatalf("State = %q, want empty", params.State)
	}
}

func TestExtractCallbackParams_POSTWithoutFormContentType(t *testing.T) {
	form := url.Values{}
	form.Set("code", "auth-code-3")
	form.Set("state", "state-3")
	req := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/json")

	params := extractCallbackParams(req)
	if params.Code != "" {
		t.Fatalf("Code = %q, want empty (non-form content type should use query)", params.Code)
	}
}

func TestExtractCallbackParams_POSTWithQueryFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://rp.test/callback?code=q-code&state=q-state", nil)
	req.Header.Set("Content-Type", "text/plain")

	params := extractCallbackParams(req)
	if params.Code != "q-code" {
		t.Fatalf("Code = %q, want %q", params.Code, "q-code")
	}
	if params.State != "q-state" {
		t.Fatalf("State = %q, want %q", params.State, "q-state")
	}
}

func computeHashClaim(alg, rawValue string) string {
	var hash crypto.Hash
	switch {
	case strings.HasSuffix(alg, "256"):
		hash = crypto.SHA256
	case strings.HasSuffix(alg, "384"):
		hash = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		hash = crypto.SHA512
	default:
		return ""
	}
	h := hash.New()
	h.Write([]byte(rawValue))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func TestHandleCallback_HybridFlow_ByValueJAR(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	var storedNonce string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token":
			tokenClaims := map[string]any{
				"iss": issuer,
				"sub": "subject-123",
				"aud": []string{"client-id"},
				"exp": now.Add(5 * time.Minute).Unix(),
				"iat": now.Add(-1 * time.Minute).Unix(),
			}
			if storedNonce != "" {
				tokenClaims["nonce"] = storedNonce
			}
			tokenBody := `{"access_token":"access-token-123","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, signingKey, "kid-1", tokenClaims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	stateStore := memory.New(10 * time.Minute)
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithStateStore(stateStore),
		WithProfile(PlainFAPI),
		WithResponseType("code id_token"),
		WithRequestMethod("signed_non_repudiation"),
		WithClientKeyProvider(NewStaticClientKeyProvider(clientKey, "client-kid-1", "PS256", nil)),
		withNow(func() time.Time { return now }),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	rec := httptest.NewRecorder()
	authURL, err := r.AuthorizationURL(rec, req)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(authURL) failed: %v", err)
	}

	q := parsed.Query()
	if q.Get("request") == "" {
		t.Fatal("Authorization URL should contain 'request' parameter for by-value JAR")
	}
	if q.Get("request_uri") != "" {
		t.Fatal("Authorization URL should NOT contain 'request_uri' for by-value JAR")
	}
	if q.Get("response_type") != "code id_token" {
		t.Fatalf("response_type = %q, want %q", q.Get("response_type"), "code id_token")
	}

	state := q.Get("state")
	if state == "" {
		t.Fatal("state must be present")
	}

	stored, ok, err := stateStore.LoadState(context.Background(), nil, state)
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}
	if !ok {
		t.Fatal("state should be stored")
	}
	storedNonce = stored.Correlation.Nonce

	code := "authz-code-123"
	cHash := computeHashClaim("RS256", code)
	sHash := computeHashClaim("RS256", state)

	authzIDTokenClaims := map[string]any{
		"iss":    issuer,
		"sub":    "subject-123",
		"aud":    []string{"client-id"},
		"exp":    now.Add(5 * time.Minute).Unix(),
		"iat":    now.Add(-1 * time.Minute).Unix(),
		"nonce":  stored.Correlation.Nonce,
		"c_hash": cHash,
		"s_hash": sHash,
	}
	authzIDToken := signIDToken(t, signingKey, "kid-1", authzIDTokenClaims)

	rec, req = callbackRequestWithIDToken(code, state, "", authzIDToken)
	result, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}

	if result.Subject != "subject-123" {
		t.Fatalf("Subject = %q, want %q", result.Subject, "subject-123")
	}
	if result.AccessToken != "access-token-123" {
		t.Fatalf("AccessToken = %q, want %q", result.AccessToken, "access-token-123")
	}
}

func TestHandleCallback_HybridFlow_PushedJAR(t *testing.T) {
	now := time.Now().UTC()
	issuer := ""

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &signingKey.PublicKey}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	var parRequestBody string
	var tokenNonce string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithMTLSEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/mtls/par":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() failed: %v", err)
			}
			parRequestBody = r.FormValue("request")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:test-request-uri","expires_in":90}`))
		case "/mtls/token":
			tokenClaims := map[string]any{
				"iss": issuer,
				"sub": "subject-456",
				"aud": []string{"client-id"},
				"exp": now.Add(5 * time.Minute).Unix(),
				"iat": now.Add(-1 * time.Minute).Unix(),
			}
			if tokenNonce != "" {
				tokenClaims["nonce"] = tokenNonce
			}
			tokenBody := `{"access_token":"access-token-456","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, signingKey, "kid-1", tokenClaims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	stateStore := memory.New(10 * time.Minute)
	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithStateStore(stateStore),
		WithProfile(PlainFAPI),
		WithResponseType("code id_token"),
		WithRequestMethod("signed_non_repudiation"),
		WithClientKeyProvider(NewStaticClientKeyProvider(clientKey, "client-kid-1", "PS256", &tls.Certificate{})),
		WithAuthMethod(AuthMethodTLSClientAuth),
		WithRequirePAR(true),
		withNow(func() time.Time { return now }),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	rec := httptest.NewRecorder()
	authURL, err := r.AuthorizationURL(rec, req)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(authURL) failed: %v", err)
	}

	q := parsed.Query()
	if q.Get("request") != "" {
		t.Fatal("Authorization URL should NOT contain 'request' parameter for pushed JAR (uses request_uri)")
	}
	if q.Get("request_uri") == "" {
		t.Fatal("Authorization URL should contain 'request_uri' parameter for pushed JAR")
	}
	if q.Get("request_uri") != "urn:ietf:params:oauth:request_uri:test-request-uri" {
		t.Fatalf("request_uri = %q, want %q", q.Get("request_uri"), "urn:ietf:params:oauth:request_uri:test-request-uri")
	}
	if q.Get("client_id") != "client-id" {
		t.Fatalf("client_id = %q, want %q", q.Get("client_id"), "client-id")
	}

	if parRequestBody == "" {
		t.Fatal("PAR request should contain 'request' parameter in body")
	}

	state := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	stored, ok, err := stateStore.LoadState(context.Background(), nil, state)
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}
	if !ok {
		t.Fatal("state should be stored after AuthorizationURL for PAR")
	}

	tokenNonce = stored.Correlation.Nonce

	code := "authz-code-456"
	cHash := computeHashClaim("RS256", code)
	sHash := computeHashClaim("RS256", state)

	authzIDTokenClaims := map[string]any{
		"iss":    issuer,
		"sub":    "subject-456",
		"aud":    []string{"client-id"},
		"exp":    now.Add(5 * time.Minute).Unix(),
		"iat":    now.Add(-1 * time.Minute).Unix(),
		"nonce":  stored.Correlation.Nonce,
		"c_hash": cHash,
		"s_hash": sHash,
	}
	authzIDToken := signIDToken(t, signingKey, "kid-1", authzIDTokenClaims)

	rec, req = callbackRequestWithIDToken(code, state, issuer, authzIDToken)
	result, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}

	if result.Subject != "subject-456" {
		t.Fatalf("Subject = %q, want %q", result.Subject, "subject-456")
	}
	if result.AccessToken != "access-token-456" {
		t.Fatalf("AccessToken = %q, want %q", result.AccessToken, "access-token-456")
	}
}

func TestHandleCallback_FormPostValidation(t *testing.T) {
	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithProviderMetadata(providerForAuthMethods()),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	rec, req := formPostCallbackRequest("code", "")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("missing state should return ErrInvalidState, got %v", err)
	}
	rec, req = formPostCallbackRequest("", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrMissingCode) {
		t.Fatalf("missing code should return ErrMissingCode, got %v", err)
	}
	rec, req = formPostCallbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown state should return ErrInvalidState, got %v", err)
	}
}

func TestCallback_MTLSAliasForTokenEndpoint_SelfSignedTLSClientAuth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""
	var tokenPath string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithMTLSEndpoints(issuer)))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		case "/token", "/mtls/token":
			tokenPath = r.URL.Path
			claims := map[string]any{"iss": issuer, "sub": "sub-123", "aud": []string{"client-id"}, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": "nonce-1"}
			body := `{"access_token":"access","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", claims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case "/userinfo", "/mtls/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"sub-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-id"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithAuthMethod(AuthMethodSelfSignedTLSClientAuth),
		WithClientKeyProvider(NewStaticClientKeyProvider(key, "kid-1", "PS256", &tls.Certificate{})),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, "state", CallbackCorrelation{Nonce: "nonce-1", CodeVerifier: "verifier", CreatedAt: now}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest("code", "state")
	if _, err := r.HandleCallback(rec, req); err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}

	if tokenPath != "/mtls/token" {
		t.Fatalf("token path = %q, want /mtls/token", tokenPath)
	}
}
