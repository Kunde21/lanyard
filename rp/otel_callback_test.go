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

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
)

// TestHandleCallbackSpans drives a full authorization-code callback with a
// recording tracer and asserts both the span tree and that none of the
// flow's secrets (state, nonce, verifier, code, tokens, ID token, userinfo
// payload) leak into telemetry.
func TestHandleCallbackSpans(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	pub := jose.JSONWebKey{KeyID: "kid-1", Algorithm: string(jose.RS256), Use: "sig", Key: &key.PublicKey}
	now := time.Now().UTC()
	issuer := ""

	const (
		secretCode    = "SECRET-CODE"
		secretState   = "SECRET-STATE"
		secretNonce   = "SECRET-NONCE"
		secretVerify  = "SECRET-VERIFIER"
		secretAccess  = "SECRET-ACCESS-TOKEN"
		secretIDToken = "SECRET-ID-TOKEN-PAYLOAD" // asserted via its distinct claims content
	)

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
				"sub":   "SECRET-SUBJECT",
				"aud":   []string{"client-id"},
				"exp":   now.Add(5 * time.Minute).Unix(),
				"iat":   now.Unix(),
				"nonce": secretNonce,
			}
			body := `{"access_token":"` + secretAccess + `","token_type":"Bearer","expires_in":3600,"id_token":"` + signIDToken(t, key, "kid-1", claims) + `"}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"SECRET-SUBJECT","name":"SECRET-NAME"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	sr := newSpanRecorder(t)
	r, err := New(context.Background(), issuer,
		WithClientID("client-id"),
		WithClientSecret("SECRET-CLIENT-SECRET"),
		WithRedirectURI("https://rp.test/callback"),
		WithTracerProvider(sr.provider),
		WithHTTPClient(ts.Client()),
		withNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if err := r.stateStore.SaveCorrelation(context.Background(), nil, nil, secretState, CallbackCorrelation{
		Nonce:        secretNonce,
		CodeVerifier: secretVerify,
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	rec, req := callbackRequest(secretCode, secretState)
	result, err := r.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback() failed: %v", err)
	}
	if result.Subject != "SECRET-SUBJECT" {
		t.Fatalf("Subject = %q", result.Subject)
	}

	// Span tree: parent handle_callback with state validation, token
	// exchange, id token validation, and userinfo children (in call order).
	wantNames := []string{
		"rp.state_validation",
		"rp.token_exchange",
		"rp.id_token_validation",
		"rp.userinfo",
		"rp.handle_callback",
	}
	if diff := cmp.Diff(wantNames, sr.spanNames()); diff != "" {
		t.Fatalf("span tree mismatch (-want +got):\n%s", diff)
	}

	// No URL attributes carry query strings.
	for _, span := range sr.spans() {
		for _, kv := range span.Attributes() {
			if strings.Contains(kv.Value.AsString(), "?") {
				t.Fatalf("span %q attribute %q contains a query string: %q", span.Name(), kv.Key, kv.Value.AsString())
			}
		}
	}

	assertNoSecrets(t, sr.spans(), []string{
		secretCode, secretState, secretNonce, secretVerify, secretAccess,
		"SECRET-CLIENT-SECRET", "SECRET-SUBJECT", "SECRET-NAME",
	})
}

// TestHandleCallbackErrorSpan asserts the parent span records the sentinel
// for a failed callback (unknown state) without leaking the state value.
func TestHandleCallbackErrorSpan(t *testing.T) {
	sr := newSpanRecorder(t)
	r := claimsTestRP(t, WithTracerProvider(sr.provider))

	rec, req := callbackRequest("some-code", "SECRET-UNKNOWN-STATE")
	_, err := r.HandleCallback(rec, req)
	if err == nil {
		t.Fatal("HandleCallback() expected error")
	}

	spans := sr.spans()
	var parent bool
	for _, span := range spans {
		if span.Name() == "rp.handle_callback" {
			parent = true
			if got := span.Status().Description; !strings.Contains(got, ErrInvalidState.Error()) {
				t.Fatalf("status description = %q, want sentinel %q", got, ErrInvalidState.Error())
			}
		}
	}
	if !parent {
		t.Fatalf("handle_callback span missing: %v", sr.spanNames())
	}
	assertNoSecrets(t, spans, []string{"SECRET-UNKNOWN-STATE"})
}
