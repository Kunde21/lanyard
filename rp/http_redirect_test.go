package rp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
)

// errConsumerRedirectPolicy is a consumer-supplied sentinel used to prove the
// consumer's CheckRedirect callback participates in redirect decisions.
var errConsumerRedirectPolicy = errors.New("consumer redirect policy refusal")

func redirectProvider(redirector *httptest.Server) metadata.Provider {
	provider := providerForAuthMethods()
	provider.TokenEndpoint = redirector.URL + "/token"
	return provider
}

// TestSensitiveRequestHonorsConsumerErrUseLastResponse: a consumer client
// configured with http.ErrUseLastResponse stops at the initial 307 response
// and the redirect target never receives the credential-bearing POST body
// (sixth RC review R1).
func TestSensitiveRequestHonorsConsumerErrUseLastResponse(t *testing.T) {
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leak", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	stopping := redirector.Client()
	stopping.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cc, err := NewClientCredentials(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithHTTPClient(stopping),
		WithProviderMetadata(redirectProvider(redirector)),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials() failed: %v", err)
	}
	if _, err := cc.Token(context.Background()); err == nil {
		t.Fatal("Token() succeeded despite consumer stop-at-first-response policy")
	}
	if targetHits != 0 {
		t.Fatalf("redirect target hit %d times despite ErrUseLastResponse policy", targetHits)
	}
}

// TestSensitiveRequestHonorsConsumerCallbackError: a stricter consumer
// callback's error surfaces as the request failure (sixth RC review R1).
func TestSensitiveRequestHonorsConsumerCallbackError(t *testing.T) {
	targetHits := 0
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token-followed" {
			targetHits++
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/token-followed", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	consumerCalls := 0
	stricter := redirector.Client()
	stricter.CheckRedirect = func(*http.Request, []*http.Request) error {
		consumerCalls++
		return errConsumerRedirectPolicy
	}

	cc, err := NewClientCredentials(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithHTTPClient(stricter),
		WithProviderMetadata(redirectProvider(redirector)),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials() failed: %v", err)
	}
	if _, err := cc.Token(context.Background()); !errors.Is(err, errConsumerRedirectPolicy) {
		t.Fatalf("Token() err = %v, want consumer policy error", err)
	}
	if consumerCalls == 0 {
		t.Fatal("consumer CheckRedirect callback never consulted")
	}
	if targetHits != 0 {
		t.Fatal("redirect target reached despite consumer policy refusal")
	}
}

// TestSensitiveRequestConsumerCannotWeakenMinimum: even a fully permissive
// consumer callback cannot allow cross-origin or https-to-http redirects that
// the library minimum refuses (sixth RC review R1).
func TestSensitiveRequestConsumerCannotWeakenMinimum(t *testing.T) {
	cleartextHits := 0
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleartextHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer cleartext.Close()

	downgrader := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cleartext.URL+"/downgrade", http.StatusTemporaryRedirect)
	}))
	defer downgrader.Close()

	permissive := downgrader.Client()
	permissive.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }

	cc, err := NewClientCredentials(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithHTTPClient(permissive),
		WithProviderMetadata(redirectProvider(downgrader)),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials() failed: %v", err)
	}
	if _, err := cc.Token(context.Background()); !errors.Is(err, errInsecureRedirect) {
		t.Fatalf("Token() err = %v, want insecure-redirect rejection despite permissive consumer callback", err)
	}
	if cleartextHits != 0 {
		t.Fatal("credential body replayed to cleartext target despite permissive consumer callback")
	}
}

// TestSensitiveRequestPermittedRedirectWithConsumer: a same-origin https
// redirect that satisfies both the library minimum and a permissive consumer
// callback is followed to completion (sixth RC review R1).
func TestSensitiveRequestPermittedRedirectWithConsumer(t *testing.T) {
	targetHits := 0
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token-followed" {
			targetHits++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
			return
		}
		http.Redirect(w, r, "/token-followed", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	permissive := redirector.Client()
	permissive.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }

	cc, err := NewClientCredentials(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithHTTPClient(permissive),
		WithProviderMetadata(redirectProvider(redirector)),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials() failed: %v", err)
	}
	if _, err := cc.Token(context.Background()); err != nil {
		t.Fatalf("Token() failed on permitted same-origin redirect: %v", err)
	}
	if targetHits != 1 {
		t.Fatalf("redirect target hit %d times, want 1", targetHits)
	}
}

// TestSensitiveRequestConsumerImmutability: the consumer's client value is
// not mutated by the library (its CheckRedirect stays nil after a request).
func TestSensitiveRequestConsumerImmutability(t *testing.T) {
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer redirector.Close()

	plain := redirector.Client()
	if plain.CheckRedirect != nil {
		t.Fatal("precondition: fresh test client already has CheckRedirect")
	}

	cc, err := NewClientCredentials(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithHTTPClient(plain),
		WithProviderMetadata(redirectProvider(redirector)),
		WithAuthMethod(AuthMethodPost),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials() failed: %v", err)
	}
	if _, err := cc.Token(context.Background()); err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if plain.CheckRedirect != nil {
		t.Fatal("consumer http.Client was mutated by the library")
	}
}
