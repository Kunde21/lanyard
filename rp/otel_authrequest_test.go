package rp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestAuthorizationURLSpans(t *testing.T) {
	sr := newSpanRecorder(t)
	r := claimsTestRP(t,
		WithTracerProvider(sr.provider),
		WithClientSecret("SECRET-CLIENT-SECRET-0123456789abcdef"),
		WithClaims(`{"userinfo":{"given_name":null}}`),
		WithRequestMethod("signed_non_repudiation"),
	)

	authURL, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil))
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}

	names := sr.spanNames()
	wantNames := []string{"rp.signed_request_object", "rp.authorization_url"}
	if diff := cmp.Diff(wantNames, names); diff != "" {
		t.Fatalf("span tree mismatch (-want +got):\n%s", diff)
	}

	// The authorization URL carries state/nonce/challenge in its query —
	// no attribute may contain a query string or the claims JSON.
	for _, span := range sr.spans() {
		for _, kv := range span.Attributes() {
			value := kv.Value.AsString()
			if strings.Contains(value, "?") {
				t.Fatalf("span %q attribute %q contains a URL query: %q", span.Name(), kv.Key, value)
			}
		}
	}
	assertNoSecrets(t, sr.spans(), []string{
		"SECRET-CLIENT-SECRET-0123456789abcdef",
		strings.Split(authURL, "?")[1], // the full query (state, nonce, PKCE)
	})

	// Scopes are recorded (identifiers, not secrets).
	found := false
	for _, span := range sr.spans() {
		if span.Name() != "rp.authorization_url" {
			continue
		}
		for _, kv := range span.Attributes() {
			if string(kv.Key) == "lanyard.scopes" && len(kv.Value.AsStringSlice()) > 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("authorization_url span missing scopes attribute")
	}
}

func TestAuthorizationURLErrorSpan(t *testing.T) {
	sr := newSpanRecorder(t)

	// No authorization endpoint: configuration error path.
	r := claimsTestRP(t, WithTracerProvider(sr.provider))
	r.provider.AuthorizationEndpoint = ""

	_, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil))
	if err == nil {
		t.Fatal("AuthorizationURL() expected error")
	}
	if diff := cmp.Diff(ErrInvalidConfiguration, err, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("error mismatch (-want +got):\n%s", diff)
	}

	spans := sr.spans()
	if len(spans) != 1 || spans[0].Name() != "rp.authorization_url" {
		t.Fatalf("spans = %v, want single authorization_url", sr.spanNames())
	}
	// The failure status carries the sentinel description, not the raw error.
	status := spans[0].Status()
	if status.Description != ErrInvalidConfiguration.Error() {
		t.Fatalf("span status description = %q, want sentinel %q", status.Description, ErrInvalidConfiguration.Error())
	}
}

func TestPARSpan(t *testing.T) {
	var gotForm string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		gotForm = string(body[:n])
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"request_uri":"urn:par:SECRET-PAR-REQUEST-URI","expires_in":90}`)
	}))
	defer ts.Close()

	sr := newSpanRecorder(t)
	provider := providerForAuthMethods()
	provider.PushedAuthorizationRequestEndpoint = ts.URL
	provider.JWKSURI = ts.URL

	r, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("SECRET-CLIENT-SECRET-0123456789abcdef"),
		WithRedirectURI("https://rp.test/callback"),
		WithTracerProvider(sr.provider),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
		WithRequirePAR(true),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if _, err := r.AuthorizationURL(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)); err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	if !strings.Contains(gotForm, "request=") {
		t.Fatalf("PAR request body unexpected: %q", gotForm)
	}

	wantNames := []string{"rp.par_request", "rp.authorization_url"}
	if diff := cmp.Diff(wantNames, sr.spanNames()); diff != "" {
		t.Fatalf("span tree mismatch (-want +got):\n%s", diff)
	}
	assertNoSecrets(t, sr.spans(), []string{"SECRET-PAR-REQUEST-URI", "SECRET-CLIENT-SECRET-0123456789abcdef"})
}
