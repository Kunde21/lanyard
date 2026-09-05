package rp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRefreshTokenSpans(t *testing.T) {
	const secretRefresh = "SECRET-REFRESH-TOKEN"
	var gotForm string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"SECRET-ACCESS-2","token_type":"Bearer","expires_in":3600,"refresh_token":"SECRET-ROTATED-REFRESH"}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods()
	provider.TokenEndpoint = ts.URL

	r, err := New(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("SECRET-CLIENT-SECRET"),
		WithRedirectURI("https://rp.test/callback"),
		WithTracerProvider(nil), // replaced below
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	sr := newSpanRecorder(t)
	r.tracer = sr.provider.Tracer(tracerName)

	if _, err := r.RefreshToken(context.Background(), secretRefresh); err != nil {
		t.Fatalf("RefreshToken() failed: %v", err)
	}
	if !strings.Contains(gotForm, secretRefresh) {
		t.Fatalf("refresh token not sent: %q", gotForm)
	}

	wantNames := []string{"rp.refresh_token"}
	if diff := cmp.Diff(wantNames, sr.spanNames()); diff != "" {
		t.Fatalf("span names mismatch (-want +got):\n%s", diff)
	}

	// The rotation event is recorded.
	rotated := false
	for _, span := range sr.spans() {
		for _, event := range span.Events() {
			if event.Name == "rotation" {
				rotated = true
			}
		}
	}
	if !rotated {
		t.Fatal("rotation event missing")
	}

	assertNoSecrets(t, sr.spans(), []string{
		secretRefresh, "SECRET-ROTATED-REFRESH", "SECRET-ACCESS-2", "SECRET-CLIENT-SECRET",
	})
}

func TestClientCredentialsSpans(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"SECRET-CC-TOKEN","token_type":"Bearer","expires_in":3600}`)
	}))
	defer ts.Close()

	provider := providerForAuthMethods()
	provider.TokenEndpoint = ts.URL

	sr := newSpanRecorder(t)
	cc, err := NewClientCredentials(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("SECRET-CLIENT-SECRET"),
		WithTracerProvider(sr.provider),
		WithHTTPClient(ts.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("NewClientCredentials() failed: %v", err)
	}

	if _, err := cc.Token(context.Background()); err != nil {
		t.Fatalf("Token() failed: %v", err)
	}

	if diff := cmp.Diff([]string{"rp.client_credentials"}, sr.spanNames()); diff != "" {
		t.Fatalf("span names mismatch (-want +got):\n%s", diff)
	}
	assertNoSecrets(t, sr.spans(), []string{"SECRET-CC-TOKEN", "SECRET-CLIENT-SECRET"})
}
