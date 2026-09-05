package metadata

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func metadataSpanRecorder(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return recorder, provider
}

func discoveryTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer": "` + issuer + `",
			"authorization_endpoint": "` + issuer + `/authorize",
			"token_endpoint": "` + issuer + `/token",
			"jwks_uri": "` + issuer + `/jwks",
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestDiscoverySpan(t *testing.T) {
	recorder, provider := metadataSpanRecorder(t)
	server := discoveryTestServer(t)

	client := NewClient(
		WithTracerProvider(provider),
		WithHTTPClient(server.Client()),
	)
	if _, err := client.DiscoverProvider(context.Background(), "https://issuer-secret.example.com"); err != nil {
		t.Logf("DiscoverProvider against unreachable issuer failed (expected for offline test): %v", err)
	}

	_ = client

	// Span exists and carries the mode attribute; the issuer attribute is
	// the URL itself (query-free by construction).
	spans := recorder.Ended()
	found := false
	for _, span := range spans {
		if span.Name() != "metadata.discovery" {
			continue
		}
		found = true
		modeOK, issuerOK := false, false
		for _, kv := range span.Attributes() {
			if string(kv.Key) == "lanyard.discovery.mode" && kv.Value.AsString() == "oidc" {
				modeOK = true
			}
			if string(kv.Key) == "lanyard.issuer" && strings.Contains(kv.Value.AsString(), "issuer-secret.example.com") {
				issuerOK = true
			}
		}
		if !modeOK {
			t.Fatalf("discovery span missing mode attribute: %v", span.Attributes())
		}
		if !issuerOK {
			t.Fatalf("discovery span missing issuer attribute: %v", span.Attributes())
		}
	}
	if !found {
		t.Fatalf("no metadata.discovery span recorded: %v", spans)
	}
}

func TestJWKSSpanStripsQuery(t *testing.T) {
	recorder, provider := metadataSpanRecorder(t)

	client := NewClient(WithTracerProvider(provider))
	_, _ = client.RemoteKeySetFromJWKSURI("https://issuer.example.com/jwks?access_token=SECRET-TOKEN")

	for _, span := range recorder.Ended() {
		if span.Name() != "metadata.jwks" {
			continue
		}
		for _, kv := range span.Attributes() {
			value := kv.Value.AsString()
			if strings.Contains(value, "?") || strings.Contains(value, "SECRET-TOKEN") {
				t.Fatalf("jwks uri attribute leaks query: %q", value)
			}
		}
		return
	}
	t.Fatal("no metadata.jwks span recorded")
}

func TestSafeErrorDescription(t *testing.T) {
	// Wrapped chains must still resolve to the sentinel description.
	wrapped := fmt.Errorf("fetch failed: %w", ErrDiscoveryFailed)
	if diff := cmp.Diff(ErrDiscoveryFailed, wrapped, cmpopts.EquateErrors()); diff != "" {
		t.Fatalf("fixture does not wrap the sentinel (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("discovery failed", safeErrorDescription(wrapped)); diff != "" {
		t.Fatalf("wrapped sentinel description mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("http status 404", safeErrorDescription(&HTTPStatusError{StatusCode: 404})); diff != "" {
		t.Fatalf("http status description mismatch (-want +got):\n%s", diff)
	}
	if got := safeErrorDescription(context.Canceled); got == "" {
		t.Fatal("fallback description empty")
	}
	_ = errors.Is // keep errors imported for flow assertions
}
