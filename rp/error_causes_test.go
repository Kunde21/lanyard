package rp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
)

// typedTransportError is a consumer-recognizable transport failure used to
// prove typed causes survive the library's error wrapping.
type typedTransportError struct{ msg string }

func (e *typedTransportError) Error() string { return e.msg }

// TestIntrospectionPreservesCancellationCause: an already-canceled context
// surfaces both the operation sentinel and context.Canceled through
// errors.Is (sixth RC review R2).
func TestIntrospectionPreservesCancellationCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached with a canceled context")
	}))
	defer server.Close()

	introspector, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithProviderMetadata(introspectionProvider(server.URL+"/introspect", "client_secret_basic")),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = introspector.IntrospectToken(ctx, IntrospectionRequest{Token: "token"})
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("IntrospectToken() error = %v, want ErrIntrospectionFailed", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("IntrospectToken() error = %v, want context.Canceled reachable via errors.Is", err)
	}
}

// TestIntrospectionFallbackPreservesCancellationCause: the post->basic auth
// fallback retry path also preserves the underlying cause.
func TestIntrospectionFallbackPreservesCancellationCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	introspector, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithProviderMetadata(introspectionProvider(server.URL+"/introspect", "client_secret_post", "client_secret_basic")),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = introspector.IntrospectToken(ctx, IntrospectionRequest{Token: "token"})
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("IntrospectToken() error = %v, want ErrIntrospectionFailed", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("IntrospectToken() error = %v, want context.Canceled reachable via errors.Is on the fallback path", err)
	}
}

// TestIntrospectionPreservesDeadlineCause: deadline expiration stays
// machine-readable.
func TestIntrospectionPreservesDeadlineCause(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	introspector, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithProviderMetadata(introspectionProvider(server.URL+"/introspect", "client_secret_basic")),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = introspector.IntrospectToken(ctx, IntrospectionRequest{Token: "token"})
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("IntrospectToken() error = %v, want ErrIntrospectionFailed", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("IntrospectToken() error = %v, want context.DeadlineExceeded reachable via errors.Is", err)
	}
}

// TestIntrospectionPreservesTypedTransportError: consumer-visible typed
// transport errors survive wrapping via errors.As.
func TestIntrospectionPreservesTypedTransportError(t *testing.T) {
	introspector, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithProviderMetadata(introspectionProvider("https://issuer.test/introspect", "client_secret_basic")),
		WithHTTPClient(&http.Client{Transport: failingTransport{&typedTransportError{msg: "circuit breaker open"}}}),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	_, err = introspector.IntrospectToken(context.Background(), IntrospectionRequest{Token: "token"})
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Fatalf("IntrospectToken() error = %v, want ErrIntrospectionFailed", err)
	}
	var typed *typedTransportError
	if !errors.As(err, &typed) {
		t.Fatalf("IntrospectToken() error = %v, want *typedTransportError reachable via errors.As", err)
	}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// TestGrantManagementPreservesCancellationCause: query and revoke keep both
// the sentinel and context.Canceled reachable.
func TestGrantManagementPreservesCancellationCause(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be reached with a canceled context")
	}
	m := grantManagerTestServer(t, handler)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := m.QueryGrant(ctx, "access-token", "g1"); !errors.Is(err, ErrGrantManagementFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("QueryGrant() error = %v, want ErrGrantManagementFailed and context.Canceled reachable", err)
	}
	if err := m.RevokeGrant(ctx, "access-token", "g1"); !errors.Is(err, ErrGrantManagementFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("RevokeGrant() error = %v, want ErrGrantManagementFailed and context.Canceled reachable", err)
	}
}

// TestGrantManagementPreservesTypedTransportError: typed transport failures
// survive grant query wrapping.
func TestGrantManagementPreservesTypedTransportError(t *testing.T) {
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			TokenEndpoint:                     "https://issuer.test/token",
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		},
		GrantManagementEndpoint:          "https://issuer.test/grants",
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	m, err := NewGrantManager(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("super-secret-secret-0123456789abcdef"),
		WithHTTPClient(&http.Client{Transport: failingTransport{&typedTransportError{msg: "connection pool exhausted"}}}),
		WithProviderMetadata(provider),
	)
	if err != nil {
		t.Fatalf("NewGrantManager() failed: %v", err)
	}

	_, err = m.QueryGrant(context.Background(), "access-token", "g1")
	if !errors.Is(err, ErrGrantManagementFailed) {
		t.Fatalf("QueryGrant() error = %v, want ErrGrantManagementFailed", err)
	}
	var typed *typedTransportError
	if !errors.As(err, &typed) {
		t.Fatalf("QueryGrant() error = %v, want *typedTransportError reachable via errors.As", err)
	}
}
