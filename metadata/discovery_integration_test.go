package metadata

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDiscoverProviderSWRAndETag(t *testing.T) {
	type state struct {
		mu         sync.Mutex
		calls      int
		body       string
		etag       string
		lastIfNone string
	}

	s := &state{}
	issuer := ""
	s.etag = `"v1"`

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls++
		s.lastIfNone = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=1")
		w.Header().Set("ETag", s.etag)
		if s.lastIfNone != "" && s.lastIfNone == s.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(s.body))
	})

	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	issuer = ts.URL
	s.body = providerResponse(issuer, issuer+"/token-v1")

	c := NewClient(WithHTTPClient(ts.Client()), WithDefaultDiscoveryTTL(100*time.Millisecond))

	got1, err := c.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		t.Fatalf("DiscoverProvider() first call failed: %v", err)
	}
	if diff := cmp.Diff(issuer+"/token-v1", got1.TokenEndpoint); diff != "" {
		t.Fatalf("TokenEndpoint mismatch (-want +got):\n%s", diff)
	}

	cacheKey := providerCachePrefix + issuer
	entry, ok := c.discoveryCache.Get(cacheKey)
	if !ok || entry == nil {
		t.Fatalf("expected cache entry")
	}

	// Force a deterministic conditional refresh and assert 304 path.
	_, err = c.refreshDiscovery(context.Background(), issuer, cacheKey, entry, c.providerRefreshOpts())
	if err != nil {
		t.Fatalf("refreshDiscovery() failed: %v", err)
	}

	s.mu.Lock()
	ifNone := s.lastIfNone
	callsAfter304 := s.calls
	s.mu.Unlock()
	if diff := cmp.Diff(`"v1"`, ifNone); diff != "" {
		t.Fatalf("If-None-Match mismatch (-want +got):\n%s", diff)
	}

	// Make entry stale, rotate server response, then assert stale-while-revalidate behavior.
	s.mu.Lock()
	s.etag = `"v2"`
	s.body = providerResponse(issuer, issuer+"/token-v2")
	s.mu.Unlock()

	time.Sleep(1200 * time.Millisecond)

	gotStale, err := c.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		t.Fatalf("DiscoverProvider() stale call failed: %v", err)
	}
	if diff := cmp.Diff(issuer+"/token-v1", gotStale.TokenEndpoint); diff != "" {
		t.Fatalf("stale TokenEndpoint mismatch (-want +got):\n%s", diff)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, callErr := c.DiscoverProvider(context.Background(), issuer)
		if callErr == nil && got.TokenEndpoint == issuer+"/token-v2" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	gotFresh, err := c.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		t.Fatalf("DiscoverProvider() final call failed: %v", err)
	}
	if diff := cmp.Diff(issuer+"/token-v2", gotFresh.TokenEndpoint); diff != "" {
		t.Fatalf("fresh TokenEndpoint mismatch (-want +got):\n%s", diff)
	}

	s.mu.Lock()
	callsFinal := s.calls
	s.mu.Unlock()
	if callsFinal <= callsAfter304 {
		t.Fatalf("expected additional calls after stale refresh: before=%d after=%d", callsAfter304, callsFinal)
	}
}

func providerResponse(issuer, tokenEndpoint string) string {
	authorizationEndpoint := issuer + "/authorize"
	jwksURI := issuer + "/jwks"

	return fmt.Sprintf(`{
  "issuer": %q,
  "authorization_endpoint": %q,
  "jwks_uri": %q,
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint": %q
}`,
		issuer,
		authorizationEndpoint,
		jwksURI,
		tokenEndpoint,
	)
}

func TestDiscoverProviderConformanceFreshDiscovery(t *testing.T) {
	issuer := ""
	var calls int
	currentTokenEndpoint := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write([]byte(providerResponse(issuer, currentTokenEndpoint)))
	}))
	defer ts.Close()

	issuer = ts.URL
	currentTokenEndpoint = issuer + "/token-v1"

	client := NewClient(
		WithHTTPClient(ts.Client()),
		WithConformanceFreshDiscovery(true),
	)

	gotFirst, err := client.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		t.Fatalf("DiscoverProvider() first call failed: %v", err)
	}
	if diff := cmp.Diff(issuer+"/token-v1", gotFirst.TokenEndpoint); diff != "" {
		t.Fatalf("first token endpoint mismatch (-want +got):\n%s", diff)
	}

	currentTokenEndpoint = issuer + "/token-v2"

	gotSecond, err := client.DiscoverProvider(context.Background(), issuer)
	if err != nil {
		t.Fatalf("DiscoverProvider() second call failed: %v", err)
	}
	if diff := cmp.Diff(issuer+"/token-v2", gotSecond.TokenEndpoint); diff != "" {
		t.Fatalf("second token endpoint mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(2, calls); diff != "" {
		t.Fatalf("discovery call count mismatch (-want +got):\n%s", diff)
	}
}
