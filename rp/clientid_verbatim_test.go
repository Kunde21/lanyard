package rp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/rp/store/memory"
)

// TestWithClientIDPreservesVerbatimValue: RFC 7591 registration endpoints may
// issue client identifiers containing leading/trailing whitespace. The
// conformance suite's dynamic-client plan deliberately issues such
// identifiers, and a silent TrimSpace corrupted them so the authorization
// request carried a different client_id than the one registered.
func TestWithClientIDPreservesVerbatimValue(t *testing.T) {
	var c clientConfig
	WithClientID(" client id with edges ").applyConfig(&c)
	if c.clientID != " client id with edges " {
		t.Fatalf("clientID = %q, want verbatim value preserved", c.clientID)
	}
}

// TestAuthorizationURLCarriesVerbatimClientID: the authorization request
// URL-encodes the exact client_id, whitespace included.
func TestAuthorizationURLCarriesVerbatimClientID(t *testing.T) {
	issuer := ""
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(providerMetadataJSON(issuer)))
	}))
	defer ts.Close()
	issuer = ts.URL

	r, err := New(
		context.Background(),
		issuer,
		WithClientID("client-123 )`_^ "), WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(ts.Client()),
		WithStateStore(memory.New(10*time.Minute)),
		withRandReader(strings.NewReader(strings.Repeat("a", 256))),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	rec := httptest.NewRecorder()
	raw, err := r.AuthorizationURL(rec, req)
	if err != nil {
		t.Fatalf("AuthorizationURL() failed: %v", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthorizationURL() produced unparseable URL: %v", err)
	}
	if got := parsed.Query().Get("client_id"); got != "client-123 )`_^ " {
		t.Fatalf("client_id query param = %q, want verbatim registered identifier", got)
	}
}
