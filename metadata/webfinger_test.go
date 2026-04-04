package metadata

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestResolveIssuerFromWebFingerAcct(t *testing.T) {
	issuer := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if diff := cmp.Diff("/.well-known/webfinger", r.URL.Path); diff != "" {
			t.Fatalf("webfinger path mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff("acct:alice@"+r.Host, r.URL.Query().Get("resource")); diff != "" {
			t.Fatalf("resource query mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(webFingerIssuerRel, r.URL.Query().Get("rel")); diff != "" {
			t.Fatalf("rel query mismatch (-want +got):\n%s", diff)
		}

		w.Header().Set("Content-Type", "application/jrd+json")
		_, _ = fmt.Fprintf(w, `{"subject":%q,"links":[{"rel":%q,"href":%q}]}`, r.URL.Query().Get("resource"), webFingerIssuerRel, issuer)
	}))
	defer ts.Close()

	issuer = ts.URL + "/issuer"
	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}

	client := NewClient(WithHTTPClient(ts.Client()))
	got, err := client.ResolveIssuerFromWebFinger(context.Background(), "acct:alice@"+parsed.Host)
	if err != nil {
		t.Fatalf("ResolveIssuerFromWebFinger() failed: %v", err)
	}

	if diff := cmp.Diff(issuer, got); diff != "" {
		t.Fatalf("resolved issuer mismatch (-want +got):\n%s", diff)
	}
}

func TestDiscoverProviderFromResource(t *testing.T) {
	issuer := ""
	resource := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/webfinger":
			if diff := cmp.Diff(resource, r.URL.Query().Get("resource")); diff != "" {
				t.Fatalf("resource query mismatch (-want +got):\n%s", diff)
			}
			w.Header().Set("Content-Type", "application/jrd+json")
			_, _ = fmt.Fprintf(w, `{"subject":%q,"links":[{"rel":%q,"href":%q}]}`, resource, webFingerIssuerRel, issuer)
		case "/tenant/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"jwks_uri":%q,"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`,
				issuer,
				issuer+"/authorize",
				issuer+"/jwks",
			)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}
	resource = "https://" + parsed.Host + "/alice"
	issuer = ts.URL + "/tenant"

	client := NewClient(WithHTTPClient(ts.Client()))
	metadata, err := client.DiscoverProviderFromResource(context.Background(), resource)
	if err != nil {
		t.Fatalf("DiscoverProviderFromResource() failed: %v", err)
	}

	if diff := cmp.Diff(issuer, metadata.Issuer); diff != "" {
		t.Fatalf("issuer mismatch (-want +got):\n%s", diff)
	}
}

func TestResolveIssuerFromWebFingerMissingIssuerLink(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jrd+json")
		_, _ = fmt.Fprint(w, `{"subject":"acct:alice@example.test","links":[{"rel":"self","href":"https://example.test/alice"}]}`)
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse() failed: %v", err)
	}

	client := NewClient(WithHTTPClient(ts.Client()))
	_, err = client.ResolveIssuerFromWebFinger(context.Background(), "acct:alice@"+parsed.Host)
	if err == nil {
		t.Fatalf("ResolveIssuerFromWebFinger() expected error")
	}
}
