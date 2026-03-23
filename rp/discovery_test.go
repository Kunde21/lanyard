package rp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDiscoverProvider(t *testing.T) {
	issuer := ""
	discoveryCalls := 0

	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		discoveryCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
	}))
	defer ts.Close()
	issuer = ts.URL

	got, err := DiscoverProvider(context.Background(), issuer, WithDiscoveryHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("DiscoverProvider() failed: %v", err)
	}

	if diff := cmp.Diff(issuer, got.Issuer); diff != "" {
		t.Fatalf("issuer mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, discoveryCalls); diff != "" {
		t.Fatalf("discovery call count mismatch (-want +got):\n%s", diff)
	}
}

func TestDiscoverProviderWithWebFingerAndPreloadJWKS(t *testing.T) {
	issuer := ""
	webFingerCalls := 0
	discoveryCalls := 0
	jwksCalls := 0

	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/webfinger":
			webFingerCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"subject":"acct:alice@%s","links":[{"rel":"http://openid.net/specs/connect/1.0/issuer","href":%q}]}`,
				strings.TrimPrefix(ts.URL, "https://"), issuer,
			)
		case "/.well-known/openid-configuration":
			discoveryCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(providerMetadataJSONWithEndpoints(issuer)))
		case "/jwks":
			jwksCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	issuer = ts.URL

	resource := "acct:alice@" + strings.TrimPrefix(ts.URL, "https://")
	got, err := DiscoverProvider(
		context.Background(),
		"",
		WithDiscoveryHTTPClient(ts.Client()),
		WithDiscoveryWebFingerResource(resource),
		WithDiscoveryPreloadJWKS(true),
	)
	if err != nil {
		t.Fatalf("DiscoverProvider() failed: %v", err)
	}

	if diff := cmp.Diff(issuer, got.Issuer); diff != "" {
		t.Fatalf("issuer mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, webFingerCalls); diff != "" {
		t.Fatalf("webfinger call count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, discoveryCalls); diff != "" {
		t.Fatalf("discovery call count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(1, jwksCalls); diff != "" {
		t.Fatalf("jwks call count mismatch (-want +got):\n%s", diff)
	}
}
