package metadata

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestOIDCWellKnownURL(t *testing.T) {
	tt := []struct {
		name   string
		issuer string
		want   string
	}{
		{name: "host only", issuer: "https://example.com", want: "https://example.com/.well-known/openid-configuration"},
		{name: "path", issuer: "https://example.com/tenant", want: "https://example.com/tenant/.well-known/openid-configuration"},
		{name: "trailing slash", issuer: "https://example.com/tenant/", want: "https://example.com/tenant/.well-known/openid-configuration"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OIDCWellKnownURL(tc.issuer)
			if err != nil {
				t.Fatalf("OIDCWellKnownURL() failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("OIDCWellKnownURL() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOAuthASWellKnownURL(t *testing.T) {
	tt := []struct {
		name   string
		issuer string
		want   string
	}{
		{name: "host only", issuer: "https://example.com", want: "https://example.com/.well-known/oauth-authorization-server"},
		{name: "path", issuer: "https://example.com/tenant", want: "https://example.com/.well-known/oauth-authorization-server/tenant"},
		{name: "trailing slash", issuer: "https://example.com/tenant/", want: "https://example.com/.well-known/oauth-authorization-server/tenant"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OAuthASWellKnownURL(tc.issuer)
			if err != nil {
				t.Fatalf("OAuthASWellKnownURL() failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("OAuthASWellKnownURL() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWellKnownInvalidIssuer(t *testing.T) {
	invalid := []string{
		"http://example.com",
		"https://example.com?q=1",
		"https://example.com#frag",
	}

	for _, issuer := range invalid {
		if _, err := OIDCWellKnownURL(issuer); err == nil {
			t.Fatalf("OIDCWellKnownURL(%q) expected error", issuer)
		}
		if _, err := OAuthASWellKnownURL(issuer); err == nil {
			t.Fatalf("OAuthASWellKnownURL(%q) expected error", issuer)
		}
	}
}
