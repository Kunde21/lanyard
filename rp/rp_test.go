package rp

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/google/go-cmp/cmp"
)

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		clientID    string
		redirectURI string
	}{
		{name: "missing issuer", issuer: "", clientID: "client", redirectURI: "https://rp.test/callback"},
		{name: "invalid issuer", issuer: "http://issuer.test", clientID: "client", redirectURI: "https://rp.test/callback"},
		{name: "missing client id", issuer: "https://issuer.test", clientID: "", redirectURI: "https://rp.test/callback"},
		{name: "missing redirect uri", issuer: "https://issuer.test", clientID: "client", redirectURI: ""},
		{name: "invalid redirect uri", issuer: "https://issuer.test", clientID: "client", redirectURI: "http://rp.test/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.issuer, tt.clientID, "secret", tt.redirectURI)
			if err == nil {
				t.Fatalf("New() expected error")
			}
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() error mismatch: got %v", err)
			}
		})
	}
}

func TestNew_DefaultsAndOptions(t *testing.T) {
	customHTTPClient := &http.Client{}
	customLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	customOIDCClient := oidc.NewClient()

	got, err := New(
		"https://issuer.test",
		"client",
		"secret",
		"https://rp.test/callback",
		WithHTTPClient(customHTTPClient),
		WithLogger(customLogger),
		WithOIDCClient(customOIDCClient),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if diff := cmp.Diff([]string{"openid"}, got.scopes); diff != "" {
		t.Fatalf("scopes mismatch (-want +got):\n%s", diff)
	}
	if got.httpClient != customHTTPClient {
		t.Fatalf("httpClient mismatch")
	}
	if got.logger != customLogger {
		t.Fatalf("logger mismatch")
	}
	if got.oidcClient != customOIDCClient {
		t.Fatalf("oidcClient mismatch")
	}
}
