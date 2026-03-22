package rp_test

import (
	"context"
	"testing"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/Kunde21/lanyard/rp"
)

func TestPublicAPIOptionNames(t *testing.T) {
	_ = rp.WithProviderMetadata(oidc.ProviderMetadata{})
	_ = rp.WithClientCredentialsProviderMetadata(oidc.ProviderMetadata{})

	tok := rp.Token{
		AccessToken:  "at",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken:      "id",
		RefreshToken: "rt",
		Scope:        "openid profile",
	}
	if tok.IDToken == "" {
		t.Fatalf("Token should expose IDToken for authorization code responses")
	}

	_, _ = rp.NewClientCredentials(
		context.Background(),
		"https://issuer.example.com",
		"client-id",
		"secret",
		rp.WithClientCredentialsProviderMetadata(oidc.ProviderMetadata{}),
	)
}
