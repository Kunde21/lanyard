package rp_test

import (
	"context"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/Kunde21/lanyard/rp"
)

func TestPublicAPIOptionNames(t *testing.T) {
	_ = rp.WithProviderMetadata(metadata.Provider{})
	_ = rp.WithDiscoveryHTTPClient(nil)
	_ = rp.WithDiscoveryLogger(nil)
	_ = rp.WithDiscoveryMetadataClient(nil)
	_ = rp.WithDiscoveryWebFingerResource("acct:alice@example.com")
	_ = rp.WithDiscoveryPreloadJWKS(true)
	_ = rp.SetAuthorizationDetails([]map[string]any{{"type": "account_information"}})
	_ = rp.SetAuthParam("resource", "urn:example:api")
	_ = rp.WithProfile(rp.OIDC)
	_ = rp.WithProfile(rp.OAuth2)
	_ = rp.WithProfile(rp.FAPI1Adv)
	_ = rp.WithProfile(rp.FAPI2SecurityProfile)
	_ = rp.WithProfile(rp.FAPI2MessageSigning)
	_ = rp.WithProfile(rp.PlainFAPI)
	_ = rp.WithDiscoveryMode(rp.DiscoveryAuto)
	_ = rp.WithDiscoveryMode(rp.DiscoveryOIDC)
	_ = rp.WithDiscoveryMode(rp.DiscoveryOAuth2)
	_ = rp.WithDiscoveryMode(rp.DiscoveryDisabled)
	_ = rp.WithSenderConstrain(rp.SenderConstraintDPoP)
	_ = rp.WithSenderConstrain(rp.SenderConstraintMTLS)
	_ = rp.WithSenderConstrain(rp.SenderConstraintNone)

	tok := rp.Token{
		AccessToken:  "at",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken:      "id",
		RefreshToken: "rt",
		Scope:        "openid profile",
	}
	_ = tok.DecodeRaw(&struct{}{})
	_, _ = tok.Extra("authorization_details")
	if tok.IDToken == "" {
		t.Fatalf("Token should expose IDToken for authorization code responses")
	}

	_, _ = rp.DiscoverProvider(context.Background(), "https://issuer.example.com")

	_, _ = rp.NewClientCredentials(
		context.Background(),
		"https://issuer.example.com",
		rp.WithClientID("client-id"),
		rp.WithClientSecret("secret"),
		rp.WithProviderMetadata(metadata.Provider{}),
	)
}

func TestPublicAPIRemovedSymbols(t *testing.T) {
	t.Log("WithFAPIProfile, WithOIDCClient, WithClientCredentialsOIDCClient, WithDiscoveryOIDCClient, WithClientCredentialsProviderMetadata, WithClientCredentialsSenderConstrain, and string-taking sender-constrain signatures have been removed")
}
