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
	_ = rp.AuthMethodSelfSignedTLSClientAuth
	_ = rp.ErrRefreshTokenFailed

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

func TestPublicAPIOptionTypeAssignments(t *testing.T) {
	var opt rp.Option
	opt = rp.WithClientID("client-id")
	opt = rp.WithClientSecret("secret")
	opt = rp.WithScopes("read")
	opt = rp.WithProviderMetadata(metadata.Provider{})
	opt = rp.WithRedirectURI("https://rp.example.com/callback")
	opt = rp.WithProfile(rp.OIDC)
	_ = opt

	var authOpt rp.AuthCodeOption
	authOpt = rp.WithRedirectURI("https://rp.example.com/callback")
	authOpt = rp.WithProfile(rp.OIDC)
	authOpt = rp.WithRequirePAR(true)
	_ = authOpt
}

func TestPublicAPIRemovedSymbols(t *testing.T) {
	t.Log("WithFAPIProfile, WithOIDCClient, WithClientCredentialsOIDCClient, WithDiscoveryOIDCClient, WithClientCredentialsProviderMetadata, WithClientCredentialsSenderConstrain, and string-taking sender-constrain signatures have been removed")
}

func TestIntrospectionPublicAPI(t *testing.T) {
	var req rp.IntrospectionRequest
	req.Token = "token"
	req.TokenTypeHint = rp.TokenTypeHintAccessToken
	req.PreferJWTResponse = true
	req.ExpectedJWTAudience = "https://rs.example.com"

	var resp rp.IntrospectionResponse
	_ = resp.Active
	_ = resp.Scope
	_ = resp.ClientID
	_ = resp.Username
	_ = resp.TokenType
	_ = resp.Exp
	_ = resp.Iat
	_ = resp.Nbf
	_ = resp.Sub
	_ = resp.Aud
	_ = resp.Iss
	_ = resp.JTI
	_ = resp.RawJWT()

	var extra struct{ Custom string `json:"custom"` }
	_ = resp.DecodeRaw(&extra)

	_ = rp.ErrIntrospectionFailed
	_ = rp.TokenTypeHintAccessToken
	_ = rp.TokenTypeHintRefreshToken
	_ = (*rp.Introspector)(nil)
}
