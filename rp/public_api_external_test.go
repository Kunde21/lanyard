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

	var extra struct {
		Custom string `json:"custom"`
	}
	_ = resp.DecodeRaw(&extra)

	_ = rp.ErrIntrospectionFailed
	_ = rp.TokenTypeHintAccessToken
	_ = rp.TokenTypeHintRefreshToken
	_ = (*rp.Introspector)(nil)
	_ = rp.ErrRefreshTokenRejected
	var oauthErr rp.OAuthError
	_ = oauthErr.Code
	var rotSrc *rp.RefreshTokenSource
	_, _ = rp.NewRefreshTokenSource(nil, "rt")
	_ = rotSrc

	// Grant management surface.
	_ = rp.GrantActionCreate
	_ = rp.GrantActionMerge
	_ = rp.GrantActionUpdate
	_ = rp.GrantActionReplace
	_ = rp.SetGrantManagementAction(rp.GrantActionMerge, "grant-id")
	_ = rp.SetGrantID("grant-id")
	_, _ = rp.NewGrantManager(nil, "https://issuer.example.com")
	_ = rp.ErrGrantManagementFailed
	_ = rp.ErrInvalidGrantID
	_ = rp.ErrAuthorizationFailed
	var grantStatus rp.GrantStatus
	_ = grantStatus.Scopes
	_ = grantStatus.Claims
	_ = grantStatus.AuthorizationDetails
	_ = grantStatus.UpdatedBy
	_ = grantStatus.DecodeRaw(&struct{}{})
	var grantScope rp.GrantScope
	_ = grantScope.Resource
	var rpInst *rp.RP
	query := rpInst.QueryGrant
	revoke := rpInst.RevokeGrant
	_ = query
	_ = revoke

	// Dynamic client registration surface.
	_ = rp.ErrRegistrationFailed
	_, _ = rp.NewRegistrar(nil, "https://issuer.example.com")
	var regOpt rp.Option = rp.WithInitialAccessToken("token")
	_ = regOpt
	var reg rp.ClientRegistration
	manageable := reg.Manageable
	secretExpired := reg.SecretExpired
	opts := reg.Options
	_, _, _ = manageable, secretExpired, opts
	_ = rp.ClientMetadata{}
	_ = rp.ClientUpdate{}

	// Claims parameter + identity assurance surface.
	_ = rp.WithClaims("{}")
	_ = rp.SetClaims("{}")
	cr := rp.NewClaimsRequest()
	_ = cr.AddVerifiedClaimsToIDToken
	_ = cr.AddVerifiedClaimsToUserInfo
	_, _ = cr.JSON()
	_ = rp.ClaimsRequest{}
	_ = rp.VerifiedClaimsFilter{}
	_ = rp.VerificationFilter{}
	_ = rp.EvidenceFilter{}
	_ = rp.CheckDetailsFilter{}
	_ = rp.Constrainable{}
	_ = rp.ClaimConstraint{}
	var verified rp.VerifiedClaims
	_ = verified.DecodeRaw
	var verification rp.Verification
	freshFor := verification.FreshFor
	_ = freshFor
	var parsed []rp.VerifiedClaims
	parseFn := rp.ParseVerifiedClaims
	_ = parseFn
	_ = parsed
	_ = rp.SetGrantManagementAction(rp.GrantActionMerge, "grant-id")
	var cbResult rp.CallbackResult
	_ = cbResult.GrantID
	var tokenValue rp.Token
	_ = tokenValue.GrantID

	var opt rp.Option
	opt = rp.WithIntrospectionDecryptionKey(nil) // compiles; nil rejected at construction
	_ = opt
	_ = resp.Cnf
}
