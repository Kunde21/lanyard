// Package rp implements OpenID Connect relying party flows.
//
// The package is organized around three main caller stories.
//
// # Browser-based sign-in
//
// Construct an [RP] with [New], redirect users to [RP.AuthorizationURL], then
// finish the authorization code flow with [RP.HandleCallback]. A default
// in-memory state store is created when neither [WithStateStore] nor
// [WithCorrelationStore] is provided.
//
// Use [WithProfile] to select a behavior profile (such as [OIDC], [OAuth2],
// [FAPI1Adv], [FAPI2SecurityProfile], [FAPI2MessageSigning], or [PlainFAPI]).
// Profile defaults fill fields that the caller has not already set.
//
// # Client credentials
//
// For service-to-service access, construct [ClientCredentials] with
// [NewClientCredentials] and request a shared [Token] with
// [ClientCredentials.Token].
//
// # Token introspection
//
// Token introspection is available through [NewIntrospector] for resource-server
// style use and through [RP.IntrospectToken] for existing RP instances. JSON
// responses from RFC 7662 are supported, and signed JWT responses from RFC 9701
// are verified when requested. Signed-then-encrypted (nested JWT) RFC 9701
// responses are decrypted when a key is configured via
// [WithIntrospectionDecryptionKey].
//
// # Token refresh
//
// When the authorization code flow returns a refresh token, use
// [RP.RefreshToken] to exchange it for a fresh [Token] without user
// interaction. The method respects the same auth method and DPoP
// configuration as the original flow.
//
// Authorization servers following RFC 9700 rotate the refresh token on every
// use; once rotated, the previous token is invalid. Track rotation with
// [NewRefreshTokenSource], which serializes refreshes so concurrent callers
// never replay a rotated-out token. When the server rejects a token
// (invalid_grant), refresh errors wrap [ErrRefreshTokenRejected]; discard the
// token and restart the authorization flow.
//
// # Resource indicators
//
// Use [WithResources] or [SetResources] to send OAuth 2.0 Resource Indicators
// (RFC 8707) as repeated resource parameters. Use [WithTokenResources] to
// override resources for refresh-token and client-credentials token requests.
//
// # Sender-constrained tokens (RFC 7800)
//
// Sender-constrained access tokens (DPoP, RFC 9449; mTLS, RFC 8705) bind a
// token to a proof-of-possession key via the RFC 7800 cnf (confirmation)
// claim. [Confirmation] parses all cnf members; [Confirmation.VerifyDPoPBinding]
// and [Confirmation.VerifyMTLSBinding] verify a token's binding against the
// RP's own key material. [RP.DPoPKeyThumbprint] returns the JWK thumbprint an
// authorization server places in cnf.jkt for DPoP-bound tokens issued to this
// RP. [ParseAccessTokenConfirmation] decodes cnf from a JWT access token
// obtained over a trusted channel (without signature verification; see its
// godoc for the security caveat).
//
// # Provider discovery
//
// For configuration validation or provider inspection before construction, use
// [DiscoverProvider].
//
// # Options
//
// [New] and [NewClientCredentials] both accept [Option] values for shared
// client configuration such as [WithClientID], [WithClientSecret],
// [WithMetadataClient], [WithScopes], [WithProviderMetadata], and
// [WithSenderConstrain]. Browser-flow-only options such as [WithRedirectURI],
// [WithStateStore], [WithProfile], and [WithRequirePAR] also satisfy
// [AuthCodeOption] and are rejected by [NewClientCredentials].
//
// State store implementations for the browser flow are available under the
// rp/store packages, including rp/store/memory and rp/store/cookie.
package rp
