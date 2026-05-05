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
// # Token refresh
//
// When the authorization code flow returns a refresh token, use
// [RP.RefreshToken] to exchange it for a fresh [Token] without user
// interaction. The method respects the same auth method and DPoP
// configuration as the original flow.
//
// # Resource indicators
//
// Use [WithResources] or [SetResources] to send OAuth 2.0 Resource Indicators
// (RFC 8707) as repeated resource parameters. Use [WithTokenResources] to
// override resources for refresh-token and client-credentials token requests.
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
