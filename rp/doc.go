// Package rp implements OpenID Connect relying party flows.
//
// The package is organized around three main caller stories.
//
// # Browser-based sign-in
//
// Construct an [RP] with [New], redirect users to [RP.AuthorizationURL], then
// finish the authorization code flow with [RP.HandleCallback]. A default
// in-memory state store is created when [WithStateStore] is not provided.
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
// # Provider discovery
//
// For configuration validation or provider inspection before construction, use
// [DiscoverProvider].
//
// # Options
//
// Key option families:
//   - [WithMetadataClient] injects a [metadata.Client] for discovery and JWKS.
//   - [WithProfile] selects the RP behavior profile.
//   - [WithSenderConstrain] enables DPoP or mTLS sender constraining.
//   - [WithProviderMetadata] supplies partial or full provider metadata.
//
// State store implementations for the browser flow are available under the
// rp/store packages, including rp/store/memory and rp/store/cookie.
package rp
