// Package rp implements OpenID Connect relying party flows.
//
// The package is organized around two main caller stories.
//
// For browser-based sign-in, construct an [RP] with [New], redirect users to
// [RP.AuthorizationURL], then finish the authorization code flow with
// [RP.HandleCallback].
//
// For service-to-service access, construct [ClientCredentials] with
// [NewClientCredentials] and request a shared [Token] value with
// [ClientCredentials.Token].
//
// State store implementations for the browser flow are available under the
// rp/store packages, including rp/store/memory and rp/store/cookie.
package rp
