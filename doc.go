// Package lanyard is an OpenID Connect and OAuth 2.0 relying party library.
//
// Most applications should start with the [rp] package, which implements
// browser-based sign-in, callback handling, token refresh, client credentials,
// token exchange, DPoP, mTLS sender-constrained tokens, PAR, JAR, and JARM.
//
// Use [metadata] directly for provider discovery, OAuth 2.0 authorization
// server metadata, WebFinger issuer resolution, or remote JWKS construction
// without building a relying party. Use [jwks] directly when a JWKS URI is
// already known. The [cache] package provides the default generic in-memory
// cache used by metadata and JWKS clients.
//
// The lower-level [validateurl] and [httputil] packages are exported for
// callers that need the same URL validation and HTTP JSON-fetch behavior used
// internally by discovery and key retrieval.
package lanyard
