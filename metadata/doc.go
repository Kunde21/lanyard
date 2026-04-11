// Package metadata provides OIDC provider discovery and OAuth 2.0 authorization
// server metadata retrieval with built-in caching.
//
// The main entry point is [NewClient], which returns a [Client] ready for
// discovery. A Client installs default in-memory caches for both discovery
// metadata and JWKS results; callers can replace these via [WithDiscoveryCache]
// and [WithJWKSCache].
//
// # Discovery
//
// Use [Client.DiscoverProvider] for standard OIDC discovery (OpenID Connect
// Discovery 1.0). Use [Client.DiscoverAuthorizationServer] for OAuth 2.0-only
// authorization server metadata (RFC 8414). Both methods cache results and
// refresh stale entries in the background.
//
// # Remote Key Sets
//
// [Client.RemoteKeySet] discovers provider metadata and returns a
// [*jwks.RemoteKeySet] for token verification. Alternatively, use
// [Client.RemoteKeySetFromJWKSURI] when the JWKS URL is already known.
//
// # When to use this package directly
//
// Most callers should use the higher-level [rp] package, which creates a
// Client automatically. Use this package directly when you need discovery
// without constructing a relying party, or when you need fine-grained control
// over caching or HTTP behavior.
package metadata
