// Package httputil contains HTTP helpers used by discovery and JWKS clients.
//
// [FetchJSON] applies JSON request headers, handles conditional responses,
// captures bounded error-body previews, and delegates successful response
// decoding to the caller. [CalculateFreshUntil] centralizes Cache-Control and
// Expires handling with a caller-provided fallback TTL.
//
// Most applications should use the higher-level [metadata], [jwks], or [rp]
// packages instead of this package directly.
package httputil
