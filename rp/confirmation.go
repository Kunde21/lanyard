package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Confirmation represents the RFC 7800 "cnf" (confirmation) claim, which binds
// a JWT to a proof-of-possession key. At most one binding member is expected
// (RFC 7800 §3.1); the two that matter for sender-constrained tokens are:
//
//   - JKT (RFC 7638 JWK Thumbprint) — used by DPoP (RFC 9449).
//   - X5T256 (x5t#S256, X.509 SHA-256 certificate thumbprint) — used by mTLS (RFC 8705).
//
// Other members (jwk, x5c, x5u, x5t, kid, jwe) are parsed for completeness but
// not enforced by VerifyDPoPBinding / VerifyMTLSBinding.
type Confirmation struct {
	JWK    json.RawMessage `json:"jwk,omitempty"`
	JKT    string          `json:"jkt,omitempty"`
	X5T256 string          `json:"x5t#S256,omitempty"`
	X5C    []string        `json:"x5c,omitempty"`
	X5U    string          `json:"x5u,omitempty"`
	X5T    string          `json:"x5t,omitempty"`
	Kid    string          `json:"kid,omitempty"`
	JWE    string          `json:"jwe,omitempty"`
}

// IsBound reports whether the confirmation carries a recognized binding member
// (jkt or x5t#S256).
func (c Confirmation) IsBound() bool {
	return c.JKT != "" || c.X5T256 != ""
}

// VerifyDPoPBinding reports whether c binds the token to the public key
// derived from priv (DPoP). Returns ErrTokenUnbound if no jkt member is
// present, or an error wrapping ErrTokenBindingMismatch on mismatch.
func (c Confirmation) VerifyDPoPBinding(priv crypto.PrivateKey) error {
	if c.JKT == "" {
		return ErrTokenUnbound
	}
	got, err := JWKThumbprint(priv)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenBindingMismatch, err)
	}
	if subtle.ConstantTimeCompare([]byte(c.JKT), []byte(got)) != 1 {
		return fmt.Errorf("%w: jkt mismatch", ErrTokenBindingMismatch)
	}
	return nil
}

// VerifyMTLSBinding reports whether c binds the token to cert's leaf
// certificate (mTLS x5t#S256). Returns ErrTokenUnbound if no x5t#S256 member
// is present, or an error wrapping ErrTokenBindingMismatch on mismatch.
func (c Confirmation) VerifyMTLSBinding(cert *x509.Certificate) error {
	if c.X5T256 == "" {
		return ErrTokenUnbound
	}
	got := X509CertThumbprint(cert)
	if subtle.ConstantTimeCompare([]byte(c.X5T256), []byte(got)) != 1 {
		return fmt.Errorf("%w: x5t#S256 mismatch", ErrTokenBindingMismatch)
	}
	return nil
}

// JWKThumbprint returns the base64url-encoded RFC 7638 SHA-256 JWK Thumbprint
// of the public key derived from priv. Supports *rsa.PrivateKey and
// *ecdsa.PrivateKey (the same types accepted by DPoP proof generation).
// Unsupported key types return an error.
func JWKThumbprint(priv crypto.PrivateKey) (string, error) {
	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return "", fmt.Errorf("unsupported key type %T", priv)
	}
	jwk := jose.JSONWebKey{Key: pub}
	digest, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(digest), nil
}

// X509CertThumbprint returns the base64url-encoded SHA-256 thumbprint of the
// DER encoding of cert's leaf — the value carried in the RFC 7800 cnf claim
// member "x5t#S256" for mTLS-bound tokens (RFC 8705 §3). Returns "" for nil.
func X509CertThumbprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
