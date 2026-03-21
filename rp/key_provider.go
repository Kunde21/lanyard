package rp

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// ClientKeyProvider provides cryptographic keys and certificates for client authentication.
type ClientKeyProvider interface {
	// PrivateKey returns the private key for signing JWT assertions (private_key_jwt).
	// The returned key must implement crypto.PrivateKey.
	PrivateKey() crypto.PrivateKey

	// KeyID returns the key ID (kid) to use in JWT headers.
	KeyID() string

	// SigningAlgorithm returns the JWS algorithm to use for signing (e.g., "PS256", "RS256", "ES256").
	SigningAlgorithm() string

	// TLSCertificate returns the TLS certificate for mTLS client authentication.
	// Return nil if mTLS is not configured.
	TLSCertificate() *tls.Certificate
}

type staticClientKeyProvider struct {
	privateKey       crypto.PrivateKey
	keyID            string
	signingAlgorithm string
	tlsCert          *tls.Certificate
}

func NewStaticClientKeyProvider(privateKey crypto.PrivateKey, keyID, signingAlgorithm string, tlsCert *tls.Certificate) ClientKeyProvider {
	return &staticClientKeyProvider{
		privateKey:       privateKey,
		keyID:            keyID,
		signingAlgorithm: signingAlgorithm,
		tlsCert:          tlsCert,
	}
}

func (s *staticClientKeyProvider) PrivateKey() crypto.PrivateKey {
	return s.privateKey
}

func (s *staticClientKeyProvider) KeyID() string {
	return s.keyID
}

func (s *staticClientKeyProvider) SigningAlgorithm() string {
	return s.signingAlgorithm
}

func (s *staticClientKeyProvider) TLSCertificate() *tls.Certificate {
	return s.tlsCert
}

func parseJWK(data json.RawMessage) (crypto.PrivateKey, string, string, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		D   string `json:"d"`
		N   string `json:"n"`
		E   string `json:"e"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Crv string `json:"crv"`
		P   string `json:"p"`
		Q   string `json:"q"`
	}

	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, "", "", fmt.Errorf("failed to parse JWK: %w", err)
	}

	alg := jwk.Alg
	if alg == "" {
		switch jwk.Kty {
		case "RSA":
			alg = "PS256"
		case "EC":
			if jwk.Crv == "P-256" {
				alg = "ES256"
			}
		}
	}

	switch jwk.Kty {
	case "RSA":
		if jwk.D == "" || jwk.P == "" || jwk.Q == "" {
			return nil, jwk.Kid, alg, fmt.Errorf("RSA private key requires d, p, q fields")
		}
		d, err := base64URLDecodeBigInt(jwk.D)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode RSA private exponent: %w", err)
		}
		p, err := base64URLDecodeBigInt(jwk.P)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode RSA prime p: %w", err)
		}
		q, err := base64URLDecodeBigInt(jwk.Q)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode RSA prime q: %w", err)
		}

		key := &rsaPrivateKey{}
		key.D = d
		key.Primes = []*big.Int{p, q}
		key.N = new(big.Int).Mul(p, q)
		key.E = 65537

		return key, jwk.Kid, alg, nil

	case "EC":
		if jwk.D == "" {
			return nil, jwk.Kid, alg, fmt.Errorf("EC private key requires d field")
		}
		d, err := base64URLDecodeBigInt(jwk.D)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode EC private key: %w", err)
		}
		x, err := base64URLDecodeBigInt(jwk.X)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode EC X: %w", err)
		}
		y, err := base64URLDecodeBigInt(jwk.Y)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to decode EC Y: %w", err)
		}

		key := &ecPrivateKey{}
		key.D = d
		key.X = x
		key.Y = y

		return key, jwk.Kid, alg, nil
	}

	return nil, jwk.Kid, alg, nil
}

func base64URLDecodeBigInt(s string) (*big.Int, error) {
	decoder := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(s))
	data, err := io.ReadAll(decoder)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

type rsaPrivateKey struct {
	D      *big.Int
	Primes []*big.Int
	N      *big.Int
	E      int
}

func (r *rsaPrivateKey) Public() crypto.PublicKey {
	return &rsaPublicKey{N: r.N, E: r.E}
}

type rsaPublicKey struct {
	N *big.Int
	E int
}

type ecPrivateKey struct {
	D *big.Int
	X *big.Int
	Y *big.Int
}

func (e *ecPrivateKey) Public() crypto.PublicKey {
	return &ecPublicKey{X: e.X, Y: e.Y}
}

type ecPublicKey struct {
	X *big.Int
	Y *big.Int
}
