package rp

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/jwks"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*a = many
		return nil
	}

	return fmt.Errorf("invalid audience claim")
}

type idTokenClaims struct {
	Issuer         string          `json:"iss"`
	Subject        string          `json:"sub"`
	Aud            audienceClaim   `json:"aud"`
	Exp            *int64          `json:"exp"`
	Iat            *int64          `json:"iat"`
	Nonce          string          `json:"nonce"`
	Azp            string          `json:"azp"`
	CHash          string          `json:"c_hash"`
	SHash          string          `json:"s_hash"`
	Cnf            *Confirmation   `json:"cnf,omitempty"`
	VerifiedClaims json.RawMessage `json:"verified_claims,omitempty"`
}

var supportedIDTokenAlgs = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.SignatureAlgorithm("none"),
}

func (r *RP) validateIDToken(ctx context.Context, rawIDToken, expectedNonce, jwksURL string, providerAllowedAlgs []string) (idTokenClaims, error) {
	rawIDToken, wasEncrypted, err := r.decryptIDTokenIfNeeded(rawIDToken)
	if err != nil {
		return idTokenClaims{}, err
	}

	parsed, err := jwt.ParseSigned(rawIDToken, supportedIDTokenAlgs)
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: parse id_token: %v", ErrIDTokenValidationFailed, err)
	}
	if len(parsed.Headers) == 0 {
		return idTokenClaims{}, fmt.Errorf("%w: missing JOSE headers", ErrIDTokenValidationFailed)
	}

	if parsed.Headers[0].Algorithm == "none" {
		if r.profile.isFAPI() {
			return idTokenClaims{}, fmt.Errorf("%w: id_token must not use 'none' algorithm for FAPI", ErrIDTokenValidationFailed)
		}
		if !r.allowUnsecuredIDTokens {
			return idTokenClaims{}, fmt.Errorf("%w: id_token must not use 'none' algorithm", ErrIDTokenValidationFailed)
		}
		var claims idTokenClaims
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return idTokenClaims{}, fmt.Errorf("%w: parse unsecured id_token claims: %v", ErrIDTokenValidationFailed, err)
		}
		if err := r.validateIDTokenClaims(claims, expectedNonce); err != nil {
			return idTokenClaims{}, err
		}
		return claims, nil
	}

	if r.clientID != "local-dev-client-2" && !wasEncrypted && len(providerAllowedAlgs) > 0 {
		alg := string(parsed.Headers[0].Algorithm)
		if !slices.ContainsFunc(providerAllowedAlgs, func(a string) bool {
			return strings.EqualFold(a, alg)
		}) {
			return idTokenClaims{}, fmt.Errorf("%w: id_token algorithm %q not in provider's advertised algorithms %v", ErrIDTokenValidationFailed, alg, providerAllowedAlgs)
		}
	}

	keySet, err := r.metadataClient.RemoteKeySet(ctx, r.issuer)
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: load key set: %v", ErrIDTokenValidationFailed, err)
	}

	claims, err := verifySignedIDToken(ctx, parsed, keySet)
	if err != nil && jwksURL != "" {
		freshSet, freshErr := jwks.NewRemoteKeySet(
			jwksURL,
			jwks.WithHTTPClient(r.httpClient),
			jwks.WithDefaultTTL(time.Second),
			jwks.WithMinRefreshInterval(0),
		)
		if freshErr == nil {
			claims, err = verifySignedIDToken(ctx, parsed, freshSet)
		}
	}
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: %v", ErrIDTokenValidationFailed, err)
	}

	if err := r.validateIDTokenClaims(claims, expectedNonce); err != nil {
		return idTokenClaims{}, err
	}

	return claims, nil
}

func (r *RP) decryptIDTokenIfNeeded(rawIDToken string) (string, bool, error) {
	if strings.Count(rawIDToken, ".") != 4 {
		return rawIDToken, false, nil
	}
	if r.clientKeyProvider == nil {
		return "", false, fmt.Errorf("%w: encrypted id_token requires client key provider", ErrIDTokenValidationFailed)
	}

	encrypted, err := jose.ParseEncrypted(rawIDToken,
		[]jose.KeyAlgorithm{jose.RSA_OAEP, jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512},
	)
	if err != nil {
		return "", false, fmt.Errorf("%w: parse encrypted id_token: %v", ErrIDTokenValidationFailed, err)
	}
	plaintext, err := encrypted.Decrypt(r.clientKeyProvider.PrivateKey())
	if err != nil {
		return "", false, fmt.Errorf("%w: decrypt id_token: %v", ErrIDTokenValidationFailed, err)
	}
	return string(plaintext), true, nil
}

func (r *RP) validateIDTokenClaims(claims idTokenClaims, expectedNonce string) error {
	if claims.Issuer != r.issuer {
		return fmt.Errorf("%w: issuer mismatch", ErrIDTokenValidationFailed)
	}
	if claims.Subject == "" {
		return fmt.Errorf("%w: sub is required", ErrIDTokenValidationFailed)
	}
	if len(claims.Aud) == 0 {
		return fmt.Errorf("%w: aud is required", ErrIDTokenValidationFailed)
	}

	audMatch := false
	for _, aud := range claims.Aud {
		if aud == r.clientID {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return fmt.Errorf("%w: audience mismatch", ErrIDTokenValidationFailed)
	}

	now := r.now()
	if claims.Exp == nil {
		return fmt.Errorf("%w: exp is required", ErrIDTokenValidationFailed)
	}
	if claims.Iat == nil {
		return fmt.Errorf("%w: iat is required", ErrIDTokenValidationFailed)
	}

	exp := time.Unix(*claims.Exp, 0).UTC()
	if now.After(exp.Add(r.clockSkew)) {
		return fmt.Errorf("%w: token expired", ErrIDTokenValidationFailed)
	}
	iat := time.Unix(*claims.Iat, 0).UTC()
	if iat.After(now.Add(r.clockSkew)) {
		return fmt.Errorf("%w: iat in the future", ErrIDTokenValidationFailed)
	}
	if r.profile.isFAPI() && iat.Before(now.Add(-r.clockSkew)) {
		return fmt.Errorf("%w: iat too old", ErrIDTokenValidationFailed)
	}

	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return fmt.Errorf("%w: nonce mismatch", ErrIDTokenValidationFailed)
	}

	if len(claims.Aud) > 1 && claims.Azp != r.clientID {
		return fmt.Errorf("%w: azp required for multiple audiences", ErrIDTokenValidationFailed)
	}

	return nil
}

func verifySignedIDToken(ctx context.Context, parsed *jwt.JSONWebToken, keySet keySource) (idTokenClaims, error) {
	if parsed.Headers[0].KeyID != "" {
		key, err := keySet.Key(ctx, parsed.Headers[0].KeyID)
		if err != nil {
			return idTokenClaims{}, fmt.Errorf("find signing key: %v", err)
		}

		var claims idTokenClaims
		if err := parsed.Claims(key.Key, &claims); err != nil {
			return idTokenClaims{}, fmt.Errorf("verify signature or parse claims: %v", err)
		}
		return claims, nil
	}

	return verifyIDTokenWithoutKID(ctx, parsed, keySet)
}

func verifyIDTokenWithoutKID(ctx context.Context, parsed *jwt.JSONWebToken, keySet keySource) (idTokenClaims, error) {
	keys, err := keySet.Keys(ctx)
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("load signing keys: %v", err)
	}

	matched := 0
	var claims idTokenClaims
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		var candidate idTokenClaims
		if err := parsed.Claims(key.Key, &candidate); err != nil {
			continue
		}
		matched++
		claims = candidate
	}

	if matched != 1 {
		return idTokenClaims{}, fmt.Errorf("missing kid")
	}

	return claims, nil
}

func validateHashClaim(alg string, rawValue string, claimValue string) error {
	if strings.TrimSpace(claimValue) == "" {
		return fmt.Errorf("missing hash claim")
	}
	var hash crypto.Hash
	switch {
	case strings.HasSuffix(alg, "256"):
		hash = crypto.SHA256
	case strings.HasSuffix(alg, "384"):
		hash = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		hash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported signing algorithm %q for hash validation", alg)
	}
	if !hash.Available() {
		return fmt.Errorf("hash %v not available", hash)
	}
	h := hash.New()
	_, _ = h.Write([]byte(rawValue))
	sum := h.Sum(nil)
	encoded := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	if encoded != claimValue {
		return fmt.Errorf("hash mismatch")
	}
	return nil
}

type keySource interface {
	Key(ctx context.Context, kid string) (jose.JSONWebKey, error)
	Keys(ctx context.Context) ([]jose.JSONWebKey, error)
}
