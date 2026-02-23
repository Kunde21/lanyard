package rp

import (
	"context"
	"encoding/json"
	"fmt"
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
	Issuer  string        `json:"iss"`
	Subject string        `json:"sub"`
	Aud     audienceClaim `json:"aud"`
	Exp     *int64        `json:"exp"`
	Iat     *int64        `json:"iat"`
	Nonce   string        `json:"nonce"`
	Azp     string        `json:"azp"`
}

func (r *RP) validateIDToken(ctx context.Context, rawIDToken, expectedNonce, jwksURL string) (idTokenClaims, error) {
	parsed, err := jwt.ParseSigned(rawIDToken, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: parse id_token: %v", ErrIDTokenValidationFailed, err)
	}
	if len(parsed.Headers) == 0 {
		return idTokenClaims{}, fmt.Errorf("%w: missing JOSE headers", ErrIDTokenValidationFailed)
	}

	keySet, err := r.oidcClient.RemoteKeySet(ctx, r.issuer)
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

type keySource interface {
	Key(ctx context.Context, kid string) (jose.JSONWebKey, error)
	Keys(ctx context.Context) ([]jose.JSONWebKey, error)
}
