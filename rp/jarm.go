package rp

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

type jarmClaims struct {
	Iss              string        `json:"iss"`
	Aud              audienceClaim `json:"aud"`
	Exp              *int64        `json:"exp"`
	Iat              *int64        `json:"iat"`
	Code             string        `json:"code"`
	State            string        `json:"state"`
	Error            string        `json:"error"`
	ErrorDescription string        `json:"error_description"`
}

func (r *RP) parseJARMResponse(ctx context.Context, rawJARM string) (jarmClaims, error) {
	if rawJARM == "" {
		return jarmClaims{}, fmt.Errorf("%w: empty JARM response", ErrInvalidState)
	}

	supportedAlgs := []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512,
	}

	parsed, err := josejwt.ParseSigned(rawJARM, supportedAlgs)
	if err != nil {
		return jarmClaims{}, fmt.Errorf("%w: failed to parse JARM response: %v", ErrInvalidState, err)
	}
	if len(parsed.Headers) == 0 {
		return jarmClaims{}, fmt.Errorf("%w: JARM response missing JOSE headers", ErrInvalidState)
	}

	alg := parsed.Headers[0].Algorithm
	if alg == "none" {
		return jarmClaims{}, fmt.Errorf("%w: JARM response must not use 'none' algorithm", ErrInvalidState)
	}

	allowedAlgs := r.provider.AuthorizationSigningAlgValuesSupported
	if len(allowedAlgs) > 0 {
		if !slices.ContainsFunc(allowedAlgs, func(a string) bool {
			return strings.EqualFold(a, string(alg))
		}) {
			return jarmClaims{}, fmt.Errorf("%w: JARM algorithm %q not in provider's supported algorithms %v", ErrInvalidState, alg, allowedAlgs)
		}
	}

	jwksURI := r.provider.JWKSURI
	if jwksURI == "" {
		return jarmClaims{}, fmt.Errorf("%w: provider metadata missing jwks_uri for JARM verification", ErrInvalidState)
	}

	keySet, err := r.oidcClient.RemoteKeySetFromJWKSURI(jwksURI)
	if err != nil {
		return jarmClaims{}, fmt.Errorf("%w: failed to load JWKS for JARM verification: %v", ErrInvalidState, err)
	}

	var claims jarmClaims
	if parsed.Headers[0].KeyID != "" {
		key, err := keySet.Key(ctx, parsed.Headers[0].KeyID)
		if err != nil {
			return jarmClaims{}, fmt.Errorf("%w: failed to find JARM signing key: %v", ErrInvalidState, err)
		}
		if err := parsed.Claims(key.Key, &claims); err != nil {
			return jarmClaims{}, fmt.Errorf("%w: JARM signature verification failed: %v", ErrInvalidState, err)
		}
	} else {
		keys, err := keySet.Keys(ctx)
		if err != nil {
			return jarmClaims{}, fmt.Errorf("%w: failed to load JARM signing keys: %v", ErrInvalidState, err)
		}

		matched := 0
		for _, key := range keys {
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			var candidate jarmClaims
			if err := parsed.Claims(key.Key, &candidate); err != nil {
				continue
			}
			matched++
			claims = candidate
		}
		if matched != 1 {
			return jarmClaims{}, fmt.Errorf("%w: JARM verification requires exactly one matching key, got %d", ErrInvalidState, matched)
		}
	}

	if err := r.validateJARMClaims(claims); err != nil {
		return jarmClaims{}, err
	}

	return claims, nil
}

func (r *RP) validateJARMClaims(claims jarmClaims) error {
	if claims.Iss == "" {
		return fmt.Errorf("%w: JARM response missing iss", ErrInvalidState)
	}
	if len(claims.Aud) == 0 {
		return fmt.Errorf("%w: JARM response missing aud", ErrInvalidState)
	}

	audMatch := false
	for _, aud := range claims.Aud {
		if aud == r.clientID {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return fmt.Errorf("%w: JARM audience mismatch", ErrInvalidState)
	}

	now := r.now()
	if claims.Exp == nil {
		return fmt.Errorf("%w: JARM response missing exp", ErrInvalidState)
	}

	exp := time.Unix(*claims.Exp, 0).UTC()
	if now.After(exp.Add(r.clockSkew)) {
		return fmt.Errorf("%w: JARM response expired", ErrInvalidState)
	}
	if claims.Iat != nil {
		iat := time.Unix(*claims.Iat, 0).UTC()
		if iat.After(now.Add(r.clockSkew)) {
			return fmt.Errorf("%w: JARM response iat in the future", ErrInvalidState)
		}
	}

	return nil
}

func (r *RP) isJARMResponse(params callbackParams) bool {
	return strings.TrimSpace(params.Response) != ""
}
