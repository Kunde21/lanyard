package rp

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type requestObjectClaims struct {
	Iss                  string            `json:"iss"`
	Aud                  string            `json:"aud"`
	ClientID             string            `json:"client_id"`
	ResponseType         string            `json:"response_type"`
	RedirectURI          string            `json:"redirect_uri"`
	Scope                string            `json:"scope"`
	State                string            `json:"state"`
	Nonce                string            `json:"nonce,omitempty"`
	CodeChallenge        string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod  string            `json:"code_challenge_method,omitempty"`
	AuthorizationDetails string            `json:"authorization_details,omitempty"`
	ResponseMode         string            `json:"response_mode,omitempty"`
	IssuedAt             int64             `json:"iat"`
	NotBefore            int64             `json:"nbf"`
	Expiration           int64             `json:"exp"`
	JTI                  string            `json:"jti"`
	Extra                map[string]string `json:"-"`
}

func (r *RP) buildSignedRequestObject(state, nonce, challenge, authorizationDetails string, extra url.Values) (string, error) {
	if r.clientKeyProvider == nil {
		return "", fmt.Errorf("%w: client key provider required for signed request object", ErrInvalidConfiguration)
	}

	now := r.now()
	claims := requestObjectClaims{
		Iss:                  r.clientID,
		Aud:                  r.issuer,
		ClientID:             r.clientID,
		ResponseType:         "code",
		RedirectURI:          r.redirectURI,
		Scope:                strings.Join(r.scopes, " "),
		State:                state,
		CodeChallenge:        challenge,
		CodeChallengeMethod:  "S256",
		AuthorizationDetails: authorizationDetails,
		IssuedAt:             now.Unix(),
		NotBefore:            now.Unix(),
		Expiration:           now.Add(5 * time.Minute).Unix(),
		JTI:                  generateJTI(r.randReader),
	}

	if r.usesOpenIDScope() {
		claims.Nonce = nonce
	}

	if strings.TrimSpace(r.responseMode) != "" {
		claims.ResponseMode = r.responseMode
	}

	if extra != nil {
		for key := range extra {
			if isStandardRequestObjectClaim(key) {
				continue
			}
			if claims.Extra == nil {
				claims.Extra = make(map[string]string)
			}
			claims.Extra[key] = extra.Get(key)
		}
	}

	return signRequestObjectClaims(r.clientKeyProvider, claims)
}

func isStandardRequestObjectClaim(key string) bool {
	switch strings.ToLower(key) {
	case "iss", "aud", "client_id", "response_type", "redirect_uri",
		"scope", "state", "nonce", "code_challenge", "code_challenge_method",
		"authorization_details", "response_mode", "iat", "nbf", "exp", "jti":
		return true
	}
	return false
}

func signRequestObjectClaims(keyProvider ClientKeyProvider, claims requestObjectClaims) (string, error) {
	alg := signingAlgorithm(keyProvider.SigningAlgorithm())
	if alg == "" {
		return "", fmt.Errorf("unsupported signing algorithm for request object: %s", keyProvider.SigningAlgorithm())
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: keyProvider.PrivateKey()}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": keyProvider.KeyID(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create request object signer: %w", err)
	}

	claimMap := claimsToMap(claims)

	payload, err := json.Marshal(claimMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request object claims: %w", err)
	}

	sig, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign request object: %w", err)
	}

	return sig.CompactSerialize()
}

func claimsToMap(claims requestObjectClaims) map[string]any {
	m := map[string]any{
		"iss":                   claims.Iss,
		"aud":                   claims.Aud,
		"client_id":             claims.ClientID,
		"response_type":         claims.ResponseType,
		"redirect_uri":          claims.RedirectURI,
		"scope":                 claims.Scope,
		"state":                 claims.State,
		"code_challenge":        claims.CodeChallenge,
		"code_challenge_method": claims.CodeChallengeMethod,
		"iat":                   claims.IssuedAt,
		"nbf":                   claims.NotBefore,
		"exp":                   claims.Expiration,
		"jti":                   claims.JTI,
	}
	if claims.Nonce != "" {
		m["nonce"] = claims.Nonce
	}
	if claims.AuthorizationDetails != "" {
		m["authorization_details"] = claims.AuthorizationDetails
	}
	if claims.ResponseMode != "" {
		m["response_mode"] = claims.ResponseMode
	}
	for k, v := range claims.Extra {
		m[k] = v
	}
	return m
}

func signingAlgorithm(alg string) jose.SignatureAlgorithm {
	switch alg {
	case "PS256":
		return jose.PS256
	case "RS256":
		return jose.RS256
	case "ES256":
		return jose.ES256
	case "PS384":
		return jose.PS384
	case "ES384":
		return jose.ES384
	default:
		return ""
	}
}

var _ crypto.PrivateKey = (*rsaPrivateKey)(nil)
