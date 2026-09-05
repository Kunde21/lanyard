package rp

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"go.opentelemetry.io/otel/attribute"
)

type requestObjectClaims struct {
	Iss                   string            `json:"iss"`
	Aud                   string            `json:"aud"`
	ClientID              string            `json:"client_id"`
	ResponseType          string            `json:"response_type"`
	RedirectURI           string            `json:"redirect_uri"`
	Scope                 string            `json:"scope"`
	State                 string            `json:"state"`
	Nonce                 string            `json:"nonce,omitempty"`
	CodeChallenge         string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod   string            `json:"code_challenge_method,omitempty"`
	AuthorizationDetails  json.RawMessage   `json:"authorization_details,omitempty"`
	Resource              []string          `json:"resource,omitempty"`
	Claims                json.RawMessage   `json:"claims,omitempty"`
	GrantID               string            `json:"grant_id,omitempty"`
	GrantManagementAction string            `json:"grant_management_action,omitempty"`
	ResponseMode          string            `json:"response_mode,omitempty"`
	IssuedAt              int64             `json:"iat"`
	NotBefore             int64             `json:"nbf"`
	Expiration            int64             `json:"exp"`
	JTI                   string            `json:"jti"`
	Extra                 map[string]string `json:"-"`
}

func (r *RP) buildSignedRequestObject(state, nonce, challenge, authorizationDetails string, resources []string, grant *grantManagementRequest, claimsParam string, extra url.Values) (string, error) {
	_, span := r.spanStart(context.Background(), "rp.signed_request_object",
		attribute.Bool("lanyard.asymmetric", r.clientKeyProvider != nil),
	)
	defer span.End()

	signed, err := r.buildSignedRequestObjectInner(state, nonce, challenge, authorizationDetails, resources, grant, claimsParam, extra)
	spanError(span, err)
	return signed, err
}

func (r *RP) buildSignedRequestObjectInner(state, nonce, challenge, authorizationDetails string, resources []string, grant *grantManagementRequest, claimsParam string, extra url.Values) (string, error) {
	now := r.now()
	parsedAuthorizationDetails, err := parseAuthorizationDetailsClaim(authorizationDetails)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization_details for request object: %w", err)
	}

	claims := requestObjectClaims{
		Iss:                   r.clientID,
		Aud:                   r.issuer,
		ClientID:              r.clientID,
		ResponseType:          r.authorizationResponseType(),
		RedirectURI:           r.redirectURI,
		Scope:                 strings.Join(r.scopes, " "),
		State:                 state,
		CodeChallenge:         challenge,
		CodeChallengeMethod:   "S256",
		AuthorizationDetails:  parsedAuthorizationDetails,
		Resource:              append([]string(nil), resources...),
		GrantID:               grant.grantIDValue(),
		GrantManagementAction: grant.actionValue(),
		Claims:                json.RawMessage(claimsParam),
		IssuedAt:              now.Unix(),
		NotBefore:             now.Unix(),
		Expiration:            now.Add(5 * time.Minute).Unix(),
		JTI:                   generateJTI(r.randReader),
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

	if r.clientKeyProvider != nil {
		return signRequestObjectClaims(r.clientKeyProvider, claims)
	}
	return signRequestObjectWithSecret(r.clientSecret, claims)
}

func isStandardRequestObjectClaim(key string) bool {
	switch strings.ToLower(key) {
	case "iss", "aud", "client_id", "response_type", "redirect_uri",
		"scope", "state", "nonce", "code_challenge", "code_challenge_method",
		"authorization_details", "response_mode", "resource", "grant_id",
		"grant_management_action", "claims", "iat", "nbf", "exp", "jti":
		return true
	}
	return false
}

func signRequestObjectClaims(keyProvider ClientKeyProvider, claims requestObjectClaims) (string, error) {
	alg := signatureAlgorithm(keyProvider.SigningAlgorithm())
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

func signRequestObjectWithSecret(secret string, claims requestObjectClaims) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("%w: client secret or key provider required for signed request object", ErrInvalidConfiguration)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, &jose.SignerOptions{})
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
	if len(claims.AuthorizationDetails) > 0 {
		var authorizationDetails any
		if err := json.Unmarshal(claims.AuthorizationDetails, &authorizationDetails); err == nil {
			m["authorization_details"] = authorizationDetails
		}
	}
	if claims.ResponseMode != "" {
		m["response_mode"] = claims.ResponseMode
	}
	if claims.GrantID != "" {
		m["grant_id"] = claims.GrantID
	}
	if claims.GrantManagementAction != "" {
		m["grant_management_action"] = claims.GrantManagementAction
	}
	if len(claims.Resource) > 0 {
		m["resource"] = claims.Resource
	}
	if len(claims.Claims) > 0 && string(claims.Claims) != "null" {
		var parsed map[string]any
		if err := json.Unmarshal(claims.Claims, &parsed); err == nil {
			m["claims"] = parsed
		}
	}
	for k, v := range claims.Extra {
		m[k] = v
	}
	return m
}

func parseAuthorizationDetailsClaim(raw string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, err
	}

	canonical, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}

	return json.RawMessage(canonical), nil
}

var _ crypto.PrivateKey = (*rsaPrivateKey)(nil)
