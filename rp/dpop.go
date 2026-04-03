package rp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type dpopProof struct {
	Header    dpopHeader
	Payload   dpopPayload
	Signature string
}

type dpopHeader struct {
	Typ string  `json:"typ"`
	Alg string  `json:"alg"`
	Kid string  `json:"kid"`
	JWK dpopJWK `json:"jwk"`
}

type dpopJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type dpopPayload struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func (r *RP) generateDPoPProof(method, rawURL, accessToken, nonce string) (string, error) {
	if r.clientKeyProvider == nil {
		return "", fmt.Errorf("client key provider is required for DPoP")
	}

	privateKey := r.clientKeyProvider.PrivateKey()
	if privateKey == nil {
		return "", fmt.Errorf("private key is required for DPoP")
	}

	alg := r.clientKeyProvider.SigningAlgorithm()
	joseAlg := algToJose(alg)
	if joseAlg == "" {
		return "", fmt.Errorf("unsupported algorithm for DPoP: %s", alg)
	}

	var jwk map[string]any
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		jwk = rsaJWK(key)
	case *ecdsa.PrivateKey:
		jwk = ecdsaJWK(key)
	default:
		return "", fmt.Errorf("unsupported key type for DPoP: %T", privateKey)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: joseAlg, Key: privateKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"typ": "dpop+jwt",
			"jwk": jwk,
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	payload := dpopPayload{
		JTI:   generateJTI(r.randReader),
		HTM:   method,
		HTU:   normalizeDPoPHTU(rawURL),
		IAT:   r.now().Unix(),
		Nonce: nonce,
	}
	if accessToken != "" {
		payload.ATH = dpopAccessTokenHash(accessToken)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DPoP payload: %w", err)
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return "", fmt.Errorf("failed to sign DPoP proof: %w", err)
	}
	return sig.CompactSerialize()
}

func algToJose(alg string) jose.SignatureAlgorithm {
	switch alg {
	case "PS256":
		return jose.PS256
	case "PS384":
		return jose.PS384
	case "PS512":
		return jose.PS512
	case "RS256":
		return jose.RS256
	case "RS384":
		return jose.RS384
	case "RS512":
		return jose.RS512
	case "ES256":
		return jose.ES256
	case "ES384":
		return jose.ES384
	case "ES512":
		return jose.ES512
	default:
		return ""
	}
}

func rsaJWK(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
}

func ecdsaJWK(key *ecdsa.PrivateKey) map[string]any {
	curve := key.Curve.Params().Name
	crv := "P-256"
	if curve == "P-384" {
		crv = "P-384"
	} else if curve == "P-521" {
		crv = "P-521"
	}

	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}
}

func normalizeDPoPHTU(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawQuery = ""
	return u.String()
}

func dpopAccessTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func extractDPoPNonce(resp *http.Response) (string, bool) {
	nonce := resp.Header.Get("DPoP-Nonce")
	if nonce == "" {
		return "", false
	}
	return nonce, true
}

func isUseDPoPNonce(resp *http.Response) bool {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	return strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`)
}

func isDPoPSupported(method AuthMethod) bool {
	return method == AuthMethodPrivateKeyJWT || method == AuthMethodTLSClientAuth
}

type senderConstrainType string

const (
	SenderConstrainNone senderConstrainType = ""
	SenderConstrainDPoP senderConstrainType = "dpop"
	SenderConstrainMTLS senderConstrainType = "mtls"
)

func normalizeSenderConstrain(raw string) senderConstrainType {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(SenderConstrainDPoP):
		return SenderConstrainDPoP
	case string(SenderConstrainMTLS):
		return SenderConstrainMTLS
	default:
		return SenderConstrainNone
	}
}

func (r *RP) shouldUseDPoP() bool {
	if r.senderConstrain != SenderConstrainNone {
		return r.senderConstrain == SenderConstrainDPoP && r.clientKeyProvider != nil && isDPoPSupported(r.resolvedAuthMethod)
	}
	return r.clientKeyProvider != nil && isDPoPSupported(r.resolvedAuthMethod)
}

func validateDPoPProof(proof, method, url, expectedAth string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid DPoP proof format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode DPoP header: %w", err)
	}

	var header dpopHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse DPoP header: %w", err)
	}

	if header.Typ != "dpop+jwt" {
		return fmt.Errorf("invalid DPoP proof type: %s", header.Typ)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode DPoP payload: %w", err)
	}

	var payload dpopPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("failed to parse DPoP payload: %w", err)
	}

	if payload.HTM != method {
		return fmt.Errorf("DPoP proof method mismatch: expected %s, got %s", method, payload.HTM)
	}

	if payload.HTU != url {
		return fmt.Errorf("DPoP proof URL mismatch: expected %s, got %s", url, payload.HTU)
	}

	if expectedAth != "" && payload.ATH != expectedAth {
		return fmt.Errorf("DPoP proof token hash mismatch: expected %s, got %s", expectedAth, payload.ATH)
	}

	now := time.Now().Unix()
	if payload.IAT < now-60 || payload.IAT > now+60 {
		return fmt.Errorf("DPoP proof timestamp out of range")
	}

	return nil
}
