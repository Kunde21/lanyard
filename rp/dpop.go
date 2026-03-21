package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type DPoPProof struct {
	Header    DPoPHeader
	Payload   DPoPPayload
	Signature string
}

type DPoPHeader struct {
	Typ string  `json:"typ"`
	Alg string  `json:"alg"`
	Kid string  `json:"kid"`
	JWK DPoPJWK `json:"jwk"`
}

type DPoPJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type DPoPPayload struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
}

func (r *RP) generateDPoPProof(method, url, accessToken string) (string, error) {
	if r.clientKeyProvider == nil {
		return "", fmt.Errorf("client key provider is required for DPoP")
	}

	privateKey := r.clientKeyProvider.PrivateKey()
	if privateKey == nil {
		return "", fmt.Errorf("private key is required for DPoP")
	}

	alg := r.clientKeyProvider.SigningAlgorithm()
	kid := r.clientKeyProvider.KeyID()

	var jwk DPoPJWK
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		jwk = rsaToJWK(key)
	case *ecdsa.PrivateKey:
		jwk = ecdsaToJWK(key)
	default:
		return "", fmt.Errorf("unsupported key type for DPoP: %T", privateKey)
	}

	header := DPoPHeader{
		Typ: "dpop+jwt",
		Alg: alg,
		Kid: kid,
		JWK: jwk,
	}

	jti := generateJTI(r.randReader)

	iat := time.Now().Unix()
	payload := DPoPPayload{
		JTI: jti,
		HTM: method,
		HTU: url,
		IAT: iat,
	}

	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		payload.ATH = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DPoP header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DPoP payload: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature, err := signDpop(signingInput, privateKey, alg)
	if err != nil {
		return "", fmt.Errorf("failed to sign DPoP proof: %w", err)
	}

	return signingInput + "." + signature, nil
}

func signDpop(input string, privateKey crypto.PrivateKey, alg string) (string, error) {
	var joseAlg jose.SignatureAlgorithm
	switch alg {
	case "PS256":
		joseAlg = jose.PS256
	case "PS384":
		joseAlg = jose.PS384
	case "PS512":
		joseAlg = jose.PS512
	case "RS256":
		joseAlg = jose.RS256
	case "RS384":
		joseAlg = jose.RS384
	case "RS512":
		joseAlg = jose.RS512
	case "ES256":
		joseAlg = jose.ES256
	case "ES384":
		joseAlg = jose.ES384
	case "ES512":
		joseAlg = jose.ES512
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: joseAlg, Key: privateKey}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return sig.CompactSerialize()
}

func rsaToJWK(key *rsa.PrivateKey) DPoPJWK {
	return DPoPJWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
}

func ecdsaToJWK(key *ecdsa.PrivateKey) DPoPJWK {
	curve := key.Curve.Params().Name
	crv := "P-256"
	if curve == "P-384" {
		crv = "P-384"
	} else if curve == "P-521" {
		crv = "P-521"
	}

	return DPoPJWK{
		Kty: "EC",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
	}
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

func (r *RP) shouldUseDPoP() bool {
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

	var header DPoPHeader
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

	var payload DPoPPayload
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
