package rp

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	return buildDPoPProof(r.clientKeyProvider, r.randReader, r.now, method, rawURL, accessToken, nonce)
}

func buildDPoPProof(keyProvider ClientKeyProvider, randReader io.Reader, now func() time.Time, method, rawURL, accessToken, nonce string) (string, error) {
	if keyProvider == nil {
		return "", fmt.Errorf("client key provider is required for DPoP")
	}
	if randReader == nil {
		randReader = crand.Reader
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	privateKey := keyProvider.PrivateKey()
	if privateKey == nil {
		return "", fmt.Errorf("private key is required for DPoP")
	}

	alg := keyProvider.SigningAlgorithm()
	joseAlg := signatureAlgorithm(alg)
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
		JTI:   generateJTI(randReader),
		HTM:   method,
		HTU:   normalizeDPoPHTU(rawURL),
		IAT:   now().Unix(),
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

func (r *RP) attachDPoPProof(req *http.Request, accessToken, nonce string) error {
	proof, err := r.generateDPoPProof(req.Method, req.URL.String(), accessToken, nonce)
	if err != nil {
		return err
	}
	req.Header.Set("DPoP", proof)
	return nil
}

// AttachDPoPProof adds a DPoP proof to req.
func (r *RP) AttachDPoPProof(req *http.Request, accessToken, nonce string) error {
	return r.attachDPoPProof(req, accessToken, nonce)
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
	if strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		return true
	}
	if resp.Header.Get("DPoP-Nonce") != "" {
		return true
	}
	return false
}

func isDPoPSupported(method AuthMethod) bool {
	return method == AuthMethodPrivateKeyJWT || method == AuthMethodTLSClientAuth
}

func (r *RP) cachedDPoPNonce(rawURL string) string {
	if r.dpopNonces == nil {
		return ""
	}
	nonce, _ := r.dpopNonces.get(normalizeDPoPHTU(rawURL))
	return nonce
}

func (r *RP) storeDPoPNonce(rawURL, nonce string) {
	if r.dpopNonces == nil || nonce == "" {
		return
	}
	r.dpopNonces.put(normalizeDPoPHTU(rawURL), nonce)
}

func (r *RP) extractAndStoreDPoPNonce(resp *http.Response, rawURL string) {
	nonce, ok := extractDPoPNonce(resp)
	if ok {
		r.storeDPoPNonce(rawURL, nonce)
	}
}

// DPoPNonceForEndpoint returns the cached DPoP nonce for the given endpoint, if any.
func (r *RP) DPoPNonceForEndpoint(endpoint string) (string, bool) {
	if r.dpopNonces == nil {
		return "", false
	}
	return r.dpopNonces.get(normalizeDPoPHTU(endpoint))
}

// StoreDPoPNonce stores a DPoP nonce for the given endpoint.
func (r *RP) StoreDPoPNonce(endpoint, nonce string) {
	r.storeDPoPNonce(endpoint, nonce)
}

// SenderConstraint selects the sender-constraining mode for outbound requests.
type SenderConstraint string

const (
	// SenderConstraintNone disables sender-constraining.
	SenderConstraintNone SenderConstraint = ""
	// SenderConstraintDPoP enables DPoP (Demonstration of Proof-of-Possession).
	SenderConstraintDPoP SenderConstraint = "dpop"
	// SenderConstraintMTLS enables mTLS sender-constraining.
	SenderConstraintMTLS SenderConstraint = "mtls"
)

func normalizeSenderConstrain(raw string) SenderConstraint {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(SenderConstraintDPoP):
		return SenderConstraintDPoP
	case string(SenderConstraintMTLS):
		return SenderConstraintMTLS
	default:
		return SenderConstraintNone
	}
}

func (r *RP) shouldUseDPoP() bool {
	return r.senderConstrain == SenderConstraintDPoP &&
		r.clientKeyProvider != nil &&
		isDPoPSupported(r.resolvedAuthMethod)
}

// ShouldUseDPoP reports whether the RP is configured to use DPoP.
func (r *RP) ShouldUseDPoP() bool {
	return r.shouldUseDPoP()
}

type dpopRequestConfig struct {
	buildRequest   func() (*http.Request, error)
	attachDPoP     func(req *http.Request, nonce string) error
	handleResponse func(body io.Reader) error
	storeNonce     func(resp *http.Response)
	successStatus  int
	httpClient     *http.Client
	useDPoP        bool
	cachedNonce    string
}

func doRequestWithDPoPRetry(cfg dpopRequestConfig) (*http.Response, int, string, error) {
	req, err := cfg.buildRequest()
	if err != nil {
		return nil, 0, "", err
	}

	if cfg.useDPoP {
		if err := cfg.attachDPoP(req, cfg.cachedNonce); err != nil {
			return nil, 0, "", fmt.Errorf("failed to generate DPoP proof: %w", err)
		}
	}

	resp, status, preview, err := doJSONStatus(req, cfg.httpClient, cfg.successStatus, cfg.handleResponse)
	if err != nil {
		return resp, status, preview, err
	}

	if cfg.useDPoP && resp != nil {
		cfg.storeNonce(resp)
	}

	if cfg.useDPoP && isUseDPoPNonce(resp) {
		nonce, ok := extractDPoPNonce(resp)
		if ok {
			retryReq, retryErr := cfg.buildRequest()
			if retryErr != nil {
				return nil, 0, "", retryErr
			}
			if err := cfg.attachDPoP(retryReq, nonce); err != nil {
				return nil, 0, "", fmt.Errorf("failed to generate DPoP proof: %w", err)
			}

			resp, status, preview, err = doJSONStatus(retryReq, cfg.httpClient, cfg.successStatus, cfg.handleResponse)
			if err != nil {
				return resp, status, preview, err
			}
			if resp != nil {
				cfg.storeNonce(resp)
			}
		}
	}

	return resp, status, preview, nil
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
