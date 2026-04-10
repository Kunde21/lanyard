package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Kunde21/lanyard/rp"
)

var (
	conformanceKeyOnce    sync.Once
	cachedConformanceKeys conformanceKeySet
	conformanceKeyErr     error
)

type conformanceKeySet struct {
	rsaPrivateKey *rsa.PrivateKey
	rsaKeyID      string
	rsaAlg        string
	mtlsCert      *tls.Certificate
	mtlsKeyID     string
	mtlsAlg       string
}

func loadConformanceKeySet() (conformanceKeySet, error) {
	conformanceKeyOnce.Do(func() {
		cachedConformanceKeys, conformanceKeyErr = readConformanceKeySet()
	})
	return cachedConformanceKeys, conformanceKeyErr
}

func readConformanceKeySet() (conformanceKeySet, error) {
	certsDir := strings.TrimSpace(os.Getenv("RP_CONFORMANCE_CERTS_DIR"))
	if certsDir == "" {
		certsDir = "conformance/certs"
	}
	resolvedCertsDir, err := resolveConformanceCertsDir(certsDir)
	if err != nil {
		return conformanceKeySet{}, err
	}

	jwksData, err := os.ReadFile(filepath.Join(resolvedCertsDir, "client.jwks.json"))
	if err != nil {
		return conformanceKeySet{}, fmt.Errorf("read client jwks: %w", err)
	}
	rsaKey, rsaKeyID, rsaAlg, err := loadRSAKeyFromJWKS(jwksData)
	if err != nil {
		return conformanceKeySet{}, err
	}

	certData, err := os.ReadFile(filepath.Join(resolvedCertsDir, "client-mtls.pem"))
	if err != nil {
		return conformanceKeySet{}, fmt.Errorf("read mtls cert: %w", err)
	}
	keyData, err := os.ReadFile(filepath.Join(resolvedCertsDir, "client-mtls-key.pem"))
	if err != nil {
		return conformanceKeySet{}, fmt.Errorf("read mtls key: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return conformanceKeySet{}, fmt.Errorf("load mtls key pair: %w", err)
	}

	return conformanceKeySet{
		rsaPrivateKey: rsaKey,
		rsaKeyID:      rsaKeyID,
		rsaAlg:        rsaAlg,
		mtlsCert:      &tlsCert,
		mtlsKeyID:     "client-mtls",
		mtlsAlg:       "ES256",
	}, nil
}

func resolveConformanceCertsDir(certsDir string) (string, error) {
	trimmed := strings.TrimSpace(certsDir)
	if trimmed == "" {
		return "", fmt.Errorf("conformance certs dir is required")
	}
	if filepath.IsAbs(trimmed) {
		if _, err := os.Stat(trimmed); err != nil {
			return "", fmt.Errorf("stat conformance certs dir: %w", err)
		}
		return trimmed, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	current := wd
	for {
		candidate := filepath.Join(current, trimmed)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return "", fmt.Errorf("locate conformance certs dir %q from %q", trimmed, wd)
}

func loadClientKeyProvider(authType, senderConstrain string) (rp.ClientKeyProvider, error) {
	trimmedAuthType := strings.ToLower(strings.TrimSpace(authType))
	trimmedSenderConstrain := strings.ToLower(strings.TrimSpace(senderConstrain))

	needsSigningKey := false
	needsTLSCert := false

	switch trimmedAuthType {
	case "private_key_jwt":
		needsSigningKey = true
		needsTLSCert = trimmedSenderConstrain == "mtls"
	case "mtls", "tls_client_auth", "self_signed_tls_client_auth":
		needsSigningKey = true
		needsTLSCert = true
	}

	if !needsSigningKey && !needsTLSCert {
		return nil, nil
	}

	keys, err := loadConformanceKeySet()
	if err != nil {
		return nil, err
	}

	var mtlsCert *tls.Certificate
	if needsTLSCert {
		mtlsCert = keys.mtlsCert
	}

	return rp.NewStaticClientKeyProvider(keys.rsaPrivateKey, keys.rsaKeyID, keys.rsaAlg, mtlsCert), nil
}

func loadRequestObjectKeyProvider(authType, senderConstrain, requestType string) (rp.ClientKeyProvider, error) {
	if !requestTypeNeedsAsymmetricSigningKey(requestType) {
		return loadClientKeyProvider(authType, senderConstrain)
	}

	keys, err := loadConformanceKeySet()
	if err != nil {
		return nil, err
	}

	var mtlsCert *tls.Certificate
	switch strings.ToLower(strings.TrimSpace(authType)) {
	case "private_key_jwt":
		if strings.EqualFold(strings.TrimSpace(senderConstrain), "mtls") {
			mtlsCert = keys.mtlsCert
		}
	case "mtls", "tls_client_auth", "self_signed_tls_client_auth":
		mtlsCert = keys.mtlsCert
	}

	return rp.NewStaticClientKeyProvider(keys.rsaPrivateKey, keys.rsaKeyID, keys.rsaAlg, mtlsCert), nil
}

func conformancePublicJWKS() (map[string]any, error) {
	keys, err := loadConformanceKeySet()
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": keys.rsaKeyID,
			"alg": keys.rsaAlg,
			"n":   base64.RawURLEncoding.EncodeToString(keys.rsaPrivateKey.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(keys.rsaPrivateKey.PublicKey.E)).Bytes()),
		}},
	}, nil
}

func requestTypeNeedsAsymmetricSigningKey(requestType string) bool {
	switch strings.ToLower(strings.TrimSpace(requestType)) {
	case "request_object", "request_uri":
		return true
	default:
		return false
	}
}

func loadRSAKeyFromJWKS(data []byte) (*rsa.PrivateKey, string, string, error) {
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			D   string `json:"d"`
			P   string `json:"p"`
			Q   string `json:"q"`
			DP  string `json:"dp"`
			DQ  string `json:"dq"`
			QI  string `json:"qi"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, "", "", fmt.Errorf("parse jwks: %w", err)
	}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.D == "" {
			continue
		}
		rsaKey, err := rsaPrivateKeyFromJWK(key.N, key.E, key.D, key.P, key.Q, key.DP, key.DQ, key.QI)
		if err != nil {
			return nil, "", "", err
		}
		alg := key.Alg
		if alg == "" {
			alg = "PS256"
		}
		return rsaKey, key.Kid, alg, nil
	}
	return nil, "", "", fmt.Errorf("no RSA signing key found in jwks")
}

func rsaPrivateKeyFromJWK(n, e, d, p, q, dp, dq, qi string) (*rsa.PrivateKey, error) {
	modulus, err := decodeBase64URLInt(n)
	if err != nil {
		return nil, fmt.Errorf("decode jwk modulus: %w", err)
	}
	exponent, err := decodeBase64URLInt(e)
	if err != nil {
		return nil, fmt.Errorf("decode jwk exponent: %w", err)
	}
	privateExponent, err := decodeBase64URLInt(d)
	if err != nil {
		return nil, fmt.Errorf("decode jwk private exponent: %w", err)
	}
	pPrime, err := decodeBase64URLInt(p)
	if err != nil {
		return nil, fmt.Errorf("decode jwk prime p: %w", err)
	}
	qPrime, err := decodeBase64URLInt(q)
	if err != nil {
		return nil, fmt.Errorf("decode jwk prime q: %w", err)
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: modulus, E: int(exponent.Int64())},
		D:         privateExponent,
		Primes:    []*big.Int{pPrime, qPrime},
	}
	if dp != "" && dq != "" && qi != "" {
		dpInt, err := decodeBase64URLInt(dp)
		if err != nil {
			return nil, fmt.Errorf("decode jwk dp: %w", err)
		}
		dqInt, err := decodeBase64URLInt(dq)
		if err != nil {
			return nil, fmt.Errorf("decode jwk dq: %w", err)
		}
		qiInt, err := decodeBase64URLInt(qi)
		if err != nil {
			return nil, fmt.Errorf("decode jwk qi: %w", err)
		}
		key.Precomputed.Dp = dpInt
		key.Precomputed.Dq = dqInt
		key.Precomputed.Qinv = qiInt
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("validate rsa key: %w", err)
	}
	key.Precompute()
	return key, nil
}

func decodeBase64URLInt(raw string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

func parsePrivateKeyPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode pem block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func ecdsaPrivateKeyFromPEM(data []byte) (*ecdsa.PrivateKey, error) {
	key, err := parsePrivateKeyPEM(data)
	if err != nil {
		return nil, err
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key type %T is not ECDSA", key)
	}
	if ecdsaKey.Curve == nil {
		ecdsaKey.Curve = elliptic.P256()
	}
	return ecdsaKey, nil
}
