package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	certsDir := flag.String("certs-dir", "", "Directory to write key files")
	flag.Parse()

	if *certsDir == "" {
		fmt.Fprintln(os.Stderr, "-certs-dir is required")
		os.Exit(1)
	}

	if err := generateServerJWKS(*certsDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate server JWKS: %v\n", err)
		os.Exit(1)
	}

	if err := generateClientJWKS(*certsDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate client JWKS: %v\n", err)
		os.Exit(1)
	}

	if err := generateClientMTLSCert(*certsDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate client mTLS cert: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generated FAPI2 key material in", *certsDir)
}

func generateServerJWKS(dir string) error {
	path := filepath.Join(dir, "server.jwks.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA: %w", err)
	}

	jwks := map[string]any{
		"keys": []map[string]any{
			rsaToJWK(rsaKey, "server-signing-rsa"),
		},
	}

	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return os.WriteFile(path, data, 0o600)
}

func generateClientJWKS(dir string) error {
	path := filepath.Join(dir, "client.jwks.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA: %w", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate EC: %w", err)
	}

	jwks := map[string]any{
		"keys": []map[string]any{
			rsaToJWK(rsaKey, "client-signing-rsa"),
			ecToJWK(ecKey, "client-dpop-ec"),
		},
	}

	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return os.WriteFile(path, data, 0o600)
}

func generateClientMTLSCert(dir string) error {
	certPath := filepath.Join(dir, "client-mtls.pem")
	keyPath := filepath.Join(dir, "client-mtls-key.pem")
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Subject: pkix.Name{
			CommonName:   "client-mtls.localhost",
			Organization: []string{"Lanyard Conformance"},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"client-mtls.localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certPEM := encodePEM(certDER, "CERTIFICATE")
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := encodePEM(keyBytes, "EC PRIVATE KEY")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

func rsaToJWK(key *rsa.PrivateKey, kid string) map[string]any {
	key.Precompute()
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "PS256",
		"n":   base64URLEncode(key.PublicKey.N.Bytes()),
		"e":   base64URLEncode(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		"d":   base64URLEncode(key.D.Bytes()),
		"p":   base64URLEncode(key.Primes[0].Bytes()),
		"q":   base64URLEncode(key.Primes[1].Bytes()),
		"dp":  base64URLEncode(key.Precomputed.Dp.Bytes()),
		"dq":  base64URLEncode(key.Precomputed.Dq.Bytes()),
		"qi":  base64URLEncode(key.Precomputed.Qinv.Bytes()),
	}
}

func ecToJWK(key *ecdsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "EC",
		"kid": kid,
		"use": "sig",
		"alg": "ES256",
		"crv": "P-256",
		"x":   base64URLEncode(key.PublicKey.X.Bytes()),
		"y":   base64URLEncode(key.PublicKey.Y.Bytes()),
		"d":   base64URLEncode(key.D.Bytes()),
	}
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func encodePEM(data []byte, blockType string) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)

	var result []byte
	const lineLen = 64
	for i := 0; i < len(encoded); i += lineLen {
		end := i + lineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		result = append(result, encoded[i:end]...)
		result = append(result, '\n')
	}

	return []byte("-----BEGIN " + blockType + "-----\n" +
		string(result) +
		"-----END " + blockType + "-----\n")
}
