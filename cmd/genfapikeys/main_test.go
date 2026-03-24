package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateClientMTLSCert_SetsNonEmptySubjectAndIssuer(t *testing.T) {
	dir := t.TempDir()

	if err := generateClientMTLSCert(dir); err != nil {
		t.Fatalf("generateClientMTLSCert() failed: %v", err)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "client-mtls.pem"))
	if err != nil {
		t.Fatalf("ReadFile(client-mtls.pem) failed: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("pem.Decode() returned nil block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() failed: %v", err)
	}

	if got := cert.Subject.String(); got == "" {
		t.Fatal("certificate subject is empty")
	}

	if got := cert.Issuer.String(); got == "" {
		t.Fatal("certificate issuer is empty")
	}
}
