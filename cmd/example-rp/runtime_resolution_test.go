package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

func TestNewRPHTTPClient_LogsRequestAndResponseDumps(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newRPHTTPClient(nil)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ReadAll() failed: %v", err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "rp http request dump") {
		t.Fatal("expected request dump log entry")
	}
	if !strings.Contains(logs, "rp http response dump") {
		t.Fatal("expected response dump log entry")
	}
}

func TestProviderMetadataForResolvedRequest_UsesMTLSAliasesForConformanceOAuthOnly(t *testing.T) {
	resolved := resolvedRPRequest{
		issuer:          "https://suite.localhost/test/a/plain-fapi-10/",
		scopes:          []string{"accounts"},
		senderConstrain: "mtls",
	}

	got, ok := providerMetadataForResolvedRequest(resolved)
	if !ok {
		t.Fatal("providerMetadataForResolvedRequest() = not configured, want configured")
	}

	if diff := cmp.Diff("https://suite.localhost/test/a/plain-fapi-10/authorize", got.AuthorizationEndpoint); diff != "" {
		t.Fatalf("authorization endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://suite.localhost/test/a/plain-fapi-10/par", got.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("PAR endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://suite.localhost:8444/test-mtls/a/plain-fapi-10/par", got.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint); diff != "" {
		t.Fatalf("MTLS PAR endpoint mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://suite.localhost:8444/test-mtls/a/plain-fapi-10/token", got.MTLSEndpointAliases.TokenEndpoint); diff != "" {
		t.Fatalf("MTLS token endpoint mismatch (-want +got):\n%s", diff)
	}
}

func TestProviderMetadataForResolvedRequest_UsesOverrideForEncryptedClient2(t *testing.T) {
	got, ok := providerMetadataForResolvedRequest(resolvedRPRequest{
		issuer:   "https://suite.localhost/test/a/plain-fapi-10/",
		clientID: "local-dev-client-2",
		scopes:   []string{"openid"},
	})
	if !ok {
		t.Fatal("providerMetadataForResolvedRequest() = not configured, want configured")
	}
	if diff := cmp.Diff([]string{"PS256", "RS256"}, got.IDTokenSigningAlgValuesSupported); diff != "" {
		t.Fatalf("ID token signing algs mismatch (-want +got):\n%s", diff)
	}
}

func TestNewRPHTTPClient_SendsClientCertificateWhenRequested(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	tlsCert, privateKey, err := generateTestTLSCertificate()
	if err != nil {
		t.Fatalf("generateTestTLSCertificate() failed: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("expected client certificate on TLS connection")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()

	client := newRPHTTPClient(rp.NewStaticClientKeyProvider(privateKey, "test-mtls", "RS256", &tlsCert))
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}
	defer resp.Body.Close()

	if diff := cmp.Diff(http.StatusNoContent, resp.StatusCode); diff != "" {
		t.Fatalf("status mismatch (-want +got):\n%s", diff)
	}
}

func TestNewRPHTTPClient_SendsClientCertificateWithUnrelatedAcceptedCAs(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	tlsCert, privateKey, err := generateTestTLSCertificate()
	if err != nil {
		t.Fatalf("generateTestTLSCertificate() failed: %v", err)
	}

	caPool, err := generateUnrelatedCAPool()
	if err != nil {
		t.Fatalf("generateUnrelatedCAPool() failed: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("expected client certificate on TLS connection")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, ClientCAs: caPool}
	server.StartTLS()
	defer server.Close()

	client := newRPHTTPClient(rp.NewStaticClientKeyProvider(privateKey, "test-mtls", "RS256", &tlsCert))
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}
	defer resp.Body.Close()

	if diff := cmp.Diff(http.StatusNoContent, resp.StatusCode); diff != "" {
		t.Fatalf("status mismatch (-want +got):\n%s", diff)
	}
}

func generateTestTLSCertificate() (tls.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, privateKey, nil
}

func generateUnrelatedCAPool() (*x509.CertPool, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ca.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}
