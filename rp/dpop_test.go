package rp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateDPoPProof_IncludesExpectedClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	r := &RP{
		clientConfig: clientConfig{
			clientKeyProvider:  NewStaticClientKeyProvider(key, "kid-1", "PS256", nil),
			resolvedAuthMethod: AuthMethodPrivateKeyJWT,
			randReader:         bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)),
			now:                func() time.Time { return time.Unix(1712100000, 0).UTC() },
		},
	}

	proof, err := r.generateDPoPProof(http.MethodPost, "https://issuer.test/token", "access-token", "nonce-123")
	if err != nil {
		t.Fatalf("generateDPoPProof() failed: %v", err)
	}

	header, payload := decodeProofParts(t, proof)

	if diff := cmp.Diff("dpop+jwt", header.Typ); diff != "" {
		t.Fatalf("typ mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(http.MethodPost, payload.HTM); diff != "" {
		t.Fatalf("htm mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("https://issuer.test/token", payload.HTU); diff != "" {
		t.Fatalf("htu mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("nonce-123", payload.Nonce); diff != "" {
		t.Fatalf("nonce mismatch (-want +got):\n%s", diff)
	}
	if payload.ATH == "" {
		t.Fatalf("expected ath to be set")
	}
	if payload.JTI == "" {
		t.Fatalf("expected jti to be set")
	}
	if payload.IAT == 0 {
		t.Fatalf("expected iat to be set")
	}
}

func TestDoRequestWithDPoPRetry_NoDPoP(t *testing.T) {
	var gotAccept string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	var decoded bool
	resp, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return http.NewRequest(http.MethodPost, ts.URL, nil)
		},
		handleResponse: func(body io.Reader) error {
			decoded = true
			return nil
		},
		successStatus: http.StatusOK,
		httpClient:    ts.Client(),
		useDPoP:       false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(http.StatusOK, status); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
	if preview != "" {
		t.Errorf("expected empty preview for success, got %q", preview)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !decoded {
		t.Fatal("expected handleResponse to be called")
	}
	if gotAccept != "application/json" {
		t.Fatalf("expected Accept header to be set, got %q", gotAccept)
	}
}

func TestDoRequestWithDPoPRetry_WithDPoP_StoresNonce(t *testing.T) {
	var gotDPoP string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")
		w.Header().Set("DPoP-Nonce", "server-nonce-1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	var storedNonce string
	resp, status, _, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return http.NewRequest(http.MethodPost, ts.URL, nil)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			req.Header.Set("DPoP", "proof-with-"+nonce)
			return nil
		},
		handleResponse: func(body io.Reader) error { return nil },
		storeNonce: func(resp *http.Response) {
			storedNonce = resp.Header.Get("DPoP-Nonce")
		},
		successStatus: http.StatusOK,
		httpClient:    ts.Client(),
		useDPoP:       true,
		cachedNonce:   "cached-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(http.StatusOK, status); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff("proof-with-cached-1", gotDPoP); diff != "" {
		t.Errorf("DPoP header mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("server-nonce-1", storedNonce); diff != "" {
		t.Errorf("stored nonce mismatch (-want +got):\n%s", diff)
	}
}

func TestDoRequestWithDPoPRetry_RetriesOnNonceChallenge(t *testing.T) {
	requests := 0
	var firstProof string
	var secondProof string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		proof := r.Header.Get("DPoP")

		if requests == 1 {
			firstProof = proof
			w.Header().Set("DPoP-Nonce", "nonce-2")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		secondProof = proof
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	var storedNonces []string
	resp, status, _, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return http.NewRequest(http.MethodPost, ts.URL, nil)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			req.Header.Set("DPoP", "proof-"+nonce)
			return nil
		},
		handleResponse: func(body io.Reader) error { return nil },
		storeNonce: func(resp *http.Response) {
			storedNonces = append(storedNonces, resp.Header.Get("DPoP-Nonce"))
		},
		successStatus: http.StatusOK,
		httpClient:    ts.Client(),
		useDPoP:       true,
		cachedNonce:   "cached-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(http.StatusOK, status); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(2, requests); diff != "" {
		t.Errorf("request count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("proof-cached-1", firstProof); diff != "" {
		t.Errorf("first proof mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("proof-nonce-2", secondProof); diff != "" {
		t.Errorf("second proof mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"nonce-2", ""}, storedNonces); diff != "" {
		t.Errorf("stored nonces mismatch (-want +got):\n%s", diff)
	}
}

func TestDoRequestWithDPoPRetry_BuildRequestError(t *testing.T) {
	buildErr := fmt.Errorf("build failed")
	resp, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return nil, buildErr
		},
		useDPoP: false,
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, buildErr) {
		t.Errorf("expected buildErr, got: %v", err)
	}
	if resp != nil || status != 0 || preview != "" {
		t.Errorf("expected zero values, got resp=%v status=%d preview=%q", resp, status, preview)
	}
}

func TestDoRequestWithDPoPRetry_AttachDPoPError(t *testing.T) {
	attachErr := fmt.Errorf("attach failed")
	resp, status, preview, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return http.NewRequest(http.MethodPost, "http://example.com", nil)
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return attachErr
		},
		useDPoP:     true,
		cachedNonce: "nonce",
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "attach failed") {
		t.Errorf("expected attach error message, got: %v", err)
	}
	if !errors.Is(err, attachErr) {
		t.Errorf("expected wrapped attachErr, got: %v", err)
	}
	if resp != nil || status != 0 || preview != "" {
		t.Errorf("expected zero values, got resp=%v status=%d preview=%q", resp, status, preview)
	}
}

func TestDoRequestWithDPoPRetry_DoJSONStatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`invalid json`))
	}))
	defer ts.Close()

	resp, status, _, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			return http.NewRequest(http.MethodPost, ts.URL, nil)
		},
		handleResponse: func(body io.Reader) error {
			return fmt.Errorf("decode failed")
		},
		successStatus: http.StatusOK,
		httpClient:    ts.Client(),
		useDPoP:       false,
	})

	if err == nil {
		t.Fatal("expected error")
	}
	var decodeErr *jsonDecodeError
	if !errors.As(err, &decodeErr) {
		t.Errorf("expected jsonDecodeError, got: %T: %v", err, err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
}

func decodeProofParts(t *testing.T, proof string) (dpopHeader, dpopPayload) {
	t.Helper()

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof should have 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	var header dpopHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var payload dpopPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	return header, payload
}
