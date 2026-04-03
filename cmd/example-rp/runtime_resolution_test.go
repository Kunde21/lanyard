package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRPHTTPClient_LogsRequestAndResponseDumps(t *testing.T) {
	t.Setenv("RP_INSECURE_TLS", "true")

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	previous := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(previous)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(body) failed: %v", err)
		}
		if got, want := string(body), "grant_type=authorization_code"; got != want {
			t.Fatalf("request body mismatch: got %q want %q", got, want)
		}

		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}))
	defer ts.Close()

	client := newRPHTTPClient(nil)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader("grant_type=authorization_code"))
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() failed: %v", err)
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ReadAll(response body) failed: %v", err)
	}

	logs := logOutput.String()
	for _, want := range []string{
		"rp http request dump",
		"grant_type=authorization_code",
		"rp http response dump",
		"401 Unauthorized",
		`DPoP error=\"use_dpop_nonce\"`,
		`{\"error\":\"use_dpop_nonce\"}`,
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs missing %q:\n%s", want, logs)
		}
	}
}
