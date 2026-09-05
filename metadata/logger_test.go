package metadata

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestLoggerIsConsumers proves a consumer-supplied logger receives the
// library's debug output (here: a JWKS refresh failure), and that the
// default stays silent (discard) unless configured.
func TestLoggerIsConsumers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	validJWKS, err := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": "kid-a",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var failing atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validJWKS)
	}))
	defer server.Close()

	var buf bytes.Buffer
	consumerLogger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := NewClient(
		WithLogger(consumerLogger),
		WithHTTPClient(server.Client()),
	)
	keySet, err := client.RemoteKeySetFromJWKSURI(server.URL)
	if err != nil {
		t.Fatalf("RemoteKeySetFromJWKSURI() failed: %v", err)
	}

	// Prime the cache with a successful fetch.
	if _, err := keySet.Keys(context.Background()); err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}

	// Fail refreshes; an unknown-kid lookup then logs through the consumer's
	// logger.
	failing.Store(true)
	_, _ = keySet.Key(context.Background(), "kid-missing")

	if !strings.Contains(buf.String(), "jwks refresh failed") {
		t.Fatalf("consumer logger received no jwks output: %q", buf.String())
	}

	// The default client logs nothing (discard handler).
	defaultClient := NewClient(WithHTTPClient(server.Client()))
	defaultSet, err := defaultClient.RemoteKeySetFromJWKSURI(server.URL)
	if err != nil {
		t.Fatalf("RemoteKeySetFromJWKSURI() failed: %v", err)
	}
	// Prime, then flip back to failing for the default client's refresh.
	failing.Store(false)
	if _, err := defaultSet.Keys(context.Background()); err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	failing.Store(true)
	_, _ = defaultSet.Key(context.Background(), "kid-missing")
}
