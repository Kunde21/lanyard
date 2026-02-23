package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/rp"
)

func main() {
	flow, err := rp.New(
		envOrDefault("RP_ISSUER", "https://suite.test"),
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.test/callback"),
		rp.WithHTTPClient(&http.Client{Timeout: 15 * time.Second}),
	)
	if err != nil {
		log.Fatalf("failed to initialize RP: %v", err)
	}

	mux := newMux(flow)

	const addr = ":8080"
	log.Printf("example RP listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("example RP server failed: %v", err)
	}
}

type flowHandler interface {
	AuthorizationURL(ctx context.Context) (string, error)
	HandleCallback(ctx context.Context, code, state string) (*rp.CallbackResult, error)
}

func newMux(flow flowHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin(flow))
	mux.HandleFunc("/callback", handleCallback(flow))
	return mux
}

func handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintln(w, "<!doctype html><html><body><h1>Lanyard example RP</h1><p><a href=\"/login\">Login</a></p></body></html>")
}

func handleLogin(flow flowHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := flow.AuthorizationURL(r.Context())
		if err != nil {
			http.Error(w, "failed to initialize login", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func handleCallback(flow flowHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authErr := strings.TrimSpace(r.URL.Query().Get("error")); authErr != "" {
			http.Error(w, "authorization failed", http.StatusBadRequest)
			return
		}

		code := strings.TrimSpace(r.URL.Query().Get("code"))
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if state == "" {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		result, err := flow.HandleCallback(r.Context(), code, state)
		if err != nil {
			status := callbackStatus(err)
			http.Error(w, "callback processing failed", status)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body><h1>Login complete</h1><p>Subject: %s</p></body></html>", result.Subject)
	}
}

func callbackStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if errors.Is(err, rp.ErrInvalidState) || errors.Is(err, rp.ErrMissingCode) || errors.Is(err, rp.ErrIDTokenValidationFailed) || errors.Is(err, rp.ErrUserInfoValidationFailed) || errors.Is(err, rp.ErrTokenExchangeFailed) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
