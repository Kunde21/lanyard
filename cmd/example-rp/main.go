package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/oidc"
	"github.com/Kunde21/lanyard/rp"
	"github.com/Kunde21/lanyard/rp/store/cookie"
)

type flowHandler interface {
	AuthorizationURL(ctx context.Context, w http.ResponseWriter, req *http.Request) (string, error)
	HandleCallback(ctx context.Context, w http.ResponseWriter, req *http.Request) (*rp.CallbackResult, error)
}

var sharedStateStore = newSharedStateStore()

func newSharedStateStore() rp.StateStore {
	authKey := []byte(envOrDefault("RP_STATE_COOKIE_AUTH_KEY", "0123456789abcdef0123456789abcdef"))
	encryptionKey := []byte(envOrDefault("RP_STATE_COOKIE_ENC_KEY", "abcdef0123456789abcdef0123456789"))

	store, err := cookie.New(
		authKey,
		encryptionKey,
		cookie.WithTTL(10*time.Minute),
		cookie.WithSecure(!envTrue("RP_STATE_COOKIE_INSECURE")),
	)
	if err != nil {
		log.Fatalf("failed to create cookie-backed RP state store: %v", err)
	}

	return store
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/login-userinfo-body", handleLoginUserInfoBody)
	mux.HandleFunc("/callback", handleCallback)

	const addr = ":8080"
	log.Printf("example RP listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("example RP server failed: %v", err)
	}
}

func newMuxForTest(flow flowHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLoginWithFlow(flow))
	mux.HandleFunc("/login-userinfo-body", handleLoginWithFlow(flow))
	mux.HandleFunc("/callback", handleCallbackWithFlow(flow))
	return mux
}

func rpClientFromRequest(r *http.Request, clientID, clientSecret, redirectURI string, transport rp.UserInfoTokenTransport) (*rp.RP, error) {
	issuer := r.URL.Query().Get("issuer")
	if issuer == "" {
		issuer = envOrDefault("RP_ISSUER", "https://suite.localhost")
	}
	httpClient := newRPHTTPClient()
	oidcOpts := []oidc.Option{oidc.WithHTTPClient(httpClient)}
	if envTrue("RP_CONFORMANCE_FRESH_DISCOVERY") {
		oidcOpts = append(oidcOpts, oidc.WithConformanceFreshDiscovery(true))
	}
	oidcClient := oidc.NewClient(oidcOpts...)

	opts := []rp.Option{
		rp.WithHTTPClient(httpClient),
		rp.WithOIDCClient(oidcClient),
		rp.WithStateStore(sharedStateStore),
		rp.WithUserInfoTokenTransport(transport),
		rp.WithScopes(parseScopesEnv("RP_SCOPES", []string{"openid", "profile", "email", "phone", "address"})...),
	}

	return rp.New(r.Context(), issuer, clientID, clientSecret, redirectURI, opts...)
}

func newRPHTTPClient() *http.Client {
	transport := &http.Transport{}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RP_INSECURE_TLS")), "true") {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	}

	return &http.Client{Timeout: 15 * time.Second, Transport: transport}
}

func handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintln(w, "<!doctype html><html><body><h1>Lanyard example RP</h1><p><a href=\"/login\">Login</a></p></body></html>")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	authURL, err := flow.AuthorizationURL(r.Context(), w, r)
	if err != nil {
		http.Error(w, "failed to initialize login", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleLoginUserInfoBody(w http.ResponseWriter, r *http.Request) {
	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportBody,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	authURL, err := flow.AuthorizationURL(r.Context(), w, r)
	if err != nil {
		http.Error(w, "failed to initialize login", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleLoginWithFlow(flow flowHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := flow.AuthorizationURL(r.Context(), w, r)
		if err != nil {
			http.Error(w, "failed to initialize login", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if authErr := strings.TrimSpace(r.URL.Query().Get("error")); authErr != "" {
		http.Error(w, "authorization failed", http.StatusBadRequest)
		return
	}

	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	result, err := flow.HandleCallback(r.Context(), w, r)
	if err != nil {
		log.Printf("callback processing failed: %v", err)
		status := callbackStatus(err)
		http.Error(w, "callback processing failed", status)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!doctype html><html><body><h1>Login complete</h1><p>Subject: %s</p></body></html>", result.Subject)
}

func handleCallbackWithFlow(flow flowHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authErr := strings.TrimSpace(r.URL.Query().Get("error")); authErr != "" {
			http.Error(w, "authorization failed", http.StatusBadRequest)
			return
		}

		result, err := flow.HandleCallback(r.Context(), w, r)
		if err != nil {
			log.Printf("callback processing failed: %v", err)
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
	if errors.Is(err, rp.ErrIDTokenValidationFailed) || errors.Is(err, rp.ErrUserInfoValidationFailed) {
		return http.StatusOK
	}
	if errors.Is(err, rp.ErrInvalidState) || errors.Is(err, rp.ErrMissingCode) || errors.Is(err, rp.ErrTokenExchangeFailed) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func issuerFromRequest(r *http.Request) string {
	issuer := strings.TrimSpace(r.URL.Query().Get("issuer"))
	if issuer == "" {
		issuer = envOrDefault("RP_ISSUER", "https://suite.localhost")
	}
	return issuer
}

func webFingerAcctResource(issuer string) (string, error) {
	alias, host, err := webFingerAliasAndHost(issuer)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("acct:%s.oidcc-client-test-discovery-webfinger-acct@%s", alias, host), nil
}

func webFingerURLResource(issuer string) (string, error) {
	alias, host, err := webFingerAliasAndHost(issuer)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%s/%s/oidcc-client-test-discovery-webfinger-url", host, alias), nil
}

func webFingerAliasAndHost(issuer string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil {
		return "", "", err
	}
	host := strings.TrimSpace(parsed.Host)
	if host == "" {
		return "", "", fmt.Errorf("issuer host missing")
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 3 || segments[0] != "test" || segments[1] != "a" {
		return "", "", fmt.Errorf("issuer path %q does not include /test/a/{alias}", parsed.Path)
	}
	alias := strings.TrimSpace(segments[2])
	if alias == "" {
		return "", "", fmt.Errorf("issuer alias missing")
	}

	return alias, host, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envTrue(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))
	return strings.EqualFold(value, "1") || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") || strings.EqualFold(value, "on")
}

func parseScopesEnv(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return append([]string(nil), fallback...)
	}

	parts := strings.Fields(strings.ReplaceAll(value, ",", " "))
	if len(parts) == 0 {
		return append([]string(nil), fallback...)
	}

	seen := make(map[string]struct{}, len(parts))
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.TrimSpace(part)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		scopes = append(scopes, normalized)
	}
	if len(scopes) == 0 {
		return append([]string(nil), fallback...)
	}
	return scopes
}
