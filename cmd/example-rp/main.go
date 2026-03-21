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
)

type flowHandler interface {
	AuthorizationURL(ctx context.Context) (string, error)
	HandleCallback(ctx context.Context, code, state string) (*rp.CallbackResult, error)
}

var sharedStateStore = rp.NewMemoryStateStore(10 * time.Minute)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/login-userinfo-body", handleLoginUserInfoBody)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/discovery", handleDiscovery)
	mux.HandleFunc("/discovery-jwks", handleDiscoveryJWKS)
	mux.HandleFunc("/webfinger-acct", handleWebFingerAcct)
	mux.HandleFunc("/webfinger-url", handleWebFingerURL)

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
	mux.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "discovery triggered (test)")
	})
	mux.HandleFunc("/discovery-jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "discovery+jwks triggered (test)")
	})
	mux.HandleFunc("/webfinger-acct", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "webfinger acct triggered")
	})
	mux.HandleFunc("/webfinger-url", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "webfinger url triggered")
	})
	return mux
}

func rpClientFromRequest(r *http.Request, clientID, clientSecret, redirectURI string, transport rp.UserInfoTokenTransport, skipInitialDiscovery bool) (*rp.RP, error) {
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
	if skipInitialDiscovery {
		opts = append(opts, rp.WithProviderDiscovery(oidc.ProviderMetadata{}))
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
		true,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	authURL, err := flow.AuthorizationURL(r.Context())
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
		false,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	authURL, err := flow.AuthorizationURL(r.Context())
	if err != nil {
		http.Error(w, "failed to initialize login", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleLoginWithFlow(flow flowHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := flow.AuthorizationURL(r.Context())
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

	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
		true,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	result, err := flow.HandleCallback(r.Context(), code, state)
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
	if errors.Is(err, rp.ErrInvalidState) || errors.Is(err, rp.ErrMissingCode) || errors.Is(err, rp.ErrIDTokenValidationFailed) || errors.Is(err, rp.ErrUserInfoValidationFailed) || errors.Is(err, rp.ErrTokenExchangeFailed) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
		true,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "failed to create RP client: %v", err)
		return
	}

	if err := flow.Discover(r.Context()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "discovery failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "discovery triggered")
}

func handleDiscoveryJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
		false,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "failed to create RP client: %v", err)
		return
	}

	if err := flow.DiscoverWithJWKS(r.Context()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "discovery+jwks failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "discovery+jwks triggered")
}

func handleWebFingerAcct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	resource, err := webFingerAcctResource(issuerFromRequest(r))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "invalid issuer for webfinger acct resource: %v", err)
		return
	}

	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
		false,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "failed to create RP client: %v", err)
		return
	}

	if err := flow.DiscoverFromWebFinger(r.Context(), resource); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "webfinger acct discovery failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "webfinger acct triggered: %s\n", resource)
}

func handleWebFingerURL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	resource, err := webFingerURLResource(issuerFromRequest(r))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "invalid issuer for webfinger URL resource: %v", err)
		return
	}

	flow, err := rpClientFromRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
		false,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "failed to create RP client: %v", err)
		return
	}

	if err := flow.DiscoverFromWebFinger(r.Context(), resource); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "webfinger URL discovery failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "webfinger url triggered: %s\n", resource)
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
