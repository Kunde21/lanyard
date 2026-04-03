package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Kunde21/lanyard/rp"
)

type flowHandler interface {
	AuthorizationURL(ctx context.Context, w http.ResponseWriter, req *http.Request) (string, error)
	HandleCallback(ctx context.Context, w http.ResponseWriter, req *http.Request) (*rp.CallbackResult, error)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/login-userinfo-body", handleLoginUserInfoBody)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/callback/", handleCallback)
	mux.HandleFunc("/conformance/runtime", handleConformanceRuntime)

	const addr = ":8080"
	slog.Info("example RP listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		stdlog.Fatalf("example RP server failed: %v", err)
	}
}

func newMuxForTest(flow flowHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLoginWithFlow(flow))
	mux.HandleFunc("/login-userinfo-body", handleLoginWithFlow(flow))
	mux.HandleFunc("/callback", handleCallbackWithFlow(flow))
	mux.HandleFunc("/callback/", handleCallbackWithFlow(flow))
	mux.HandleFunc("/conformance/runtime", handleConformanceRuntime)
	return mux
}

func rpClientFromRequest(r *http.Request, clientID, clientSecret, redirectURI string, transport rp.UserInfoTokenTransport) (*rp.RP, error) {
	resolved, err := resolveRPRequest(r, clientID, clientSecret, redirectURI, transport)
	if err != nil {
		return nil, err
	}
	return buildRPFromResolvedRequest(r, resolved)
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
		slog.Info("login initialization failed", "err", err)
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
		slog.Info("login initialization failed", "err", err)
		http.Error(w, "failed to initialize login", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleLoginWithFlow(flow flowHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, err := flow.AuthorizationURL(r.Context(), w, r)
		if err != nil {
			slog.Info("login initialization failed", "err", err)
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

	resolved, err := resolveRPRequest(r,
		envOrDefault("RP_CLIENT_ID", "local-dev-client"),
		envOrDefault("RP_CLIENT_SECRET", "local-dev-secret-32-bytes-minimum!!"),
		envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
		rp.UserInfoTokenTransportHeader,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to resolve RP request: %v", err), http.StatusInternalServerError)
		return
	}

	result, err := flow.HandleCallback(r.Context(), w, r)
	if err != nil {
		slog.Info("callback processing failed", "err", err)
		status := callbackStatus(err)
		http.Error(w, "callback processing failed", status)
		return
	}

	if err := maybeFetchConformanceResource(r.Context(), flow, resolved, result.AccessToken); err != nil {
		slog.Info("conformance resource fetch failed", "err", err)
		http.Error(w, "callback processing failed", http.StatusBadRequest)
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
			slog.Info("callback processing failed", "err", err)
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

type dpopProofAttacher interface {
	AttachDPoPProof(req *http.Request, accessToken, nonce string) error
}

func maybeFetchConformanceResource(ctx context.Context, flow flowHandler, resolved resolvedRPRequest, accessToken string) error {
	if accessToken == "" || !isFAPIProfile(resolved) {
		return nil
	}

	endpoint, err := conformanceAccountsEndpoint(resolved)
	if err != nil {
		return err
	}

	dpopEnabled := strings.EqualFold(strings.TrimSpace(resolved.senderConstrain), "dpop")
	var attacher dpopProofAttacher
	if dpopEnabled {
		var ok bool
		attacher, ok = flow.(dpopProofAttacher)
		if !ok {
			return fmt.Errorf("dpop sender constraint requires proof attacher")
		}
	}

	client := newRPHTTPClient(resolved.keyProvider)
	doRequest := func(nonce string) (*http.Response, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, "", fmt.Errorf("build conformance resource request: %w", err)
		}

		if dpopEnabled {
			req.Header.Set("Authorization", "DPoP "+accessToken)
			if err := attacher.AttachDPoPProof(req, accessToken, nonce); err != nil {
				return nil, "", fmt.Errorf("attach DPoP proof: %w", err)
			}
		} else {
			req.Header.Set("Authorization", "Bearer "+accessToken)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("execute conformance resource request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		if err != nil {
			return nil, "", fmt.Errorf("read conformance resource response: %w", err)
		}

		return resp, strings.TrimSpace(string(body)), nil
	}

	resp, preview, err := doRequest("")
	if err != nil {
		return err
	}

	if dpopEnabled && isUseDPoPNonceChallenge(resp) {
		nonce := strings.TrimSpace(resp.Header.Get("DPoP-Nonce"))
		if nonce != "" {
			resp, preview, err = doRequest(nonce)
			if err != nil {
				return err
			}
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("conformance resource endpoint returned status %d: %s", resp.StatusCode, preview)
	}

	return nil
}

func isUseDPoPNonceChallenge(resp *http.Response) bool {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	return strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`)
}

func isFAPIProfile(resolved resolvedRPRequest) bool {
	profile := strings.ToLower(strings.TrimSpace(resolved.fapiProfile))
	return strings.Contains(profile, "fapi")
}

func conformanceAccountsEndpoint(resolved resolvedRPRequest) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(resolved.issuer))
	if err != nil {
		return "", fmt.Errorf("parse issuer: %w", err)
	}
	alias, err := issuerAlias(resolved.issuer)
	if err != nil {
		return "", err
	}

	host := parsed.Host
	pathPrefix := "/test/a/"
	if strings.EqualFold(strings.TrimSpace(resolved.senderConstrain), "mtls") {
		host = parsed.Hostname() + ":8444"
		pathPrefix = "/test-mtls/a/"
	}

	return fmt.Sprintf("%s://%s%s%s/open-banking/v1.1/accounts", parsed.Scheme, host, pathPrefix, alias), nil
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
