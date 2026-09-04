package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kunde21/lanyard/rp"
)

// registrar abstracts the dynamic registration surface of *rp.Registrar.
type registrar interface {
	Register(ctx context.Context, meta rp.ClientMetadata) (rp.ClientRegistration, error)
}

// buildRegistrar builds a Registrar for the issuer of the request.
func buildRegistrar(r *http.Request) (registrar, error) {
	opts := []rp.Option{}
	if token := strings.TrimSpace(r.URL.Query().Get("initial_access_token")); token != "" {
		opts = append(opts, rp.WithInitialAccessToken(token))
	}
	return rp.NewRegistrar(
		r.Context(),
		issuerFromRequest(r),
		opts...,
	)
}

// demoClientMetadata builds the registration request for the demo from the
// request and environment defaults.
func demoClientMetadata(r *http.Request) rp.ClientMetadata {
	meta := rp.ClientMetadata{
		RedirectURIs:            []string{envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback")},
		ClientName:              envOrDefault("RP_CLIENT_NAME", "Lanyard example RP"),
		TokenEndpointAuthMethod: rp.AuthMethodBasic,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
	}
	if name := strings.TrimSpace(r.URL.Query().Get("client_name")); name != "" {
		meta.ClientName = name
	}
	return meta
}

// handleRegister serves the dynamic registration demo:
//
//	GET  /register - HTML form for manual registration
//	POST /register - register a client at the issuer's registration endpoint
//
// The issued credentials and registration management information are
// rendered once and never persisted: copy them out before leaving the page.
func handleRegister(w http.ResponseWriter, r *http.Request) {
	handleRegisterWithBuild(w, r, buildRegistrar)
}

func handleRegisterWithBuild(w http.ResponseWriter, r *http.Request, build func(*http.Request) (registrar, error)) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!doctype html><html><body><h1>Dynamic client registration</h1>
<p>POST /register?issuer=...&amp;client_name=...&amp;initial_access_token=...</p>
</body></html>`)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client, err := build(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create registrar: %v", err), http.StatusInternalServerError)
		return
	}

	reg, err := client.Register(r.Context(), demoClientMetadata(r))
	if err != nil {
		writeRegistrationError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(registrationDemoJSON{
		ClientID:                reg.ClientID,
		ClientSecret:            reg.ClientSecret,
		SecretExpired:           reg.SecretExpired(time.Now().UTC()),
		Manageable:              reg.Manageable(),
		RegistrationClientURI:   reg.RegistrationClientURI,
		RegistrationAccessToken: reg.RegistrationAccessToken,
		NextStep:                "rp.New(ctx, issuer, append(reg.Options(), rp.WithRedirectURI(...)) ...)",
	})
}

type registrationDemoJSON struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	SecretExpired           bool   `json:"secret_expired"`
	Manageable              bool   `json:"manageable"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	NextStep                string `json:"next_step"`
}

func writeRegistrationError(w http.ResponseWriter, err error) {
	if !errors.Is(err, rp.ErrRegistrationFailed) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var oauthErr *rp.OAuthError
	if errors.As(err, &oauthErr) && oauthErr.Status != 0 {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}
