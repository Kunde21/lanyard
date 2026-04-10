package main

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/Kunde21/lanyard/rp"
)

type startupAction string

const (
	startupActionFullFlow         startupAction = "full_flow"
	startupActionDiscoveryOnly    startupAction = "discovery_only"
	startupActionDiscoveryAndJWKS startupAction = "discovery_and_jwks"
)

func parseStartupAction(s string) startupAction {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case string(startupActionDiscoveryOnly):
		return startupActionDiscoveryOnly
	case string(startupActionDiscoveryAndJWKS):
		return startupActionDiscoveryAndJWKS
	case string(startupActionFullFlow):
		return startupActionFullFlow
	default:
		return startupActionFullFlow
	}
}

type rpRuntimeConfig struct {
	Alias                               string                    `json:"alias"`
	Issuer                              string                    `json:"issuer,omitempty"`
	ClientID                            string                    `json:"client_id"`
	ClientSecret                        string                    `json:"client_secret,omitempty"`
	RedirectURI                         string                    `json:"redirect_uri"`
	Scopes                              []string                  `json:"scopes,omitempty"`
	Namespace                           string                    `json:"namespace,omitempty"`
	UserInfoTokenTransport              rp.UserInfoTokenTransport `json:"userinfo_token_transport,omitempty"`
	ClientAuthType                      string                    `json:"client_auth_type,omitempty"`
	SenderConstrain                     string                    `json:"sender_constrain,omitempty"`
	AuthorizationRequestType            string                    `json:"authorization_request_type,omitempty"`
	FAPIClientType                      string                    `json:"fapi_client_type,omitempty"`
	FAPIProfile                         string                    `json:"fapi_profile,omitempty"`
	RequestType                         string                    `json:"request_type,omitempty"`
	RequirePAR                          bool                      `json:"require_par,omitempty"`
	ResponseMode                        string                    `json:"response_mode,omitempty"`
	ResponseType                        string                    `json:"response_type,omitempty"`
	FAPIRequestMethod                   string                    `json:"fapi_request_method,omitempty"`
	Profile                             string                    `json:"profile,omitempty"`
	DiscoveryMode                       string                    `json:"discovery_mode,omitempty"`
	ValidateAuthorizationResponseIssuer bool                      `json:"validate_authorization_response_issuer,omitempty"`
	StartupAction                       string                    `json:"startup_action,omitempty"`
	StartupAllowError                   bool                      `json:"startup_allow_error,omitempty"`
}

type runtimeStartupResponse struct {
	AuthorizationURL string   `json:"authorization_url,omitempty"`
	Cookies          []string `json:"cookies,omitempty"`
}

func (c rpRuntimeConfig) startupAction() startupAction {
	return parseStartupAction(c.StartupAction)
}

type runtimeRegistry struct {
	mu      sync.RWMutex
	entries map[string]rpRuntimeConfig
}

func newRuntimeRegistry() *runtimeRegistry {
	return &runtimeRegistry{entries: map[string]rpRuntimeConfig{}}
}

func (r *runtimeRegistry) Register(cfg rpRuntimeConfig) error {
	alias := strings.TrimSpace(cfg.Alias)
	if alias == "" {
		return fmt.Errorf("alias is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return fmt.Errorf("client_id is required")
	}
	if strings.TrimSpace(cfg.RedirectURI) == "" {
		return fmt.Errorf("redirect_uri is required")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = alias
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email", "phone", "address"}
	}
	if cfg.UserInfoTokenTransport == "" {
		cfg.UserInfoTokenTransport = rp.UserInfoTokenTransportHeader
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[alias] = cfg
	return nil
}

func (r *runtimeRegistry) Lookup(alias string) (rpRuntimeConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.entries[strings.TrimSpace(alias)]
	return cfg, ok
}

func (r *runtimeRegistry) Delete(alias string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, strings.TrimSpace(alias))
}

func (r *runtimeRegistry) LookupByIssuer(issuer string) (rpRuntimeConfig, bool) {
	alias, err := issuerAlias(issuer)
	if err != nil {
		return rpRuntimeConfig{}, false
	}
	return r.Lookup(alias)
}

func issuerAlias(issuer string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil {
		return "", err
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 3 || segments[0] != "test" || segments[1] != "a" || strings.TrimSpace(segments[2]) == "" {
		return "", fmt.Errorf("issuer path %q does not include /test/a/{alias}", parsed.Path)
	}
	return strings.TrimSpace(segments[2]), nil
}
