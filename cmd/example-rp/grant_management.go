package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Kunde21/lanyard/rp"
)

// grantManagementOptionsFromRequest translates the grant_management_action
// and grant_id query parameters of a login request into an authorization
// request option, validating combinations up front so demo users get an
// immediate 400 instead of an error page after the redirect.
func grantManagementOptionsFromRequest(r *http.Request) (rp.AuthorizationURLOption, error) {
	if r == nil {
		return nil, nil
	}
	action := strings.TrimSpace(r.URL.Query().Get("grant_management_action"))
	grantID := strings.TrimSpace(r.URL.Query().Get("grant_id"))

	switch {
	case action == "" && grantID == "":
		return nil, nil
	case action == "":
		return rp.SetGrantID(grantID), nil
	}

	option := rp.SetGrantManagementAction(rp.GrantManagementAction(action), grantID)
	// Re-validate combinations locally so mistakes surface as 400s.
	switch rp.GrantManagementAction(action) {
	case rp.GrantActionCreate:
		if grantID != "" {
			return nil, fmt.Errorf("grant_id must not be combined with grant_management_action=create")
		}
	case rp.GrantActionMerge, rp.GrantActionUpdate, rp.GrantActionReplace:
		if grantID == "" {
			return nil, fmt.Errorf("grant_management_action=%s requires grant_id", action)
		}
	default:
		return nil, fmt.Errorf("unknown grant_management_action %q", action)
	}
	return option, nil
}

// bearerTokenFromRequest extracts the access token for the Grant Management
// API from the Authorization header.
func bearerTokenFromRequest(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// handleGrants serves the grant management demo API:
//
//	GET    /grants/{grant_id}  - query grant status (token needs grant_management_query)
//	DELETE /grants/{grant_id}  - revoke the grant  (token needs grant_management_revoke)
//
// The access token is taken from the Authorization: Bearer header and is
// expected to be obtained out of band (for the demo, e.g. via the client
// credentials grant with the matching scope).
func handleGrants(w http.ResponseWriter, r *http.Request) {
	handleGrantsWithBuild(w, r, func(r *http.Request) (*rp.RP, error) {
		clientID, clientSecret := defaultClientCredentialsForRequest(r)
		return rpClientFromRequest(r,
			clientID,
			clientSecret,
			envOrDefault("RP_REDIRECT_URI", "https://rp.localhost/callback"),
			rp.UserInfoTokenTransportHeader,
		)
	})
}

func handleGrantsWithBuild(w http.ResponseWriter, r *http.Request, build func(*http.Request) (*rp.RP, error)) {
	switch r.Method {
	case http.MethodGet, http.MethodDelete:
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	grantID := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(r.URL.Path), "/"), "grants/")
	if grantID == "" || strings.Contains(grantID, "/") {
		http.Error(w, "grant_id missing: use /grants/{grant_id}", http.StatusBadRequest)
		return
	}

	accessToken := bearerTokenFromRequest(r)
	if accessToken == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Authorization: Bearer <grant management access token> required", http.StatusUnauthorized)
		return
	}

	flow, err := build(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create RP client: %v", err), http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodDelete {
		if err := flow.RevokeGrant(r.Context(), accessToken, grantID); err != nil {
			writeGrantManagementError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	status, err := flow.QueryGrant(r.Context(), accessToken, grantID)
	if err != nil {
		writeGrantManagementError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func writeGrantManagementError(w http.ResponseWriter, err error) {
	if !errors.Is(err, rp.ErrGrantManagementFailed) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var oauthErr *rp.OAuthError
	if errors.As(err, &oauthErr) && oauthErr.Status != 0 {
		http.Error(w, err.Error(), oauthErr.Status)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}
