package rp

import (
	"fmt"
	"net/url"
	"strings"
)

// GrantManagementAction controls how the authorization server handles the
// underlying grant when processing an authorization request (grant
// management, draft-ietf-oauth-grant-management section 5.2).
type GrantManagementAction string

const (
	// GrantActionCreate asks the authorization server to create a fresh
	// grant. Must not be combined with a grant_id.
	GrantActionCreate GrantManagementAction = "create"
	// GrantActionMerge merges the permissions consented in this request into
	// the grant identified by grant_id; existing refresh tokens for that
	// grant are invalidated.
	GrantActionMerge GrantManagementAction = "merge"
	// GrantActionUpdate is the FAPI Grant Management Implementer's Draft 1
	// spelling of [GrantActionMerge]; kept for deployments certified against
	// that revision.
	GrantActionUpdate GrantManagementAction = "update"
	// GrantActionReplace replaces the grant identified by grant_id with
	// exactly the permissions consented in this request; existing refresh
	// tokens for that grant are invalidated.
	GrantActionReplace GrantManagementAction = "replace"
)

// grantManagementRequest carries the grant management authorization request
// parameters (grant_id and grant_management_action).
type grantManagementRequest struct {
	action  GrantManagementAction
	grantID string
}

// validate checks parameter combinations per draft-ietf-oauth-grant-management
// section 5.2: create must not carry a grant_id, merge/update/replace require
// one.
func (g *grantManagementRequest) validate() error {
	if g == nil || g.action == "" {
		// A grant_id alone is valid: it references an existing grant without
		// requesting create/merge/replace semantics.
		return nil
	}
	grantID := strings.TrimSpace(g.grantID)
	switch g.action {
	case GrantActionCreate:
		if grantID != "" {
			return fmt.Errorf("%w: grant_id must not be combined with grant_management_action=create", ErrInvalidConfiguration)
		}
	case GrantActionMerge, GrantActionUpdate, GrantActionReplace:
		if grantID == "" {
			return fmt.Errorf("%w: grant_management_action=%s requires grant_id", ErrInvalidConfiguration, g.action)
		}
	default:
		return fmt.Errorf("%w: unknown grant_management_action %q", ErrInvalidConfiguration, string(g.action))
	}
	return nil
}

// validateSupported checks the requested action against the provider's
// advertised grant_management_actions_supported. The FAPI ID1 spelling
// "update" is treated as an alias of "merge" in both directions. An empty
// advertised list means the metadata is absent and imposes no restriction.
func (g *grantManagementRequest) validateSupported(supported []string) error {
	if g == nil || g.action == "" || len(supported) == 0 {
		return nil
	}
	for _, supportedAction := range supported {
		if grantActionsEquivalent(g.action, GrantManagementAction(supportedAction)) {
			return nil
		}
	}
	return fmt.Errorf("%w: grant_management_action %q not in grant_management_actions_supported %v",
		ErrInvalidConfiguration, g.action, supported)
}

func grantActionsEquivalent(a, b GrantManagementAction) bool {
	if a == GrantActionUpdate {
		a = GrantActionMerge
	}
	if b == GrantActionUpdate {
		b = GrantActionMerge
	}
	return a == b
}

// applyTo adds the grant management parameters to an authorization request
// parameter set (query form, PAR body).
func (g *grantManagementRequest) applyTo(params url.Values) {
	if g == nil {
		return
	}
	if g.action != "" {
		params.Set("grant_management_action", string(g.action))
	}
	if strings.TrimSpace(g.grantID) != "" {
		params.Set("grant_id", g.grantID)
	}
}

func (g *grantManagementRequest) grantIDValue() string {
	if g == nil {
		return ""
	}
	return strings.TrimSpace(g.grantID)
}

func (g *grantManagementRequest) actionValue() string {
	if g == nil {
		return ""
	}
	return string(g.action)
}
