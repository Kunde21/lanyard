package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrGrantManagementFailed indicates a grant management API request failed.
var ErrGrantManagementFailed = errors.New("grant management request failed")

// GrantScope describes one scope entry of a grant, optionally tied to the
// resource indicators it was approved with (RFC 8707).
type GrantScope struct {
	Scope    string   `json:"scope,omitempty"`
	Resource []string `json:"resource,omitempty"`
}

// UnmarshalJSON accepts the "resource" member name used by
// draft-ietf-oauth-grant-management as well as the "resources" spelling from
// the FAPI Grant Management Implementer's Draft 1.
func (g *GrantScope) UnmarshalJSON(data []byte) error {
	var raw struct {
		Scope     string   `json:"scope"`
		Resource  []string `json:"resource,omitempty"`
		Resources []string `json:"resources,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	g.Scope = raw.Scope
	g.Resource = raw.Resource
	if g.Resource == nil {
		g.Resource = raw.Resources
	}
	return nil
}

// GrantStatus is the status of a grant as returned by the Grant Management
// API (draft-ietf-oauth-grant-management section 6.4).
type GrantStatus struct {
	// Scopes lists the granted scope values, each optionally tied to the
	// resource indicators it was approved with.
	Scopes []GrantScope `json:"scopes,omitempty"`
	// Claims lists the OpenID Connect claim names consented in the grant.
	Claims []string `json:"claims,omitempty"`
	// AuthorizationDetails holds the RFC 9396 authorization details consented
	// in the grant, as raw JSON.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
	// CreatedAt is when the grant was originally created (NumericDate).
	CreatedAt *int64 `json:"created_at,omitempty"`
	// LastUpdated is when the grant was last updated (NumericDate). Accepts
	// both "last_updated_at" and the "last_updated" spelling.
	LastUpdated *int64 `json:"last_updated_at,omitempty"`
	// ExpiresAt is when the grant expires (NumericDate).
	ExpiresAt *int64 `json:"expires_at,omitempty"`
	// UpdatedBy indicates who last updated the grant: "client" or
	// "authorization_server".
	UpdatedBy string `json:"updated_by,omitempty"`

	raw json.RawMessage
}

type grantStatusJSON GrantStatus

// UnmarshalJSON decodes the grant status and preserves the raw payload.
func (s *GrantStatus) UnmarshalJSON(data []byte) error {
	if s == nil {
		return fmt.Errorf("grant status is nil")
	}
	type alias grantStatusJSON
	var decoded struct {
		alias
		LastUpdatedAlt *int64 `json:"last_updated,omitempty"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = GrantStatus(decoded.alias)
	if s.LastUpdated == nil {
		s.LastUpdated = decoded.LastUpdatedAlt
	}
	s.raw = append(s.raw[:0], data...)
	return nil
}

// DecodeRaw unmarshals the preserved grant status payload into target.
func (s GrantStatus) DecodeRaw(target any) error {
	if target == nil {
		return fmt.Errorf("target is nil")
	}
	if len(s.raw) == 0 {
		return fmt.Errorf("grant status raw payload is empty")
	}
	if err := json.Unmarshal(s.raw, target); err != nil {
		return fmt.Errorf("failed to decode grant status raw payload: %w", err)
	}
	return nil
}

// GrantManager is a standalone client for the Grant Management API,
// mirroring [NewIntrospector] construction (issuer-based discovery or
// explicit provider metadata). The API is authorized with a Bearer access
// token supplied by the caller, obtained with the grant_management_query
// and/or grant_management_revoke scope.
type GrantManager struct {
	clientConfig
}

// NewGrantManager creates a Grant Management API client for the given issuer.
func NewGrantManager(ctx context.Context, issuer string, opts ...Option) (*GrantManager, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	m := &GrantManager{clientConfig: defaultClientConfig(issuer)}
	for _, opt := range opts {
		if _, ok := opt.(AuthCodeOption); ok {
			return nil, fmt.Errorf("%w: auth-code option is not valid for grant management", ErrInvalidConfiguration)
		}
		opt.applyConfig(&m.clientConfig)
	}

	m.clientConfig.initDefaults()
	if len(m.optionErrors) > 0 {
		return nil, m.optionErrors[0]
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	m.clientConfig.initMetadataClient()
	if err := m.clientConfig.resolveProviderFromDiscovery(ctx); err != nil {
		return nil, err
	}
	if m.provider.GrantManagementEndpoint == "" {
		return nil, fmt.Errorf("%w: grant management endpoint is not configured", ErrInvalidConfiguration)
	}
	return m, nil
}

func (m *GrantManager) validate() error {
	if err := validateHTTPSAbsoluteURL("issuer", m.issuer); err != nil {
		return err
	}
	if m.clientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrInvalidConfiguration)
	}
	return nil
}

// QueryGrant retrieves the current status of the grant identified by grantID.
func (m *GrantManager) QueryGrant(ctx context.Context, accessToken, grantID string) (GrantStatus, error) {
	return m.clientConfig.queryGrant(ctx, accessToken, grantID)
}

// RevokeGrant revokes the grant identified by grantID and all refresh tokens
// issued from it.
func (m *GrantManager) RevokeGrant(ctx context.Context, accessToken, grantID string) error {
	return m.clientConfig.revokeGrant(ctx, accessToken, grantID)
}

// QueryGrant retrieves the current status of a grant via the provider's Grant
// Management API. accessToken must carry the grant_management_query scope.
func (r *RP) QueryGrant(ctx context.Context, accessToken, grantID string) (GrantStatus, error) {
	return r.clientConfig.queryGrant(ctx, accessToken, grantID)
}

// RevokeGrant revokes a grant via the provider's Grant Management API;
// the authorization server must revoke all refresh tokens issued from the
// grant. accessToken must carry the grant_management_revoke scope.
func (r *RP) RevokeGrant(ctx context.Context, accessToken, grantID string) error {
	return r.clientConfig.revokeGrant(ctx, accessToken, grantID)
}

func (c *clientConfig) grantResourceURL(grantID string) (string, error) {
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return "", fmt.Errorf("%w: grant_id is required", ErrGrantManagementFailed)
	}
	endpoint := c.provider.GrantManagementEndpoint
	if endpoint == "" {
		return "", fmt.Errorf("%w: grant management endpoint is not configured", ErrGrantManagementFailed)
	}
	return strings.TrimSuffix(endpoint, "/") + "/" + url.PathEscape(grantID), nil
}

func (c *clientConfig) queryGrant(ctx context.Context, accessToken, grantID string) (GrantStatus, error) {
	resourceURL, err := c.grantResourceURL(grantID)
	if err != nil {
		return GrantStatus{}, err
	}
	if strings.TrimSpace(accessToken) == "" {
		return GrantStatus{}, fmt.Errorf("%w: access token is required", ErrGrantManagementFailed)
	}

	var status GrantStatus
	httpStatus, preview, err := c.grantRequest(ctx, http.MethodGet, resourceURL, accessToken, http.StatusOK, func(body io.Reader) error {
		data, readErr := io.ReadAll(body)
		if readErr != nil {
			return fmt.Errorf("failed to read grant status: %w", readErr)
		}
		if err := json.Unmarshal(data, &status); err != nil {
			return &jsonDecodeError{Err: fmt.Errorf("failed to decode grant status: %w", err)}
		}
		return nil
	})
	if err != nil {
		return GrantStatus{}, fmt.Errorf("%w: %v", ErrGrantManagementFailed, err)
	}
	if httpStatus != http.StatusOK {
		return GrantStatus{}, c.grantStatusError(httpStatus, preview)
	}
	return status, nil
}

func (c *clientConfig) revokeGrant(ctx context.Context, accessToken, grantID string) error {
	resourceURL, err := c.grantResourceURL(grantID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("%w: access token is required", ErrGrantManagementFailed)
	}

	httpStatus, preview, err := c.grantRequest(ctx, http.MethodDelete, resourceURL, accessToken, http.StatusNoContent, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGrantManagementFailed, err)
	}
	if httpStatus != http.StatusNoContent {
		return c.grantStatusError(httpStatus, preview)
	}
	return nil
}

func (c *clientConfig) grantRequest(ctx context.Context, method, resourceURL, accessToken string, successStatus int, decode func(io.Reader) error) (int, string, error) {
	var preview string
	var retryAfter string

	_, status, previewRaw, err := doRequestWithDPoPRetry(dpopRequestConfig{
		buildRequest: func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, method, resourceURL, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to build grant management request: %w", err)
			}
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
			req.Header.Set("Accept", "application/json")
			return req, nil
		},
		attachDPoP: func(req *http.Request, nonce string) error {
			return c.attachDPoPProofForAccessToken(req, accessToken, nonce)
		},
		handleResponse: decode,
		storeNonce: func(resp *http.Response) {
			c.extractAndStoreDPoPNonce(resp, resourceURL)
			if resp != nil && resp.Header != nil {
				if v := resp.Header.Get("Retry-After"); v != "" {
					retryAfter = v
				}
			}
		},
		successStatus: successStatus,
		httpClient:    c.httpClient,
		useDPoP:       c.shouldUseDPoP(),
		cachedNonce:   c.cachedDPoPNonce(resourceURL),
	})
	preview = previewRaw
	if err != nil {
		return status, preview, err
	}
	if retryAfter != "" {
		preview = strings.TrimSpace(preview + " retry-after: " + retryAfter)
	}
	return status, preview, nil
}

func (c *clientConfig) grantStatusError(status int, preview string) error {
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(preview), &body); err == nil && body.Error != "" {
		return fmt.Errorf("%w: %w", ErrGrantManagementFailed, &OAuthError{Code: body.Error, Description: body.Description, Status: status})
	}
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: grant management endpoint returned 401: access token missing or invalid", ErrGrantManagementFailed)
	case http.StatusForbidden:
		return fmt.Errorf("%w: grant management endpoint returned 403: not authorized for this grant", ErrGrantManagementFailed)
	case http.StatusNotFound:
		return fmt.Errorf("%w: grant management endpoint returned 404: grant not found", ErrGrantManagementFailed)
	default:
		return fmt.Errorf("%w: grant management endpoint returned status %d: %s", ErrGrantManagementFailed, status, preview)
	}
}
