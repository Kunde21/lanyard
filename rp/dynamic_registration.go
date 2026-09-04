package rp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrRegistrationFailed indicates a dynamic client registration or
// registration management request failed.
var ErrRegistrationFailed = errors.New("dynamic client registration failed")

// ClientMetadata is an RFC 7591 client registration request body. Zero-value
// fields are omitted; the authorization server's response (ClientRegistration)
// is the authority on what was actually accepted.
type ClientMetadata struct {
	// RedirectURIs are the permitted callback URIs. Required unless GrantTypes
	// is exactly ["client_credentials"].
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// TokenEndpointAuthMethod defaults to client_secret_basic when omitted,
	// exactly like the provider's default per RFC 7591 section 2.
	TokenEndpointAuthMethod AuthMethod `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string   `json:"grant_types,omitempty"`
	ResponseTypes           []string   `json:"response_types,omitempty"`
	ClientName              string     `json:"client_name,omitempty"`
	ClientURI               string     `json:"client_uri,omitempty"`
	LogoURI                 string     `json:"logo_uri,omitempty"`
	Scope                   string     `json:"scope,omitempty"`
	Contacts                []string   `json:"contacts,omitempty"`
	// JWKSURI is the URL of the client's JWK Set. Mutually exclusive with JWKS.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// JWKS holds the client's public keys inline. Mutually exclusive with
	// JWKSURI.
	JWKS json.RawMessage `json:"jwks,omitempty"`
	// SoftwareID identifies the software deployment per RFC 7591 section 2.
	SoftwareID string `json:"software_id,omitempty"`
	// SoftwareVersion identifies the software version.
	SoftwareVersion string `json:"software_version,omitempty"`
	// SoftwareStatement is a signed JWT containing client metadata claims
	// (RFC 7591 section 3.1.1), passed through verbatim — the authorization
	// server verifies its signature. FAPI/Brazil deployments issue
	// PS256-signed statements; build them with go-jose.
	SoftwareStatement string `json:"software_statement,omitempty"`
}

// validate enforces the client-side rules of RFC 7591 sections 2 and 3.1.
func (m ClientMetadata) validate() error {
	hasJWKS := len(m.JWKS) > 0 && string(m.JWKS) != "null"
	if hasJWKS && strings.TrimSpace(m.JWKSURI) != "" {
		return fmt.Errorf("%w: jwks and jwks_uri are mutually exclusive", ErrInvalidConfiguration)
	}

	if len(m.RedirectURIs) > 0 {
		return nil
	}
	if len(m.GrantTypes) == 1 && m.GrantTypes[0] == "client_credentials" {
		return nil
	}
	return fmt.Errorf("%w: redirect_uris is required unless grant_types is exactly [client_credentials]",
		ErrInvalidConfiguration)
}

// ClientRegistration is an RFC 7591 registration response: the credentials
// issued for the client plus the metadata the authorization server accepted.
type ClientRegistration struct {
	ClientID                string          `json:"client_id"`
	ClientSecret            string          `json:"client_secret,omitempty"`
	ClientIDIssuedAt        *int64          `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   *int64          `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken string          `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string          `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string        `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod AuthMethod      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string        `json:"grant_types,omitempty"`
	ResponseTypes           []string        `json:"response_types,omitempty"`
	ClientName              string          `json:"client_name,omitempty"`
	ClientURI               string          `json:"client_uri,omitempty"`
	LogoURI                 string          `json:"logo_uri,omitempty"`
	Scope                   string          `json:"scope,omitempty"`
	Contacts                []string        `json:"contacts,omitempty"`
	JWKSURI                 string          `json:"jwks_uri,omitempty"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
	SoftwareID              string          `json:"software_id,omitempty"`
	SoftwareVersion         string          `json:"software_version,omitempty"`

	raw json.RawMessage
}

// UnmarshalJSON decodes the registration and preserves the raw payload.
func (r *ClientRegistration) UnmarshalJSON(data []byte) error {
	if r == nil {
		return fmt.Errorf("client registration is nil")
	}
	type alias ClientRegistration
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = ClientRegistration(decoded)
	r.raw = append(r.raw[:0], data...)
	return nil
}

// DecodeRaw unmarshals the preserved registration payload into target.
func (r ClientRegistration) DecodeRaw(target any) error {
	if target == nil {
		return fmt.Errorf("target is nil")
	}
	if len(r.raw) == 0 {
		return fmt.Errorf("client registration raw payload is empty")
	}
	if err := json.Unmarshal(r.raw, target); err != nil {
		return fmt.Errorf("failed to decode client registration raw payload: %w", err)
	}
	return nil
}

// SecretExpired reports whether the issued client secret has expired at now.
// A client without a secret, or with client_secret_expires_at set to 0 (which
// RFC 7591 section 3.2.1 defines as "does not expire"), never expires.
func (r ClientRegistration) SecretExpired(now time.Time) bool {
	if r.ClientSecret == "" || r.ClientSecretExpiresAt == nil {
		return false
	}
	expiresAt := *r.ClientSecretExpiresAt
	if expiresAt == 0 {
		return false
	}
	return now.Unix() >= expiresAt
}

// Manageable reports whether the server supports registration management
// (RFC 7592): both registration_client_uri and registration_access_token
// must have been issued together.
func (r ClientRegistration) Manageable() bool {
	return r.RegistrationClientURI != "" && r.RegistrationAccessToken != ""
}

// registrationStatusError maps a non-success registration response to an
// error, decoding RFC 7591/7592 error bodies into *OAuthError.
func registrationStatusError(status int, preview string) error {
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal([]byte(preview), &body); err == nil && body.Error != "" {
		return fmt.Errorf("%w: %w", ErrRegistrationFailed,
			&OAuthError{Code: body.Error, Description: body.Description, Status: status})
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%w: registration endpoint returned status %d: %s", ErrRegistrationFailed, status, preview)
	}
	return fmt.Errorf("%w: registration endpoint returned status %d: %s", ErrRegistrationFailed, status, preview)
}
