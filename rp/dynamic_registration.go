package rp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// RequestURIs pre-registers the request_uri endpoints the client will use
	// (RFC 7591 section 2). Some providers require request_uri values to be
	// pre-registered.
	RequestURIs []string `json:"request_uris,omitempty"`
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

// Options returns the configuration options carrying this registration's
// issued credentials, for splicing into [New]:
//
//	rp.New(ctx, issuer, append(reg.Options(), rp.WithRedirectURI(...), ...)...)
//
// Only credentials are included; redirect URI, scopes, key material, and
// auth-method pinning remain the caller's choices.
func (r ClientRegistration) Options() []Option {
	opts := []Option{WithClientID(r.ClientID)}
	if r.ClientSecret != "" {
		opts = append(opts, WithClientSecret(r.ClientSecret))
	}
	return opts
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

// Registrar registers clients at authorization servers supporting dynamic
// client registration (RFC 7591) and manages the resulting registrations
// (RFC 7592). Registration endpoints are protected by access tokens (an
// initial access token for registration, the registration access token for
// management), not by OAuth client authentication.
type Registrar struct {
	clientConfig
}

// NewRegistrar creates a dynamic client registration client for the given
// issuer. Unlike [New], it requires no client credentials: the client does
// not exist yet. Provider metadata is discovered automatically unless
// [WithProviderMetadata] supplies it. Use [WithInitialAccessToken] when the
// registration endpoint requires a bearer token.
func NewRegistrar(ctx context.Context, issuer string, opts ...Option) (*Registrar, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	g := &Registrar{clientConfig: defaultClientConfig(issuer)}
	for _, opt := range opts {
		if _, ok := opt.(AuthCodeOption); ok {
			return nil, fmt.Errorf("%w: auth-code option is not valid for dynamic client registration", ErrInvalidConfiguration)
		}
		opt.applyConfig(&g.clientConfig)
	}

	g.clientConfig.initDefaults()
	if len(g.optionErrors) > 0 {
		return nil, g.optionErrors[0]
	}
	if err := validateHTTPSAbsoluteURL("issuer", g.issuer); err != nil {
		return nil, err
	}
	g.clientConfig.initMetadataClient()
	if err := g.clientConfig.resolveProviderFromDiscovery(ctx); err != nil {
		return nil, err
	}
	if g.provider.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("%w: registration endpoint is not configured", ErrInvalidConfiguration)
	}
	return g, nil
}

// ClientUpdate is an RFC 7592 PUT request body: the registration's metadata
// plus the client_id the update targets (RFC 7592 section 2.2 requires it).
type ClientUpdate struct {
	ClientMetadata
	ClientID string `json:"client_id"`
}

// Register registers a new client at the provider's registration endpoint
// (RFC 7591 section 3.1). The response carries the issued credentials; when
// the server supports registration management it also carries the
// registration access token and client URI. The initial access token set via
// [WithInitialAccessToken], if any, authorizes the request.
func (g *Registrar) Register(ctx context.Context, meta ClientMetadata) (ClientRegistration, error) {
	if err := meta.validate(); err != nil {
		return ClientRegistration{}, err
	}
	return g.doRegistrationRequest(ctx, http.MethodPost, g.provider.RegistrationEndpoint, g.initialAccessToken, meta, http.StatusCreated)
}

// Read retrieves the current state of a registration from its client
// configuration endpoint (RFC 7592 section 2.1). accessToken is the
// registration access token issued at registration or update time.
func (g *Registrar) Read(ctx context.Context, registrationClientURI, accessToken string) (ClientRegistration, error) {
	if err := validateRegistrationManagementArgs(registrationClientURI, accessToken); err != nil {
		return ClientRegistration{}, err
	}
	return g.doRegistrationRequest(ctx, http.MethodGet, registrationClientURI, accessToken, nil, http.StatusOK)
}

// Update replaces a registration's metadata on its client configuration
// endpoint (RFC 7592 section 2.2) and returns the new registration state;
// the server MAY rotate the client secret, so always persist the returned
// value. The request is authorized with the registration access token.
func (g *Registrar) Update(ctx context.Context, registrationClientURI, accessToken string, update ClientUpdate) (ClientRegistration, error) {
	if err := validateRegistrationManagementArgs(registrationClientURI, accessToken); err != nil {
		return ClientRegistration{}, err
	}
	if err := update.validate(); err != nil {
		return ClientRegistration{}, err
	}
	if update.ClientID == "" {
		return ClientRegistration{}, fmt.Errorf("%w: client_id is required in an update", ErrInvalidConfiguration)
	}
	return g.doRegistrationRequest(ctx, http.MethodPut, registrationClientURI, accessToken, update, http.StatusOK)
}

// Delete unregisters the client (RFC 7592 section 2.3). After a successful
// delete the client_id and secret, the registration access token, and all
// tokens issued to the client are invalid.
func (g *Registrar) Delete(ctx context.Context, registrationClientURI, accessToken string) error {
	if err := validateRegistrationManagementArgs(registrationClientURI, accessToken); err != nil {
		return err
	}
	_, err := g.doRegistrationRequest(ctx, http.MethodDelete, registrationClientURI, accessToken, nil, http.StatusNoContent)
	return err
}

// doRegistrationRequest executes one registration-family HTTP request and
// decodes the success body (if any) into a ClientRegistration.
func (g *Registrar) doRegistrationRequest(ctx context.Context, method, endpoint, accessToken string, body any, successStatus int) (ClientRegistration, error) {
	req, err := g.registrationRequest(ctx, method, endpoint, accessToken, body)
	if err != nil {
		return ClientRegistration{}, fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}

	var reg ClientRegistration
	_, status, preview, err := doJSONStatus(req, g.httpClient, successStatus, func(body io.Reader) error {
		data, readErr := io.ReadAll(body)
		if readErr != nil {
			return fmt.Errorf("failed to read registration response: %w", readErr)
		}
		if len(data) == 0 {
			return nil
		}
		if err := json.Unmarshal(data, &reg); err != nil {
			return &jsonDecodeError{Err: fmt.Errorf("failed to decode registration response: %w", err)}
		}
		return nil
	})
	if err != nil {
		var decodeErr *jsonDecodeError
		if errors.As(err, &decodeErr) {
			return ClientRegistration{}, fmt.Errorf("%w: %v", ErrRegistrationFailed, decodeErr.Err)
		}
		return ClientRegistration{}, fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	if status != successStatus {
		return ClientRegistration{}, registrationStatusError(status, preview)
	}
	return reg, nil
}

func validateRegistrationManagementArgs(registrationClientURI, accessToken string) error {
	if err := validateHTTPSAbsoluteURL("registration_client_uri", registrationClientURI); err != nil {
		return fmt.Errorf("%w: %v", ErrRegistrationFailed, err)
	}
	if strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("%w: registration access token is required", ErrRegistrationFailed)
	}
	return nil
}

func (g *Registrar) registrationRequest(ctx context.Context, method, endpoint, accessToken string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal registration request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(accessToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	}
	return req, nil
}
