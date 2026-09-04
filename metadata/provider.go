package metadata

import "encoding/json"

// Provider contains OpenID Provider information from discovery.
type Provider struct {
	AuthorizationServer

	UserinfoEndpoint                          string   `json:"userinfo_endpoint,omitempty"`
	CheckSessionIframe                        string   `json:"check_session_iframe,omitempty"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint,omitempty"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported       []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported       []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported         []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported      []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported      []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	DisplayValuesSupported                    []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                       []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                           []string `json:"claims_supported,omitempty"`
	ClaimsLocalesSupported                    []string `json:"claims_locales_supported,omitempty"`
	ClaimsParameterSupported                  *bool    `json:"claims_parameter_supported,omitempty"`
	ClaimsInVerifiedClaimsSupported           []string `json:"claims_in_verified_claims_supported,omitempty"`
	DocumentsSupported                        []string `json:"documents_supported,omitempty"`
	DocumentsCheckMethodsSupported            []string `json:"documents_check_methods_supported,omitempty"`
	DocumentsMethodsSupported                 []string `json:"documents_methods_supported,omitempty"`
	ElectronicRecordsSupported                []string `json:"electronic_records_supported,omitempty"`
	RequestParameterSupported                 *bool    `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported              *bool    `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration             *bool    `json:"require_request_uri_registration,omitempty"`
	FrontchannelLogoutSupported               *bool    `json:"frontchannel_logout_supported,omitempty"`
	FrontchannelLogoutSessionSupported        *bool    `json:"frontchannel_logout_session_supported,omitempty"`
	BackchannelLogoutSupported                *bool    `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported         *bool    `json:"backchannel_logout_session_supported,omitempty"`

	PushedAuthorizationRequestEndpoint        string          `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests        *bool           `json:"require_pushed_authorization_requests,omitempty"`
	AuthorizationSigningAlgValuesSupported    []string        `json:"authorization_signing_alg_values_supported,omitempty"`
	AuthorizationEncryptionAlgValuesSupported []string        `json:"authorization_encryption_alg_values_supported,omitempty"`
	AuthorizationEncryptionEncValuesSupported []string        `json:"authorization_encryption_enc_values_supported,omitempty"`
	GrantManagementEndpoint                   string          `json:"grant_management_endpoint,omitempty"`
	GrantManagementActionsSupported           []string        `json:"grant_management_actions_supported,omitempty"`
	GrantManagementActionRequired             *bool           `json:"grant_management_action_required,omitempty"`
	TrustFrameworksSupported                  []string        `json:"trust_frameworks_supported,omitempty"`
	EvidenceSupported                         []string        `json:"evidence_supported,omitempty"`
	VerifiedClaimsSupported                   json.RawMessage `json:"verified_claims_supported,omitempty"`

	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON unmarshals provider data while retaining raw JSON.
func (p *Provider) UnmarshalJSON(data []byte) error {
	type alias Provider

	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*p = Provider(decoded)
	p.Raw = append([]byte(nil), data...)
	p.AuthorizationServer.Raw = append([]byte(nil), data...)

	return nil
}
