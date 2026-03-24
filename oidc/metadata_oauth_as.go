package oidc

import "encoding/json"

// MTLSEndpointAliases contains RFC 8705 mutual-TLS endpoint aliases.
type MTLSEndpointAliases struct {
	TokenEndpoint                      string `json:"token_endpoint,omitempty"`
	RegistrationEndpoint               string `json:"registration_endpoint,omitempty"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint                 string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint              string `json:"introspection_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
}

// AuthorizationServerMetadata contains OAuth 2.0 Authorization Server Metadata
// (RFC 8414).
type AuthorizationServerMetadata struct {
	Issuer                                             string              `json:"issuer"`
	AuthorizationEndpoint                              string              `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string              `json:"token_endpoint,omitempty"`
	JWKSURI                                            string              `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               string              `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string            `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string            `json:"response_types_supported"`
	ResponseModesSupported                             []string            `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string            `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string            `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string            `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string              `json:"service_documentation,omitempty"`
	UILocalesSupported                                 []string            `json:"ui_locales_supported,omitempty"`
	OpPolicyURI                                        string              `json:"op_policy_uri,omitempty"`
	OpTOSURI                                           string              `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string              `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string            `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string            `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string              `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string            `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string            `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	MTLSEndpointAliases                                MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`
	CodeChallengeMethodsSupported                      []string            `json:"code_challenge_methods_supported,omitempty"`
	Raw                                                json.RawMessage     `json:"-"`
}
