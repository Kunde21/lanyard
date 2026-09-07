package rp

import "github.com/Kunde21/lanyard/metadata"

func (r *RP) authorizationEndpoint(provider metadata.Provider) string {
	return provider.AuthorizationEndpoint
}

func (r *RP) pushedAuthorizationRequestEndpoint(provider metadata.Provider) string {
	method, _ := r.authMethodState()
	return pushedAuthorizationRequestEndpointWithAuthMethod(provider, method)
}

func pushedAuthorizationRequestEndpointWithAuthMethod(provider metadata.Provider, method AuthMethod) string {
	usesMTLS := method == AuthMethodTLSClientAuth || method == AuthMethodSelfSignedTLSClientAuth
	if usesMTLS && provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint != "" {
		return provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint
	}
	return provider.PushedAuthorizationRequestEndpoint
}

// effectiveTokenEndpoint selects the token endpoint, honoring the mTLS
// endpoint alias when the configuration uses mTLS (tls_client_auth,
// self_signed_tls_client_auth, or mTLS sender constraining). Shared by the
// RP flows and the client-credentials grant (third RC review T4).
func (c *clientConfig) effectiveTokenEndpoint(provider metadata.Provider) string {
	if c.usesMTLSForTokenEndpoint() && provider.MTLSEndpointAliases.TokenEndpoint != "" {
		return provider.MTLSEndpointAliases.TokenEndpoint
	}
	return provider.TokenEndpoint
}

func (r *RP) tokenEndpoint(provider metadata.Provider) string {
	return r.effectiveTokenEndpoint(provider)
}

func (r *RP) userInfoEndpoint(provider metadata.Provider) string {
	if r.senderConstrain == SenderConstraintMTLS && provider.MTLSEndpointAliases.UserinfoEndpoint != "" {
		return provider.MTLSEndpointAliases.UserinfoEndpoint
	}
	return provider.UserinfoEndpoint
}

func (r *RP) usesMTLSForTokenEndpoint() bool {
	return r.clientConfig.usesMTLSForTokenEndpoint()
}

func (c *clientConfig) usesMTLSForTokenEndpoint() bool {
	method, _ := c.authMethodState()
	return method == AuthMethodTLSClientAuth || method == AuthMethodSelfSignedTLSClientAuth || c.senderConstrain == SenderConstraintMTLS
}

func (c *clientConfig) introspectionEndpoint(provider metadata.Provider) string {
	if c.usesMTLSForIntrospectionEndpoint() && provider.MTLSEndpointAliases.IntrospectionEndpoint != "" {
		return provider.MTLSEndpointAliases.IntrospectionEndpoint
	}
	return provider.IntrospectionEndpoint
}

func (c *clientConfig) usesMTLSForIntrospectionEndpoint() bool {
	method, _ := c.authMethodState()
	return method == AuthMethodTLSClientAuth ||
		method == AuthMethodSelfSignedTLSClientAuth ||
		c.senderConstrain == SenderConstraintMTLS
}
