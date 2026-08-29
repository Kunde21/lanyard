package rp

import "github.com/Kunde21/lanyard/metadata"

func (r *RP) authorizationEndpoint(provider metadata.Provider) string {
	return provider.AuthorizationEndpoint
}

func (r *RP) pushedAuthorizationRequestEndpoint(provider metadata.Provider) string {
	if r.usesMTLSForPAR() && provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint != "" {
		return provider.MTLSEndpointAliases.PushedAuthorizationRequestEndpoint
	}
	return provider.PushedAuthorizationRequestEndpoint
}

func (r *RP) tokenEndpoint(provider metadata.Provider) string {
	if r.usesMTLSForTokenEndpoint() && provider.MTLSEndpointAliases.TokenEndpoint != "" {
		return provider.MTLSEndpointAliases.TokenEndpoint
	}
	return provider.TokenEndpoint
}

func (r *RP) userInfoEndpoint(provider metadata.Provider) string {
	if r.senderConstrain == SenderConstraintMTLS && provider.MTLSEndpointAliases.UserinfoEndpoint != "" {
		return provider.MTLSEndpointAliases.UserinfoEndpoint
	}
	return provider.UserinfoEndpoint
}

func (r *RP) usesMTLSForPAR() bool {
	return r.resolvedAuthMethod == AuthMethodTLSClientAuth || r.resolvedAuthMethod == AuthMethodSelfSignedTLSClientAuth
}

func (r *RP) usesMTLSForTokenEndpoint() bool {
	return r.resolvedAuthMethod == AuthMethodTLSClientAuth || r.resolvedAuthMethod == AuthMethodSelfSignedTLSClientAuth || r.senderConstrain == SenderConstraintMTLS
}

func (c *clientConfig) introspectionEndpoint(provider metadata.Provider) string {
	if c.usesMTLSForIntrospectionEndpoint() && provider.MTLSEndpointAliases.IntrospectionEndpoint != "" {
		return provider.MTLSEndpointAliases.IntrospectionEndpoint
	}
	return provider.IntrospectionEndpoint
}

func (c *clientConfig) usesMTLSForIntrospectionEndpoint() bool {
	return c.resolvedAuthMethod == AuthMethodTLSClientAuth ||
		c.resolvedAuthMethod == AuthMethodSelfSignedTLSClientAuth ||
		c.senderConstrain == SenderConstraintMTLS
}
