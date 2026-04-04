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
	if r.senderConstrain == SenderConstrainMTLS && provider.MTLSEndpointAliases.UserinfoEndpoint != "" {
		return provider.MTLSEndpointAliases.UserinfoEndpoint
	}
	return provider.UserinfoEndpoint
}

func (r *RP) usesMTLSForPAR() bool {
	return r.resolvedAuthMethod == AuthMethodTLSClientAuth
}

func (r *RP) usesMTLSForTokenEndpoint() bool {
	return r.resolvedAuthMethod == AuthMethodTLSClientAuth || r.senderConstrain == SenderConstrainMTLS
}
