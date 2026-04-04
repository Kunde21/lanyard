package metadata

import "path"

// OIDCWellKnownURL constructs the OIDC discovery URL for an issuer.
func OIDCWellKnownURL(issuer string) (string, error) {
	u, err := validateIssuerURL(issuer)
	if err != nil {
		return "", err
	}

	issuerPath := u.EscapedPath()
	issuerPath = trimTrailingSlash(issuerPath)

	u.Path = path.Clean(issuerPath + "/.well-known/openid-configuration")
	if u.Path == "." {
		u.Path = "/.well-known/openid-configuration"
	}

	return u.String(), nil
}

// OAuthASWellKnownURL constructs the RFC 8414 metadata URL for an issuer.
func OAuthASWellKnownURL(issuer string) (string, error) {
	u, err := validateIssuerURL(issuer)
	if err != nil {
		return "", err
	}

	issuerPath := trimTrailingSlash(u.EscapedPath())
	if issuerPath == "" {
		u.Path = "/.well-known/oauth-authorization-server"
		return u.String(), nil
	}

	u.Path = path.Clean("/.well-known/oauth-authorization-server" + issuerPath)
	return u.String(), nil
}

func trimTrailingSlash(value string) string {
	for len(value) > 1 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	if value == "/" {
		return ""
	}

	return value
}
