package rp

import "github.com/go-jose/go-jose/v4"

func signatureAlgorithm(alg string) jose.SignatureAlgorithm {
	switch alg {
	case "PS256":
		return jose.PS256
	case "PS384":
		return jose.PS384
	case "PS512":
		return jose.PS512
	case "RS256":
		return jose.RS256
	case "RS384":
		return jose.RS384
	case "RS512":
		return jose.RS512
	case "ES256":
		return jose.ES256
	case "ES384":
		return jose.ES384
	case "ES512":
		return jose.ES512
	default:
		return ""
	}
}
