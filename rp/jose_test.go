package rp

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
)

func TestSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want jose.SignatureAlgorithm
	}{
		{name: "PS256", alg: "PS256", want: jose.PS256},
		{name: "PS384", alg: "PS384", want: jose.PS384},
		{name: "PS512", alg: "PS512", want: jose.PS512},
		{name: "RS256", alg: "RS256", want: jose.RS256},
		{name: "RS384", alg: "RS384", want: jose.RS384},
		{name: "RS512", alg: "RS512", want: jose.RS512},
		{name: "ES256", alg: "ES256", want: jose.ES256},
		{name: "ES384", alg: "ES384", want: jose.ES384},
		{name: "ES512", alg: "ES512", want: jose.ES512},
		{name: "unknown", alg: "HS256", want: ""},
		{name: "empty", alg: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := signatureAlgorithm(tc.alg)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("signatureAlgorithm(%q) mismatch (-want +got):\n%s", tc.alg, diff)
			}
		})
	}
}
