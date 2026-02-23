package jwks

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecodeJWKSAllowsUnknownCurvesWhenOtherKeysValid(t *testing.T) {
	input := `{
		"keys": [
			{
				"kty": "EC",
				"crv": "secp256k1",
				"use": "sig",
				"kid": "unsupported-curve",
				"x": "Uq0P2sU2X_04k0Q1DsfHa3DXf27vfZ85aY-J7sar_mw",
				"y": "wdROEHLY3MSLyM4MCNARj9HVULt9TGawvW0H7mGfAVc"
			},
			{
				"kty": "oct",
				"kid": "oct-1",
				"use": "sig",
				"alg": "HS256",
				"k": "dGhpcy1pcy1hLXNlY3JldA"
			}
		]
	}`

	keys, err := decodeJWKS(strings.NewReader(input))
	if err != nil {
		t.Fatalf("decodeJWKS() failed: %v", err)
	}

	if diff := cmp.Diff(1, len(keys)); diff != "" {
		t.Fatalf("decoded key count mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("oct-1", keys[0].KeyID); diff != "" {
		t.Fatalf("decoded key id mismatch (-want +got):\n%s", diff)
	}
}

func TestDecodeJWKSFailsWhenAllKeysInvalid(t *testing.T) {
	input := `{
		"keys": [
			{
				"kty": "EC",
				"crv": "secp256k1",
				"use": "sig",
				"kid": "unsupported-curve",
				"x": "Uq0P2sU2X_04k0Q1DsfHa3DXf27vfZ85aY-J7sar_mw",
				"y": "wdROEHLY3MSLyM4MCNARj9HVULt9TGawvW0H7mGfAVc"
			}
		]
	}`

	if _, err := decodeJWKS(strings.NewReader(input)); err == nil {
		t.Fatalf("decodeJWKS() expected error when all keys are invalid")
	}
}
