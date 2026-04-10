package rp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestShouldUseDPoP_RespectsExplicitSenderConstraint(t *testing.T) {
	r := &RP{
		resolvedAuthMethod: AuthMethodPrivateKeyJWT,
		clientKeyProvider:  &staticClientKeyProvider{},
	}

	if diff := cmp.Diff(false, r.shouldUseDPoP()); diff != "" {
		t.Fatalf("default shouldUseDPoP() mismatch (-want +got):\n%s", diff)
	}

	WithSenderConstrain("mtls")(r)
	if diff := cmp.Diff(false, r.shouldUseDPoP()); diff != "" {
		t.Fatalf("mtls shouldUseDPoP() mismatch (-want +got):\n%s", diff)
	}

	WithSenderConstrain("dpop")(r)
	if diff := cmp.Diff(true, r.shouldUseDPoP()); diff != "" {
		t.Fatalf("dpop shouldUseDPoP() mismatch (-want +got):\n%s", diff)
	}
}
