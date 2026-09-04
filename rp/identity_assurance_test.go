package rp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// Spec section 5.2 example: verified_claims in an ID token payload.
func TestParseVerifiedClaimsObject(t *testing.T) {
	payload := map[string]any{
		"iss": "https://server.example.com",
		"sub": "248289761",
		"verified_claims": map[string]any{
			"verification": map[string]any{
				"trust_framework": "trust_framework_example",
			},
			"claims": map[string]any{
				"given_name":  "Max",
				"family_name": "Meier",
			},
		},
	}

	got, err := ParseVerifiedClaims(payload)
	if err != nil {
		t.Fatalf("ParseVerifiedClaims() failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if diff := cmp.Diff("trust_framework_example", got[0].Verification.TrustFramework); diff != "" {
		t.Fatalf("TrustFramework mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("Max", got[0].Claims["given_name"]); diff != "" {
		t.Fatalf("given_name mismatch (-want +got):\n%s", diff)
	}

	var extra struct {
		Claims map[string]any `json:"claims"`
	}
	if err := got[0].DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("Meier", extra.Claims["family_name"]); diff != "" {
		t.Fatalf("DecodeRaw family_name mismatch (-want +got):\n%s", diff)
	}
}

func TestParseVerifiedClaimsArray(t *testing.T) {
	payload := map[string]any{
		"verified_claims": []any{
			map[string]any{
				"verification": map[string]any{"trust_framework": "eidas"},
				"claims":       map[string]any{"family_name": "Doe"},
			},
			map[string]any{
				"verification": map[string]any{"trust_framework": "de_aml"},
				"claims":       map[string]any{"birthdate": "1980-01-01"},
			},
		},
	}

	got, err := ParseVerifiedClaims(payload)
	if err != nil {
		t.Fatalf("ParseVerifiedClaims() failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if diff := cmp.Diff("de_aml", got[1].Verification.TrustFramework); diff != "" {
		t.Fatalf("second TrustFramework mismatch (-want +got):\n%s", diff)
	}
}

func TestParseVerifiedClaimsAbsent(t *testing.T) {
	got, err := ParseVerifiedClaims(map[string]any{"sub": "s"})
	if err != nil {
		t.Fatalf("ParseVerifiedClaims() failed: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}

	// Explicit null is absent.
	got, err = ParseVerifiedClaims(map[string]any{"verified_claims": nil})
	if err != nil {
		t.Fatalf("ParseVerifiedClaims() failed: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %v, want nil for null member", got)
	}
}

func TestParseVerifiedClaimsEvidence(t *testing.T) {
	verificationTime := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	payload := map[string]any{
		"verified_claims": map[string]any{
			"verification": map[string]any{
				"trust_framework":   "de_aml",
				"assurance_level":   "high",
				"time":              "2026-01-15T10:30:00Z",
				"assurance_process": map[string]any{"policy": "aml-2024"},
				"evidence": []any{
					map[string]any{
						"type": "document",
						"time": "2026-01-15T09:00:00Z",
						"check_details": []any{
							map[string]any{
								"check_method": "pipp",
								"organization": "Externe Identifikationsstelle",
								"check_id":     "chk-1",
								"time":         "2026-01-15T09:15:00Z",
							},
						},
						"document_details": map[string]any{
							"type":             "idcard",
							"issuer":           "Stadt Augsburg",
							"number":           "535545A64",
							"date_of_issuance": "2012-04-25",
							"date_of_expiry":   "2022-09-07",
						},
					},
				},
			},
			"claims": map[string]any{"given_name": "Max"},
		},
	}

	got, err := ParseVerifiedClaims(payload)
	if err != nil {
		t.Fatalf("ParseVerifiedClaims() failed: %v", err)
	}
	v := got[0].Verification
	if diff := cmp.Diff("high", v.AssuranceLevel); diff != "" {
		t.Fatalf("AssuranceLevel mismatch (-want +got):\n%s", diff)
	}
	if v.Time == nil || !v.Time.Equal(verificationTime) {
		t.Fatalf("Time = %v, want %v", v.Time, verificationTime)
	}
	if len(v.Evidence) != 1 {
		t.Fatalf("Evidence len = %d, want 1", len(v.Evidence))
	}
	ev := v.Evidence[0]
	if diff := cmp.Diff("document", ev.Type); diff != "" {
		t.Fatalf("Evidence type mismatch (-want +got):\n%s", diff)
	}
	if len(ev.CheckDetails) != 1 || ev.CheckDetails[0].CheckMethod != "pipp" {
		t.Fatalf("CheckDetails = %+v, want pipp", ev.CheckDetails)
	}
	if diff := cmp.Diff("Externe Identifikationsstelle", ev.CheckDetails[0].Organization); diff != "" {
		t.Fatalf("Organization mismatch (-want +got):\n%s", diff)
	}
	if len(ev.DocumentDetails) == 0 {
		t.Fatal("DocumentDetails empty")
	}
}

func TestVerificationFreshFor(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	hourAgo := now.Add(-time.Hour)

	tests := []struct {
		name   string
		verif  Verification
		maxAge time.Duration
		want   bool
	}{
		{
			name:   "verification time within max age",
			verif:  Verification{Time: &hourAgo},
			maxAge: 2 * time.Hour,
			want:   true,
		},
		{
			name:   "verification time beyond max age",
			verif:  Verification{Time: &hourAgo},
			maxAge: 30 * time.Minute,
			want:   false,
		},
		{
			name: "latest evidence time used when verification time absent",
			verif: Verification{Evidence: []Evidence{
				{Time: ptrTime(now.Add(-3 * time.Hour))},
				{Time: ptrTime(now.Add(-90 * time.Minute))},
			}},
			maxAge: 2 * time.Hour,
			want:   true,
		},
		{
			name:   "no timestamps at all",
			verif:  Verification{TrustFramework: "de_aml"},
			maxAge: 24 * time.Hour,
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.verif.FreshFor(tc.maxAge, now); got != tc.want {
				t.Fatalf("FreshFor() = %v, want %v", got, tc.want)
			}
		})
	}

	var nilVerification *Verification
	if nilVerification.FreshFor(time.Hour, now) {
		t.Fatal("nil Verification FreshFor() = true, want false")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
