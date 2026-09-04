package rp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func unmarshalJSONOrFatal(t *testing.T, raw string) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("fixture JSON invalid: %v\n%s", err, raw)
	}
	return parsed
}

func assertClaimsRequestJSON(t *testing.T, cr *ClaimsRequest, wantRaw string) {
	t.Helper()
	raw, err := cr.JSON()
	if err != nil {
		t.Fatalf("JSON() failed: %v", err)
	}
	want := unmarshalJSONOrFatal(t, wantRaw)
	got := unmarshalJSONOrFatal(t, raw)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("claims request mismatch (-want +got):\n%s\ngot: %s", diff, raw)
	}
}

// Spec section 5.3 example: basic verified claims request.
func TestVerifiedClaimsRequestBasic(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			TrustFramework: &Constrainable{},
		},
		Claims: map[string]*ClaimConstraint{
			"given_name":  nil,
			"family_name": nil,
			"birthdate":   nil,
		},
	})
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"userinfo": {
			"verified_claims": {
				"verification": {
					"trust_framework": null
				},
				"claims": {
					"given_name": null,
					"family_name": null,
					"birthdate": null
				}
			}
		}
	}`)
}

// Spec section 5.3: essential claims.
func TestVerifiedClaimsRequestEssential(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			TrustFramework: &Constrainable{},
		},
		Claims: map[string]*ClaimConstraint{
			"given_name":  {Essential: boolPtr(true)},
			"family_name": {Essential: boolPtr(true)},
			"birthdate":   nil,
		},
	})
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"userinfo": {
			"verified_claims": {
				"verification": {
					"trust_framework": null
				},
				"claims": {
					"given_name": {"essential": true},
					"family_name": {"essential": true},
					"birthdate": null
				}
			}
		}
	}`)
}

// Spec section 5.5.1: trust framework values restriction.
func TestVerifiedClaimsRequestTrustFrameworkValues(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			TrustFramework: &Constrainable{Values: []any{"gold", "silver"}},
		},
		Claims: map[string]*ClaimConstraint{
			"given_name":  nil,
			"family_name": nil,
		},
	})
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"userinfo": {
			"verified_claims": {
				"verification": {
					"trust_framework": {"values": ["gold", "silver"]}
				},
				"claims": {
					"given_name": null,
					"family_name": null
				}
			}
		}
	}`)
}

// Spec section 5.5.1: de_aml with pipp check method and document filters.
func TestVerifiedClaimsRequestEvidenceFilters(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			TrustFramework: &Constrainable{Value: "de_aml"},
			Evidence: []EvidenceFilter{
				{
					Type: Constrainable{Value: "document"},
					CheckDetails: []CheckDetailsFilter{
						{CheckMethod: &Constrainable{Value: "pipp"}},
					},
					DocumentDetails: map[string]*Constrainable{
						"type": {Values: []any{"idcard", "passport"}},
					},
				},
			},
		},
		Claims: map[string]*ClaimConstraint{
			"given_name":  nil,
			"family_name": nil,
		},
	})
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"userinfo": {
			"verified_claims": {
				"verification": {
					"trust_framework": {"value": "de_aml"},
					"evidence": [
						{
							"type": {"value": "document"},
							"check_details": [
								{"check_method": {"value": "pipp"}}
							],
							"document_details": {
								"type": {"values": ["idcard", "passport"]}
							}
						}
					]
				},
				"claims": {
					"given_name": null,
					"family_name": null
				}
			}
		}
	}`)
}

// Spec section 5.5.2: max_age on the verification time.
func TestVerifiedClaimsRequestMaxAge(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			TrustFramework: &Constrainable{Value: "jp_aml"},
			Time:           &Constrainable{MaxAge: int64Ptr(63113852)},
		},
		Claims: map[string]*ClaimConstraint{
			"given_name": nil,
		},
	})
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"userinfo": {
			"verified_claims": {
				"verification": {
					"trust_framework": {"value": "jp_aml"},
					"time": {"max_age": 63113852}
				},
				"claims": {
					"given_name": null
				}
			}
		}
	}`)
}

// Spec section 5.6: array of verified_claims for different requirements.
func TestVerifiedClaimsRequestArray(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToUserInfo(
		VerifiedClaimsFilter{
			Verification: &VerificationFilter{
				TrustFramework: &Constrainable{Value: "eidas"},
				AssuranceLevel: &Constrainable{Value: "high"},
			},
			Claims: map[string]*ClaimConstraint{"family_name": nil},
		},
		VerifiedClaimsFilter{
			Verification: &VerificationFilter{
				TrustFramework: &Constrainable{Value: "de_aml"},
			},
			Claims: map[string]*ClaimConstraint{"birthdate": nil},
		},
	)
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"userinfo": {
			"verified_claims": [
				{
					"verification": {
						"trust_framework": {"value": "eidas"},
						"assurance_level": {"value": "high"}
					},
					"claims": {"family_name": null}
				},
				{
					"verification": {
						"trust_framework": {"value": "de_aml"}
					},
					"claims": {"birthdate": null}
				}
			]
		}
	}`)
}

// Spec section 7: verified_claims in the id_token element.
func TestVerifiedClaimsRequestIDTokenTarget(t *testing.T) {
	cr := NewClaimsRequest()
	err := cr.AddVerifiedClaimsToIDToken(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			TrustFramework: &Constrainable{},
		},
		Claims: map[string]*ClaimConstraint{"family_name": nil},
	})
	if err != nil {
		t.Fatalf("AddVerifiedClaimsToIDToken() failed: %v", err)
	}

	assertClaimsRequestJSON(t, cr, `{
		"id_token": {
			"verified_claims": {
				"verification": {
					"trust_framework": null
				},
				"claims": {"family_name": null}
			}
		}
	}`)
}

func TestVerifiedClaimsRequestValidation(t *testing.T) {
	cr := NewClaimsRequest()

	// Evidence type without value.
	err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			Evidence: []EvidenceFilter{{Type: Constrainable{}}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one value") {
		t.Fatalf("evidence type without value err = %v, want exactly-one-value error", err)
	}

	// Evidence type with values (forbidden per spec).
	err = cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{
			Evidence: []EvidenceFilter{{Type: Constrainable{Values: []any{"document"}}}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must not be used for evidence type") {
		t.Fatalf("evidence type values err = %v, want forbidden-values error", err)
	}

	// No filters.
	if err := cr.AddVerifiedClaimsToUserInfo(); err == nil {
		t.Fatal("empty filter list err = nil, want error")
	}

	// The generated JSON plugs into WithClaims.
	cr = NewClaimsRequest()
	if err := cr.AddVerifiedClaimsToUserInfo(VerifiedClaimsFilter{
		Verification: &VerificationFilter{TrustFramework: &Constrainable{}},
		Claims:       map[string]*ClaimConstraint{"given_name": nil},
	}); err != nil {
		t.Fatalf("AddVerifiedClaimsToUserInfo() failed: %v", err)
	}
	raw, err := cr.JSON()
	if err != nil {
		t.Fatalf("JSON() failed: %v", err)
	}
	if !isValidClaimsJSON(raw) {
		t.Fatalf("generated claims JSON invalid: %s", raw)
	}
}

func boolPtr(v bool) *bool { return &v }
