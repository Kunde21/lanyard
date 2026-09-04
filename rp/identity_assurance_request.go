package rp

import (
	"encoding/json"
	"fmt"
)

// ClaimsRequest is an OIDC Core section 5.5 claims request parameter. The
// IDToken and UserInfo members carry claim names to their constraints; use
// the verified_claims builders to construct identity assurance requests.
type ClaimsRequest struct {
	IDToken  map[string]any `json:"id_token,omitempty"`
	UserInfo map[string]any `json:"userinfo,omitempty"`
}

// NewClaimsRequest creates an empty claims request.
func NewClaimsRequest() *ClaimsRequest {
	return &ClaimsRequest{}
}

// JSON renders the claims request parameter value.
func (c *ClaimsRequest) JSON() (string, error) {
	if c == nil {
		return "", fmt.Errorf("%w: claims request is nil", ErrInvalidConfiguration)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("%w: failed to marshal claims request: %v", ErrInvalidConfiguration, err)
	}
	return string(encoded), nil
}

// Constrainable is a constrainable element of a verified_claims request
// (IDA 1.0 section 5.5): null when nil or fully unset, or an object with
// value, values, max_age, and/or essential restrictions.
type Constrainable struct {
	Essential *bool  `json:"essential,omitempty"`
	Value     any    `json:"value,omitempty"`
	Values    []any  `json:"values,omitempty"`
	MaxAge    *int64 `json:"max_age,omitempty"`
}

// MarshalJSON serializes a fully-unset Constrainable as null, which is the
// spec's way of requesting an element without restrictions.
func (c *Constrainable) MarshalJSON() ([]byte, error) {
	if c == nil || (c.Essential == nil && c.Value == nil && c.Values == nil && c.MaxAge == nil) {
		return []byte("null"), nil
	}
	type alias Constrainable
	return json.Marshal((*alias)(c))
}

// ClaimConstraint constrains one requested verified claim: null constraint
// (nil) requests the claim without restrictions.
type ClaimConstraint struct {
	Essential *bool  `json:"essential,omitempty"`
	Value     any    `json:"value,omitempty"`
	Values    []any  `json:"values,omitempty"`
	MaxAge    *int64 `json:"max_age,omitempty"`
}

// VerificationFilter requests verification data within verified_claims
// (IDA 1.0 sections 5.4-5.5): nil members are not requested; a non-nil
// Constrainable with all fields unset requests the element without
// constraints (serialized as null).
type VerificationFilter struct {
	TrustFramework *Constrainable   `json:"trust_framework,omitempty"`
	AssuranceLevel *Constrainable   `json:"assurance_level,omitempty"`
	AssuranceType  *Constrainable   `json:"assurance_type,omitempty"`
	Time           *Constrainable   `json:"time,omitempty"`
	Evidence       []EvidenceFilter `json:"evidence,omitempty"`
}

// EvidenceFilter is one entry of the evidence request array. Entries are
// combined with logical OR (IDA 1.0 section 5.4). Type is required and MUST
// carry exactly one Value (Values is forbidden there per the spec).
type EvidenceFilter struct {
	Type            Constrainable             `json:"type"`
	CheckDetails    []CheckDetailsFilter      `json:"check_details,omitempty"`
	DocumentDetails map[string]*Constrainable `json:"document_details,omitempty"`
}

// CheckDetailsFilter filters the check_details applied to an evidence.
type CheckDetailsFilter struct {
	CheckMethod  *Constrainable `json:"check_method,omitempty"`
	CheckID      *Constrainable `json:"check_id,omitempty"`
	Organization *Constrainable `json:"organization,omitempty"`
}

// VerifiedClaimsFilter is one verified_claims entry: the verification data
// requested plus the end-user claims to be delivered verified.
type VerifiedClaimsFilter struct {
	Verification *VerificationFilter         `json:"verification,omitempty"`
	Claims       map[string]*ClaimConstraint `json:"claims,omitempty"`
}

// Validate enforces the request grammar rules of IDA 1.0: evidence type
// filters must carry exactly one value and must not use values.
func (f *VerifiedClaimsFilter) Validate() error {
	if f == nil || f.Verification == nil {
		return nil
	}
	for i := range f.Verification.Evidence {
		ev := &f.Verification.Evidence[i]
		if len(ev.Type.Values) > 0 {
			return fmt.Errorf("%w: evidence filter %d: values must not be used for evidence type", ErrInvalidConfiguration, i)
		}
		if ev.Type.Value == nil {
			return fmt.Errorf("%w: evidence filter %d: type must carry exactly one value", ErrInvalidConfiguration, i)
		}
	}
	return nil
}

// AddVerifiedClaimsToUserInfo appends one or more verified_claims filters to
// the userinfo element of the claims request (IDA 1.0 sections 5.3-5.6).
// Multiple filters are sent as an array, requesting claim sets with different
// verification requirements.
func (c *ClaimsRequest) AddVerifiedClaimsToUserInfo(filters ...VerifiedClaimsFilter) error {
	return c.addVerifiedClaims("userinfo", filters)
}

// AddVerifiedClaimsToIDToken appends one or more verified_claims filters to
// the id_token element of the claims request.
func (c *ClaimsRequest) AddVerifiedClaimsToIDToken(filters ...VerifiedClaimsFilter) error {
	return c.addVerifiedClaims("id_token", filters)
}

func (c *ClaimsRequest) addVerifiedClaims(target string, filters []VerifiedClaimsFilter) error {
	if c == nil {
		return fmt.Errorf("%w: claims request is nil", ErrInvalidConfiguration)
	}
	if len(filters) == 0 {
		return fmt.Errorf("%w: at least one verified_claims filter required", ErrInvalidConfiguration)
	}
	for i := range filters {
		if err := filters[i].Validate(); err != nil {
			return err
		}
	}

	if c.IDToken == nil && target == "id_token" {
		c.IDToken = map[string]any{}
	}
	if c.UserInfo == nil && target == "userinfo" {
		c.UserInfo = map[string]any{}
	}
	var destination map[string]any
	switch target {
	case "id_token":
		destination = c.IDToken
	default:
		destination = c.UserInfo
	}

	if len(filters) == 1 {
		destination["verified_claims"] = filters[0]
		return nil
	}
	destination["verified_claims"] = filters
	return nil
}
