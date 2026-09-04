package rp

import (
	"encoding/json"
	"fmt"
	"time"
)

// VerifiedClaims is the identity assurance container (OpenID Connect for
// Identity Assurance 1.0): the end-user claims that were verified together
// with the metadata of the verification process.
type VerifiedClaims struct {
	// Verification describes how the claims were verified.
	Verification *Verification `json:"verification,omitempty"`
	// Claims holds the verified end-user claims.
	Claims map[string]any `json:"claims,omitempty"`

	raw json.RawMessage
}

// Verification is the verification metadata of a VerifiedClaims container:
// what was verified, how, when, and under which rules.
type Verification struct {
	// TrustFramework is the trust framework the verification complies with
	// (e.g. "de_aml", "eidas", "nist_800_63A").
	TrustFramework string `json:"trust_framework,omitempty"`
	// AssuranceLevel is the level of assurance achieved.
	AssuranceLevel string `json:"assurance_level,omitempty"`
	// AssuranceType is the type of assurance (e.g. "identity_proofing").
	AssuranceType string `json:"assurance_type,omitempty"`
	// Time is when the verification process took place (RFC 3339).
	Time *time.Time `json:"time,omitempty"`
	// Evidence lists the evidence used in the verification process.
	Evidence []Evidence `json:"evidence,omitempty"`
	// AssuranceProcess holds further data about the assurance process in
	// case of re-use of previous verification. Opaque; use DecodeRaw.
	AssuranceProcess json.RawMessage `json:"assurance_process,omitempty"`

	raw json.RawMessage
}

// Evidence is one piece of identity evidence (document, electronic record,
// vouch, electronic signature, ...) with the checks applied to it.
type Evidence struct {
	Type string `json:"type,omitempty"`
	// Time is when the evidence was collected or the check performed.
	Time *time.Time `json:"time,omitempty"`
	// CheckDetails lists the processes applied to this evidence.
	CheckDetails []CheckDetails `json:"check_details,omitempty"`
	// DocumentDetails holds document data (type, number, issuer, dates)
	// for evidence of type document. Opaque; use DecodeRaw.
	DocumentDetails json.RawMessage `json:"document_details,omitempty"`
	// ElectronicRecord holds electronic record data. Opaque; use DecodeRaw.
	ElectronicRecord json.RawMessage `json:"electronic_record,omitempty"`

	raw json.RawMessage
}

// CheckDetails describes one process applied to an evidence.
type CheckDetails struct {
	// CheckMethod is the method used (e.g. "pipp", "sripp", "eid").
	CheckMethod string `json:"check_method,omitempty"`
	// CheckID identifies the check.
	CheckID string `json:"check_id,omitempty"`
	// Organization is the party that conducted the check.
	Organization string `json:"organization,omitempty"`
	// Time is when the check was conducted (RFC 3339).
	Time *time.Time `json:"time,omitempty"`
}

// UnmarshalJSON decodes verified_claims and preserves the raw payload.
func (v *VerifiedClaims) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("verified_claims is nil")
	}
	type alias VerifiedClaims
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*v = VerifiedClaims(decoded)
	v.raw = append(v.raw[:0], data...)
	return nil
}

// DecodeRaw unmarshals the preserved verified_claims payload into target.
func (v VerifiedClaims) DecodeRaw(target any) error {
	if target == nil {
		return fmt.Errorf("target is nil")
	}
	if len(v.raw) == 0 {
		return fmt.Errorf("verified_claims raw payload is empty")
	}
	if err := json.Unmarshal(v.raw, target); err != nil {
		return fmt.Errorf("failed to decode verified_claims raw payload: %w", err)
	}
	return nil
}

// ParseVerifiedClaims extracts the verified_claims member from an ID Token
// payload or UserInfo response (map form). The member may be a single object
// or an array of objects; both are returned as a slice. An absent member
// yields nil without error.
func ParseVerifiedClaims(payload map[string]any) ([]VerifiedClaims, error) {
	member, ok := payload["verified_claims"]
	if !ok || member == nil {
		return nil, nil
	}

	encoded, err := json.Marshal(member)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode verified_claims: %w", err)
	}
	return parseVerifiedClaimsJSON(encoded)
}

func parseVerifiedClaimsJSON(encoded []byte) ([]VerifiedClaims, error) {
	var single VerifiedClaims
	if err := json.Unmarshal(encoded, &single); err == nil {
		if single.raw != nil || single.Verification != nil || single.Claims != nil {
			return []VerifiedClaims{single}, nil
		}
	}

	var many []VerifiedClaims
	if err := json.Unmarshal(encoded, &many); err != nil {
		return nil, fmt.Errorf("verified_claims must be an object or an array of objects: %w", err)
	}
	return many, nil
}

// FreshFor reports whether the verification data satisfies a max_age
// requirement (in the sense of IDA 1.0 section 5.5.2) at the given time: the
// elapsed time since verification.Time — or, when that is absent, the most
// recent time found on the evidence and its checks — must not exceed maxAge.
// Dates without a time component count from the last valid second of the
// day. Verification data carrying no timestamps at all does not satisfy any
// freshness requirement.
func (v *Verification) FreshFor(maxAge time.Duration, now time.Time) bool {
	if v == nil {
		return false
	}
	earliest := latestTimestamp(v)
	if earliest.IsZero() {
		return false
	}
	return now.Sub(earliest) <= maxAge
}

func latestTimestamp(v *Verification) time.Time {
	var latest time.Time
	consider := func(t *time.Time) {
		if t != nil && t.After(latest) {
			latest = *t
		}
	}
	consider(v.Time)
	for i := range v.Evidence {
		ev := &v.Evidence[i]
		consider(ev.Time)
		for j := range ev.CheckDetails {
			consider(ev.CheckDetails[j].Time)
		}
	}
	return latest
}
