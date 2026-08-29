package rp

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTokenGrantIDFromResponse(t *testing.T) {
	body := `{
		"access_token": "2YotnFZFEjr1zCsicMWpAA",
		"token_type": "Bearer",
		"expires_in": 3600,
		"refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
		"grant_id": "TSdqirmAxDa0_-DB_1bASQ"
	}`

	var token Token
	if err := parseTokenResponse([]byte(body), &token); err != nil {
		t.Fatalf("parseTokenResponse() failed: %v", err)
	}
	if diff := cmp.Diff("TSdqirmAxDa0_-DB_1bASQ", token.GrantID); diff != "" {
		t.Fatalf("GrantID mismatch (-want +got):\n%s", diff)
	}

	// The raw payload is preserved for DecodeRaw, including grant_id.
	var extra struct {
		GrantID string `json:"grant_id"`
	}
	if err := token.DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("TSdqirmAxDa0_-DB_1bASQ", extra.GrantID); diff != "" {
		t.Fatalf("DecodeRaw grant_id mismatch (-want +got):\n%s", diff)
	}
}

func TestTokenGrantIDOmitted(t *testing.T) {
	var token Token
	if err := parseTokenResponse([]byte(`{"access_token":"at","token_type":"Bearer"}`), &token); err != nil {
		t.Fatalf("parseTokenResponse() failed: %v", err)
	}
	if token.GrantID != "" {
		t.Fatalf("GrantID = %q, want empty", token.GrantID)
	}
}

func TestTokenGrantIDMarshalRoundTrip(t *testing.T) {
	token := Token{
		AccessToken:  "at",
		TokenType:    "Bearer",
		RefreshToken: "rt",
		GrantID:      "TSdqirmAxDa0_-DB_1bASQ",
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded Token
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if diff := cmp.Diff("TSdqirmAxDa0_-DB_1bASQ", decoded.GrantID); diff != "" {
		t.Fatalf("GrantID round-trip mismatch (-want +got):\n%s", diff)
	}
}
