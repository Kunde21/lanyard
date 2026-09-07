package rp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestParseTokenResponse_PreservesRawPayloadAndFields(t *testing.T) {
	payload := []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"authorization_details":[{"type":"account_information"}],"txn":"tx-123"}`)

	var token Token
	if err := parseTokenResponse(payload, &token); err != nil {
		t.Fatalf("parseTokenResponse() failed: %v", err)
	}

	if diff := cmp.Diff("at", token.AccessToken); diff != "" {
		t.Fatalf("AccessToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(string(payload), string(token.raw)); diff != "" {
		t.Fatalf("Raw mismatch (-want +got):\n%s", diff)
	}

	var details struct {
		AuthorizationDetails []map[string]any `json:"authorization_details"`
	}
	if err := token.DecodeRaw(&details); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("account_information", details.AuthorizationDetails[0]["type"]); diff != "" {
		t.Fatalf("authorization_details mismatch (-want +got):\n%s", diff)
	}

	txn, err := token.Extra("txn")
	if err != nil {
		t.Fatalf("Extra() failed: %v", err)
	}
	if diff := cmp.Diff("tx-123", txn); diff != "" {
		t.Fatalf("txn mismatch (-want +got):\n%s", diff)
	}
}

func TestTokenJSONRoundTrip_PreservesRawPayload(t *testing.T) {
	stored := []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"raw":{"access_token":"at","token_type":"Bearer","expires_in":3600,"authorization_details":[{"type":"payment_initiation"}],"interaction_id":"ix-1"}}`)

	var token Token
	if err := json.Unmarshal(stored, &token); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	if diff := cmp.Diff(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"authorization_details":[{"type":"payment_initiation"}],"interaction_id":"ix-1"}`, string(token.raw)); diff != "" {
		t.Fatalf("Raw mismatch (-want +got):\n%s", diff)
	}
	interactionID, err := token.Extra("interaction_id")
	if err != nil {
		t.Fatalf("Extra() failed: %v", err)
	}
	if diff := cmp.Diff("ix-1", interactionID); diff != "" {
		t.Fatalf("interaction_id mismatch (-want +got):\n%s", diff)
	}

	reencoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	got := string(reencoded)
	if !strings.Contains(got, `"raw":`) {
		t.Fatalf("marshaled token must include raw payload, got %s", got)
	}
	if !strings.Contains(got, `"authorization_details"`) {
		t.Fatalf("marshaled token must preserve raw contents, got %s", got)
	}
}

func TestTokenStringField_ErrorsForMissingOrNonString(t *testing.T) {
	token := Token{raw: json.RawMessage(`{"count":1}`)}

	if _, err := token.Extra("missing"); err == nil {
		t.Fatal("Extra() expected error for missing field")
	}
	if _, err := token.Extra("count"); err == nil {
		t.Fatal("Extra() expected error for non-string field")
	}
}

func TestTokenUnmarshalJSON_OrdinaryProviderResponse(t *testing.T) {
	payload := []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"id","refresh_token":"rt","grant_id":"grant","scope":"openid profile","provider_extension":"kept"}`)

	var got Token
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	want := Token{
		AccessToken:  "at",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken:      "id",
		RefreshToken: "rt",
		GrantID:      "grant",
		Scope:        "openid profile",
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(Token{})); diff != "" {
		t.Fatalf("Token mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("kept", mustTokenExtra(t, got, "provider_extension")); diff != "" {
		t.Fatalf("provider extension mismatch (-want +got):\n%s", diff)
	}
}

func TestTokenUnmarshalJSON_RawOnlyLegacyPersistence(t *testing.T) {
	stored := []byte(`{"raw":{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"id","refresh_token":"rt","grant_id":"grant","scope":"openid profile","provider_extension":"kept"}}`)

	var got Token
	if err := json.Unmarshal(stored, &got); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	want := Token{
		AccessToken:  "at",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken:      "id",
		RefreshToken: "rt",
		GrantID:      "grant",
		Scope:        "openid profile",
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(Token{})); diff != "" {
		t.Fatalf("Token mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("kept", mustTokenExtra(t, got, "provider_extension")); diff != "" {
		t.Fatalf("provider extension mismatch (-want +got):\n%s", diff)
	}
}

func TestTokenJSONRoundTrip_ClearedFieldsRemainAuthoritative(t *testing.T) {
	payload := []byte(`{"access_token":"old-access","token_type":"Bearer","expires_in":3600,"id_token":"old-id","refresh_token":"old-refresh","grant_id":"old-grant","scope":"openid profile","provider_extension":"kept"}`)
	var token Token
	if err := json.Unmarshal(payload, &token); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	token.AccessToken = ""
	token.TokenType = ""
	token.ExpiresIn = 0
	token.IDToken = ""
	token.RefreshToken = ""
	token.GrantID = ""
	token.Scope = ""

	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode persisted envelope: %v", err)
	}
	for _, field := range []string{
		"access_token", "token_type", "expires_in", "id_token", "refresh_token", "grant_id", "scope",
	} {
		if _, ok := envelope[field]; !ok {
			t.Errorf("persisted envelope omitted cleared field %q: %s", field, encoded)
		}
	}

	var restored Token
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("round-trip json.Unmarshal() failed: %v", err)
	}
	if diff := cmp.Diff(Token{}, restored, cmpopts.IgnoreUnexported(Token{})); diff != "" {
		t.Fatalf("cleared Token mismatch (-want +got):\n%s", diff)
	}

	var original struct {
		AccessToken       string `json:"access_token"`
		TokenType         string `json:"token_type"`
		ExpiresIn         int64  `json:"expires_in"`
		IDToken           string `json:"id_token"`
		RefreshToken      string `json:"refresh_token"`
		GrantID           string `json:"grant_id"`
		Scope             string `json:"scope"`
		ProviderExtension string `json:"provider_extension"`
	}
	if err := restored.DecodeRaw(&original); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	wantOriginal := struct {
		AccessToken       string `json:"access_token"`
		TokenType         string `json:"token_type"`
		ExpiresIn         int64  `json:"expires_in"`
		IDToken           string `json:"id_token"`
		RefreshToken      string `json:"refresh_token"`
		GrantID           string `json:"grant_id"`
		Scope             string `json:"scope"`
		ProviderExtension string `json:"provider_extension"`
	}{
		AccessToken:       "old-access",
		TokenType:         "Bearer",
		ExpiresIn:         3600,
		IDToken:           "old-id",
		RefreshToken:      "old-refresh",
		GrantID:           "old-grant",
		Scope:             "openid profile",
		ProviderExtension: "kept",
	}
	if diff := cmp.Diff(wantOriginal, original); diff != "" {
		t.Fatalf("original raw payload mismatch (-want +got):\n%s", diff)
	}
}

func TestTokenJSONRoundTrip_NonzeroEditsBeatRawPayload(t *testing.T) {
	payload := []byte(`{"access_token":"old-access","token_type":"Bearer","expires_in":3600,"id_token":"old-id","refresh_token":"old-refresh","grant_id":"old-grant","scope":"old-scope","provider_extension":"kept"}`)
	var token Token
	if err := json.Unmarshal(payload, &token); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	want := Token{
		AccessToken:  "new-access",
		TokenType:    "DPoP",
		ExpiresIn:    90,
		IDToken:      "new-id",
		RefreshToken: "new-refresh",
		GrantID:      "new-grant",
		Scope:        "new-scope",
	}
	token.AccessToken = want.AccessToken
	token.TokenType = want.TokenType
	token.ExpiresIn = want.ExpiresIn
	token.IDToken = want.IDToken
	token.RefreshToken = want.RefreshToken
	token.GrantID = want.GrantID
	token.Scope = want.Scope

	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	var restored Token
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("round-trip json.Unmarshal() failed: %v", err)
	}
	if diff := cmp.Diff(want, restored, cmpopts.IgnoreUnexported(Token{})); diff != "" {
		t.Fatalf("edited Token mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("kept", mustTokenExtra(t, restored, "provider_extension")); diff != "" {
		t.Fatalf("provider extension mismatch (-want +got):\n%s", diff)
	}
}

func mustTokenExtra(t *testing.T, token Token, name string) string {
	t.Helper()
	value, err := token.Extra(name)
	if err != nil {
		t.Fatalf("Extra(%q) failed: %v", name, err)
	}
	return value
}
