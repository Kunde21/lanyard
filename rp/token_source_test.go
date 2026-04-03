package rp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
