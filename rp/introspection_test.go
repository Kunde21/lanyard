package rp

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestIntrospectionResponse_UnmarshalPreservesRaw(t *testing.T) {
	data := []byte(`{"active":true,"scope":"read write","client_id":"client","aud":"https://api.example.com","custom":"value"}`)

	var got IntrospectionResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON() failed: %v", err)
	}

	want := IntrospectionResponse{
		Active:   true,
		Scope:    "read write",
		ClientID: "client",
		Aud:      audienceClaim{"https://api.example.com"},
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(IntrospectionResponse{})); diff != "" {
		t.Fatalf("IntrospectionResponse mismatch (-want +got):\n%s", diff)
	}

	var extra struct {
		Custom string `json:"custom"`
	}
	if err := got.DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("value", extra.Custom); diff != "" {
		t.Fatalf("custom field mismatch (-want +got):\n%s", diff)
	}
}

func TestIntrospectionResponse_UnmarshalAudArray(t *testing.T) {
	data := []byte(`{"active":true,"aud":["https://api.example.com","https://other.example.com"]}`)

	var got IntrospectionResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON() failed: %v", err)
	}

	want := audienceClaim{"https://api.example.com", "https://other.example.com"}
	if diff := cmp.Diff(want, got.Aud); diff != "" {
		t.Fatalf("Aud mismatch (-want +got):\n%s", diff)
	}
}

func TestIntrospectionResponse_RawJWT(t *testing.T) {
	resp := IntrospectionResponse{}
	if got := resp.RawJWT(); got != "" {
		t.Fatalf("RawJWT() = %q, want empty", got)
	}
}

func TestIntrospector_PublicAPISmoke(t *testing.T) {
	var _ = TokenTypeHintAccessToken
	var _ = TokenTypeHintRefreshToken
	var _ = IntrospectionRequest{Token: "token", TokenTypeHint: TokenTypeHintAccessToken}
	var _ = IntrospectionRequest{Token: "token", PreferJWTResponse: true}
	var _ = IntrospectionRequest{Token: "token", ExpectedJWTAudience: "https://rs.example.com"}
	var _ = (*Introspector)(nil)
}
