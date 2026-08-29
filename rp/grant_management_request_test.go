package rp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGrantManagementRequestValidate(t *testing.T) {
	tests := []struct {
		name          string
		grant         *grantManagementRequest
		expectedError error
		message       string
	}{
		{
			name:  "create without grant id",
			grant: &grantManagementRequest{action: GrantActionCreate},
		},
		{
			name:          "create with grant id",
			grant:         &grantManagementRequest{action: GrantActionCreate, grantID: "TSdqirmAxDa0"},
			expectedError: ErrInvalidConfiguration,
			message:       "must not be combined",
		},
		{
			name:  "merge with grant id",
			grant: &grantManagementRequest{action: GrantActionMerge, grantID: "TSdqirmAxDa0"},
		},
		{
			name:  "update with grant id",
			grant: &grantManagementRequest{action: GrantActionUpdate, grantID: "TSdqirmAxDa0"},
		},
		{
			name:  "replace with grant id",
			grant: &grantManagementRequest{action: GrantActionReplace, grantID: "TSdqirmAxDa0"},
		},
		{
			name:          "merge without grant id",
			grant:         &grantManagementRequest{action: GrantActionMerge},
			expectedError: ErrInvalidConfiguration,
			message:       "requires grant_id",
		},
		{
			name:          "unknown action",
			grant:         &grantManagementRequest{action: GrantManagementAction("delete"), grantID: "TSdqirmAxDa0"},
			expectedError: ErrInvalidConfiguration,
			message:       "unknown grant_management_action",
		},
		{
			name:  "grant id alone",
			grant: &grantManagementRequest{grantID: "TSdqirmAxDa0"},
		},
		{
			name:  "nil request",
			grant: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.grant.validate()
			if tc.expectedError == nil {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.expectedError) {
				t.Fatalf("validate() = %v, want %v", err, tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("validate() = %v, want message containing %q", err, tc.message)
			}
		})
	}
}

func TestGrantManagementRequestValidateSupported(t *testing.T) {
	tests := []struct {
		name          string
		action        GrantManagementAction
		supported     []string
		expectedError bool
	}{
		{name: "merge advertised", action: GrantActionMerge, supported: []string{"query", "merge", "revoke"}},
		{name: "merge matched via update alias", action: GrantActionMerge, supported: []string{"query", "update", "revoke"}},
		{name: "update matched via merge alias", action: GrantActionUpdate, supported: []string{"merge"}},
		{name: "update exact", action: GrantActionUpdate, supported: []string{"update"}},
		{name: "create advertised", action: GrantActionCreate, supported: []string{"create"}},
		{name: "action not advertised", action: GrantActionReplace, supported: []string{"query", "revoke"}, expectedError: true},
		{name: "no metadata imposes no restriction", action: GrantActionReplace, supported: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			grant := &grantManagementRequest{action: tc.action, grantID: "TSdqirmAxDa0"}
			err := grant.validateSupported(tc.supported)
			if tc.expectedError && err == nil {
				t.Fatal("validateSupported() = nil, want error")
			}
			if !tc.expectedError && err != nil {
				t.Fatalf("validateSupported() = %v, want nil", err)
			}
		})
	}
}

func TestBuildAuthorizationParametersGrantManagement(t *testing.T) {
	r := &RP{clientConfig: clientConfig{clientID: "client-123"}}

	params := r.buildAuthorizationParameters("state", "nonce", "verifier", "challenge", "", nil,
		&grantManagementRequest{action: GrantActionMerge, grantID: "TSdqirmAxDa0"}, nil)
	if diff := cmp.Diff("merge", params.Get("grant_management_action")); diff != "" {
		t.Fatalf("grant_management_action mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("TSdqirmAxDa0", params.Get("grant_id")); diff != "" {
		t.Fatalf("grant_id mismatch (-want +got):\n%s", diff)
	}

	params = r.buildAuthorizationParameters("state", "nonce", "verifier", "challenge", "", nil, nil, nil)
	if params.Get("grant_management_action") != "" || params.Get("grant_id") != "" {
		t.Fatal("expected no grant management parameters for nil request")
	}
}

func TestSetGrantManagementActionValidation(t *testing.T) {
	build := func(opts ...AuthorizationURLOption) authorizationURLConfig {
		cfg := authorizationURLConfig{}
		for _, opt := range opts {
			if opt != nil {
				opt(&cfg)
			}
		}
		return cfg
	}

	cfg := build(SetGrantManagementAction(GrantActionCreate, ""))
	if cfg.err != nil {
		t.Fatalf("SetGrantManagementAction(create) err = %v, want nil", cfg.err)
	}
	if cfg.grantManagement == nil || cfg.grantManagement.action != GrantActionCreate {
		t.Fatalf("grantManagement = %+v, want create", cfg.grantManagement)
	}

	cfg = build(SetGrantManagementAction(GrantActionCreate, "some-grant"))
	if !errors.Is(cfg.err, ErrInvalidConfiguration) {
		t.Fatalf("SetGrantManagementAction(create, grant) err = %v, want ErrInvalidConfiguration", cfg.err)
	}

	cfg = build(SetGrantManagementAction(GrantActionMerge, ""))
	if !errors.Is(cfg.err, ErrInvalidConfiguration) {
		t.Fatalf("SetGrantManagementAction(merge, \"\") err = %v, want ErrInvalidConfiguration", cfg.err)
	}

	cfg = build(SetGrantID("  "))
	if !errors.Is(cfg.err, ErrInvalidConfiguration) {
		t.Fatalf("SetGrantID(\"\") err = %v, want ErrInvalidConfiguration", cfg.err)
	}

	cfg = build(SetGrantID("TSdqirmAxDa0"))
	if cfg.err != nil {
		t.Fatalf("SetGrantID err = %v, want nil", cfg.err)
	}
	if cfg.grantManagement == nil || cfg.grantManagement.grantID != "TSdqirmAxDa0" || cfg.grantManagement.action != "" {
		t.Fatalf("grantManagement = %+v, want grant id only", cfg.grantManagement)
	}
}

func TestBuildSignedRequestObjectGrantManagementClaims(t *testing.T) {
	r := &RP{
		clientConfig: clientConfig{
			clientID:     "client-123",
			clientSecret: "a-very-secret-secret-0123456789abcdef",
			scopes:       []string{"openid"},
			now:          func() time.Time { return time.Unix(1700000000, 0).UTC() },
			randReader:   strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.test/callback",
	}

	signed, err := r.buildSignedRequestObject("state", "nonce", "challenge", "", nil,
		&grantManagementRequest{action: GrantActionReplace, grantID: "TSdqirmAxDa0"}, nil)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	payload := strings.Split(signed, ".")[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if diff := cmp.Diff("TSdqirmAxDa0", claims["grant_id"]); diff != "" {
		t.Fatalf("grant_id claim mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("replace", claims["grant_management_action"]); diff != "" {
		t.Fatalf("grant_management_action claim mismatch (-want +got):\n%s", diff)
	}
}

func TestGrantManagementExtraParametersNotDuplicated(t *testing.T) {
	r := &RP{
		clientConfig: clientConfig{
			clientID:     "client-123",
			clientSecret: "a-very-secret-secret-0123456789abcdef",
			now:          func() time.Time { return time.Unix(1700000000, 0).UTC() },
			randReader:   strings.NewReader("01234567890123456789012345678901"),
		},
		redirectURI: "https://rp.test/callback",
	}

	extra := url.Values{"grant_id": {"injected-via-extra"}}
	signed, err := r.buildSignedRequestObject("state", "nonce", "challenge", "", nil,
		&grantManagementRequest{action: GrantActionMerge, grantID: "canonical"}, extra)
	if err != nil {
		t.Fatalf("buildSignedRequestObject() failed: %v", err)
	}

	payload := strings.Split(signed, ".")[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if diff := cmp.Diff("canonical", claims["grant_id"]); diff != "" {
		t.Fatalf("grant_id claim mismatch (-want +got):\n%s", diff)
	}
}
