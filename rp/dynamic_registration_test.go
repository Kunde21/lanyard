package rp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestClientMetadataValidate(t *testing.T) {
	tests := []struct {
		name        string
		meta        ClientMetadata
		wantErrText string
	}{
		{
			name: "redirect uris present",
			meta: ClientMetadata{RedirectURIs: []string{"https://rp.test/callback"}},
		},
		{
			name: "client credentials only without redirect uris",
			meta: ClientMetadata{GrantTypes: []string{"client_credentials"}},
		},
		{
			name:        "authorization code without redirect uris",
			meta:        ClientMetadata{GrantTypes: []string{"authorization_code"}},
			wantErrText: "redirect_uris is required",
		},
		{
			name:        "empty metadata",
			meta:        ClientMetadata{},
			wantErrText: "redirect_uris is required",
		},
		{
			name: "jwks and jwks uri both set",
			meta: ClientMetadata{
				RedirectURIs: []string{"https://rp.test/callback"},
				JWKSURI:      "https://rp.test/jwks",
				JWKS:         json.RawMessage(`{"keys":[]}`),
			},
			wantErrText: "mutually exclusive",
		},
		{
			name: "jwks only",
			meta: ClientMetadata{
				RedirectURIs: []string{"https://rp.test/callback"},
				JWKS:         json.RawMessage(`{"keys":[]}`),
			},
		},
		{
			name: "jwks uri only",
			meta: ClientMetadata{
				RedirectURIs: []string{"https://rp.test/callback"},
				JWKSURI:      "https://rp.test/jwks",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.meta.validate()
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validate() = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("validate() = %v, want containing %q", err, tc.wantErrText)
			}
		})
	}
}

func TestClientRegistrationDecodeRFCExample(t *testing.T) {
	body := `{
		"client_id": "s6BhdRkqt3",
		"client_secret": "cf8DCbyUSm0boaf3wcbنبnb4H-3M",
		"client_id_issued_at": 1578861763,
		"client_secret_expires_at": 1578959163,
		"registration_access_token": "this.is.an.access.token.vffoiolkhlv.kryvyodkighodibevolui",
		"registration_client_uri": "https://server.example.com/register/s6BhdRkqt3",
		"client_id_issued_at_extra": null,
		"token_endpoint_auth_method": "none",
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"redirect_uris": ["https://client.example.org/callback",
			"https://client.example.org/callback2"],
		"client_name": "My Example Client",
		"client_uri": "https://client.example.org",
		"logo_uri": "https://client.example.org/logo.png",
		"scope": "read write dolphin",
		"contacts": ["admin@example.org", "dev@example.org"],
		"jwks_uri": "https://client.example.org/my_public_keys.jwks",
		"software_id": "4NRB1-0XZABZI9E6-5SM3R",
		"software_version": "2.1"
	}`

	var reg ClientRegistration
	if err := json.Unmarshal([]byte(body), &reg); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if diff := cmp.Diff("s6BhdRkqt3", reg.ClientID); diff != "" {
		t.Fatalf("ClientID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("none", string(reg.TokenEndpointAuthMethod)); diff != "" {
		t.Fatalf("TokenEndpointAuthMethod mismatch (-want +got):\n%s", diff)
	}
	if reg.ClientIDIssuedAt == nil || *reg.ClientIDIssuedAt != 1578861763 {
		t.Fatalf("ClientIDIssuedAt = %v, want 1578861763", reg.ClientIDIssuedAt)
	}
	if reg.ClientSecretExpiresAt == nil || *reg.ClientSecretExpiresAt != 1578959163 {
		t.Fatalf("ClientSecretExpiresAt = %v, want 1578959163", reg.ClientSecretExpiresAt)
	}
	if !reg.Manageable() {
		t.Fatal("Manageable() = false, want true (URI + access token issued)")
	}

	// Secret expires at 1578959163.
	if !reg.SecretExpired(time.Unix(1578959164, 0)) {
		t.Fatal("SecretExpired(at expiry+1) = false, want true")
	}
	if reg.SecretExpired(time.Unix(1578959162, 0)) {
		t.Fatal("SecretExpired(at expiry-1) = true, want false")
	}

	var extra struct {
		Scope string `json:"scope"`
	}
	if err := reg.DecodeRaw(&extra); err != nil {
		t.Fatalf("DecodeRaw() failed: %v", err)
	}
	if diff := cmp.Diff("read write dolphin", extra.Scope); diff != "" {
		t.Fatalf("DecodeRaw scope mismatch (-want +got):\n%s", diff)
	}
}

func TestClientRegistrationSecretExpirySemantics(t *testing.T) {
	now := time.Unix(1700000000, 0)

	var neverExpires ClientRegistration
	if neverExpires.SecretExpired(now) {
		t.Fatal("no secret: SecretExpired = true, want false")
	}

	expiresAt := int64(0)
	zeroMeansNever := ClientRegistration{ClientSecret: "s", ClientSecretExpiresAt: &expiresAt}
	if zeroMeansNever.SecretExpired(now) {
		t.Fatal("client_secret_expires_at=0: SecretExpired = true, want false (never expires)")
	}

	future := now.Unix() + 3600
	valid := ClientRegistration{ClientSecret: "s", ClientSecretExpiresAt: &future}
	if valid.SecretExpired(now) {
		t.Fatal("future expiry: SecretExpired = true, want false")
	}

	past := now.Unix() - 1
	expired := ClientRegistration{ClientSecret: "s", ClientSecretExpiresAt: &past}
	if !expired.SecretExpired(now) {
		t.Fatal("past expiry: SecretExpired = false, want true")
	}
}

func TestClientRegistrationManageableRequiresBoth(t *testing.T) {
	uriOnly := ClientRegistration{RegistrationClientURI: "https://server.test/register/c1"}
	if uriOnly.Manageable() {
		t.Fatal("Manageable() = true with URI only, want false")
	}
	tokenOnly := ClientRegistration{RegistrationAccessToken: "rat"}
	if tokenOnly.Manageable() {
		t.Fatal("Manageable() = true with token only, want false")
	}
}
