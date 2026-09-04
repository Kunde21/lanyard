package rp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kunde21/lanyard/metadata"
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

func newRegistrarTestServer(t *testing.T, handler http.HandlerFunc) (*Registrar, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     "https://issuer.test/token",
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			RegistrationEndpoint:              server.URL + "/register",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	g, err := NewRegistrar(
		context.Background(),
		"https://issuer.test",
		WithProviderMetadata(provider),
		WithHTTPClient(server.Client()),
	)
	if err != nil {
		t.Fatalf("NewRegistrar() failed: %v", err)
	}
	return g, server.URL
}

func TestRegistrar_Register(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotContentType string
	var gotBody map[string]any
	g, _ := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth, gotContentType = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{
			"client_id": "s6BhdRkqt3",
			"client_secret": "cf8DCbyUSm0boaf3",
			"registration_access_token": "rat-1",
			"registration_client_uri": "https://issuer.test/register/s6BhdRkqt3",
			"client_id_issued_at": 1700000000,
			"redirect_uris": ["https://rp.test/callback"]
		}`)
	})

	reg, err := g.Register(context.Background(), ClientMetadata{
		RedirectURIs: []string{"https://rp.test/callback"},
		ClientName:   "demo",
		GrantTypes:   []string{"authorization_code"},
	})
	if err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	if gotMethod != http.MethodPost || gotPath != "/register" {
		t.Fatalf("request = %s %s, want POST /register", gotMethod, gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty without initial token", gotAuth)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	if diff := cmp.Diff("https://rp.test/callback", gotBody["redirect_uris"].([]any)[0]); diff != "" {
		t.Fatalf("request redirect_uris mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff("s6BhdRkqt3", reg.ClientID); diff != "" {
		t.Fatalf("ClientID mismatch (-want +got):\n%s", diff)
	}
	if !reg.Manageable() {
		t.Fatal("Manageable() = false, want true")
	}
}

func TestRegistrar_RegisterWithInitialAccessToken(t *testing.T) {
	var gotAuth string
	g, _ := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"client_id":"c1"}`)
	})

	_, err := g.Register(context.Background(), ClientMetadata{RedirectURIs: []string{"https://rp.test/cb"}})
	if err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty (option not set)", gotAuth)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"client_id":"c1"}`)
	}))
	defer server.Close()
	g2, err := NewRegistrar(context.Background(), "https://issuer.test",
		WithProviderMetadata(metadata.Provider{
			AuthorizationServer: metadata.AuthorizationServer{
				Issuer:               "https://issuer.test",
				RegistrationEndpoint: server.URL,
			},
		}),
		WithHTTPClient(server.Client()),
		WithInitialAccessToken("initial-token"),
	)
	if err != nil {
		t.Fatalf("NewRegistrar() failed: %v", err)
	}
	if _, err := g2.Register(context.Background(), ClientMetadata{RedirectURIs: []string{"https://rp.test/cb"}}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	if diff := cmp.Diff("Bearer initial-token", gotAuth); diff != "" {
		t.Fatalf("Authorization mismatch (-want +got):\n%s", diff)
	}
}

func TestRegistrar_RegisterErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantCode   string
	}{
		{name: "invalid redirect uri", statusCode: http.StatusBadRequest, body: `{"error":"invalid_redirect_uri"}`, wantCode: "invalid_redirect_uri"},
		{name: "invalid client metadata", statusCode: http.StatusBadRequest, body: `{"error":"invalid_client_metadata","error_description":"bad name"}`, wantCode: "invalid_client_metadata"},
		{name: "invalid software statement", statusCode: http.StatusBadRequest, body: `{"error":"invalid_software_statement"}`, wantCode: "invalid_software_statement"},
		{name: "unapproved software statement", statusCode: http.StatusBadRequest, body: `{"error":"unapproved_software_statement"}`, wantCode: "unapproved_software_statement"},
		{name: "server error", statusCode: http.StatusInternalServerError, body: `oops`},
		{name: "wrong success status", statusCode: http.StatusOK, body: `{"client_id":"c1"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := g.Register(context.Background(), ClientMetadata{RedirectURIs: []string{"https://rp.test/cb"}})
			if !errors.Is(err, ErrRegistrationFailed) {
				t.Fatalf("Register() error = %v, want ErrRegistrationFailed", err)
			}
			if tc.wantCode != "" {
				var oauthErr *OAuthError
				if !errors.As(err, &oauthErr) {
					t.Fatalf("Register() error = %v, want *OAuthError", err)
				}
				if diff := cmp.Diff(tc.wantCode, oauthErr.Code); diff != "" {
					t.Fatalf("OAuthError.Code mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestRegistrar_RegisterInvalidMetadata(t *testing.T) {
	g, _ := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream call")
	})
	_, err := g.Register(context.Background(), ClientMetadata{})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Register() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestNewRegistrar_RequiresRegistrationEndpoint(t *testing.T) {
	_, err := NewRegistrar(context.Background(), "https://issuer.test",
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:        "https://issuer.test",
			TokenEndpoint: "https://issuer.test/token",
		}}),
	)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewRegistrar() error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "registration endpoint") {
		t.Fatalf("NewRegistrar() error = %v, want endpoint message", err)
	}
}

func TestRegistrar_Read(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	g, base := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"client_id":"c1","client_secret":"rotated-secret"}`)
	})

	reg, err := g.Read(context.Background(), base+"/register/c1", "rat-1")
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/register/c1" {
		t.Fatalf("request = %s %s, want GET /register/c1", gotMethod, gotPath)
	}
	if diff := cmp.Diff("Bearer rat-1", gotAuth); diff != "" {
		t.Fatalf("Authorization mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("rotated-secret", reg.ClientSecret); diff != "" {
		t.Fatalf("ClientSecret mismatch (-want +got):\n%s", diff)
	}
}

func TestRegistrar_UpdateRotatesSecret(t *testing.T) {
	var gotMethod string
	var gotBody map[string]any
	g, base := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"client_id":"c1","client_secret":"fresh-secret","client_secret_expires_at":0}`)
	})

	reg, err := g.Update(context.Background(), base+"/register/c1", "rat-1", ClientUpdate{
		ClientMetadata: ClientMetadata{RedirectURIs: []string{"https://rp.test/cb2"}},
		ClientID:       "c1",
	})
	if err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %s, want PUT", gotMethod)
	}
	if diff := cmp.Diff("c1", gotBody["client_id"]); diff != "" {
		t.Fatalf("PUT body client_id mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("fresh-secret", reg.ClientSecret); diff != "" {
		t.Fatalf("rotated ClientSecret mismatch (-want +got):\n%s", diff)
	}
	if reg.SecretExpired(time.Now()) {
		t.Fatal("SecretExpired = true, want false for expires_at 0")
	}
}

func TestRegistrar_UpdateRequiresClientID(t *testing.T) {
	g, _ := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream call")
	})
	_, err := g.Update(context.Background(), "https://issuer.test/register/c1", "rat-1", ClientUpdate{
		ClientMetadata: ClientMetadata{RedirectURIs: []string{"https://rp.test/cb"}},
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Update() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestRegistrar_Delete(t *testing.T) {
	var gotMethod string
	g, base := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	})

	if err := g.Delete(context.Background(), base+"/register/c1", "rat-1"); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method = %s, want DELETE", gotMethod)
	}
}

func TestRegistrar_DeleteNotFound(t *testing.T) {
	g, base := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	err := g.Delete(context.Background(), base+"/register/c1", "rat-1")
	if !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("Delete() error = %v, want ErrRegistrationFailed", err)
	}
}

func TestRegistrar_ManagementArgValidation(t *testing.T) {
	g, _ := newRegistrarTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream call")
	})

	if _, err := g.Read(context.Background(), "http://insecure.test/register/c1", "rat"); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("Read(insecure URI) error = %v, want ErrRegistrationFailed", err)
	}
	if _, err := g.Read(context.Background(), "https://issuer.test/register/c1", "  "); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("Read(empty token) error = %v, want ErrRegistrationFailed", err)
	}
	if err := g.Delete(context.Background(), "not-a-url", "rat"); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("Delete(bad URI) error = %v, want ErrRegistrationFailed", err)
	}
}
