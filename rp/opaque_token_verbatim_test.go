package rp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
)

// Regression coverage for the seventh RC review R1: opaque refresh-token
// values are credentials (RFC 6749 Appendix A.17, VSCHAR includes ASCII
// space) and must be stored and transmitted verbatim — never normalized by
// TrimSpace at a storage or send site.

const whitespaceBearingRefreshToken = " refresh-token "

// newOpaqueTokenServer serves the token endpoint for refresh grants and the
// introspection endpoint, recording the exact form values received and
// honoring only the exact fixture credential.
func newOpaqueTokenServer(t *testing.T, rotated string) (*httptest.Server, *[]url.Values) {
	t.Helper()
	var received []url.Values

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		received = append(received, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/introspect":
			if r.PostFormValue("token") == whitespaceBearingRefreshToken {
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
		default: // token endpoint
			if r.PostFormValue("grant_type") != "refresh_token" {
				http.Error(w, "unsupported", http.StatusBadRequest)
				return
			}
			switch r.PostFormValue("refresh_token") {
			case whitespaceBearingRefreshToken:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "at-1",
					"token_type":    "Bearer",
					"refresh_token": rotated,
				})
			case rotated:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "at-2",
					"token_type":   "Bearer",
				})
			default:
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			}
		}
	}))
	t.Cleanup(server.Close)
	return server, &received
}

func newOpaqueTokenRP(t *testing.T, server *httptest.Server) *RP {
	t.Helper()
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     server.URL,
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			IntrospectionEndpoint:             server.URL + "/introspect",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	r, err := New(
		context.Background(),
		"https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithRedirectURI("https://rp.test/callback"),
		WithHTTPClient(server.Client()),
		WithProviderMetadata(provider),
		WithAuthMethod(AuthMethodBasic),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return r
}

// TestRefreshTokenSourcePreservesOpaqueTokenExactBytes: constructor storage,
// wire transmission (direct refresh and source refresh send identical exact
// bytes), rotation adoption, persistence/reconstruction via
// CurrentRefreshToken, and Replace all preserve the credential verbatim.
func TestRefreshTokenSourcePreservesOpaqueTokenExactBytes(t *testing.T) {
	const rotated = " rotated-token "
	server, received := newOpaqueTokenServer(t, rotated)
	r := newOpaqueTokenRP(t, server)

	// Constructor stores the exact bytes.
	src, err := NewRefreshTokenSource(r, whitespaceBearingRefreshToken)
	if err != nil {
		t.Fatalf("NewRefreshTokenSource() failed: %v", err)
	}
	if got := src.CurrentRefreshToken(); got != whitespaceBearingRefreshToken {
		t.Fatalf("CurrentRefreshToken() = %q, want exact %q", got, whitespaceBearingRefreshToken)
	}

	// Direct refresh works with the exact credential.
	if _, err := r.RefreshToken(context.Background(), whitespaceBearingRefreshToken); err != nil {
		t.Fatalf("direct RefreshToken() failed: %v", err)
	}
	directSeen := (*received)[0].Get("refresh_token")

	// Source refresh sends identical exact bytes (equivalence with direct).
	token, err := src.Refresh(context.Background())
	if err != nil {
		t.Fatalf("source Refresh() failed: %v", err)
	}
	sourceSeen := (*received)[1].Get("refresh_token")
	if sourceSeen != whitespaceBearingRefreshToken || directSeen != whitespaceBearingRefreshToken {
		t.Fatalf("wire refresh_token: direct=%q source=%q, want exact %q", directSeen, sourceSeen, whitespaceBearingRefreshToken)
	}

	// Rotation adopts the rotated value verbatim (whitespace included).
	if token.RefreshToken != rotated {
		t.Fatalf("rotated Token.RefreshToken = %q, want exact %q", token.RefreshToken, rotated)
	}

	// Persistence/reconstruction: a new source from CurrentRefreshToken works.
	persisted, err := NewRefreshTokenSource(r, src.CurrentRefreshToken())
	if err != nil {
		t.Fatalf("NewRefreshTokenSource(reconstructed) failed: %v", err)
	}
	if _, err := persisted.Refresh(context.Background()); err != nil {
		t.Fatalf("reconstructed source Refresh() failed: %v", err)
	}
	if got := (*received)[2].Get("refresh_token"); got != rotated {
		t.Fatalf("reconstructed wire refresh_token = %q, want exact %q", got, rotated)
	}

	// Replace stores exact bytes too.
	src.Replace(" replaced-exact ")
	if got := src.CurrentRefreshToken(); got != " replaced-exact " {
		t.Fatalf("CurrentRefreshToken() after Replace = %q, want exact bytes preserved", got)
	}
}

// TestIntrospectionPreservesOpaqueTokenExactBytes: the introspection request
// transmits the token verbatim, including with a refresh_token hint, and a
// provider recognizing only the exact value reports it active.
func TestIntrospectionPreservesOpaqueTokenExactBytes(t *testing.T) {
	server, received := newOpaqueTokenServer(t, "unused")
	introspector, err := NewIntrospector(context.Background(), "https://issuer.test",
		WithClientID("client"),
		WithClientSecret("secret"),
		WithProviderMetadata(introspectionProvider(server.URL+"/introspect", "client_secret_basic")),
		WithHTTPClient(server.Client()),
	)
	if err != nil {
		t.Fatalf("NewIntrospector() failed: %v", err)
	}

	resp, err := introspector.IntrospectToken(context.Background(), IntrospectionRequest{
		Token:         whitespaceBearingRefreshToken,
		TokenTypeHint: TokenTypeHintRefreshToken,
	})
	if err != nil {
		t.Fatalf("IntrospectToken() failed: %v", err)
	}
	if !resp.Active {
		t.Fatal("IntrospectToken() reported inactive; provider only recognizes the exact byte value")
	}
	if got := (*received)[0].Get("token"); got != whitespaceBearingRefreshToken {
		t.Fatalf("wire token = %q, want exact %q", got, whitespaceBearingRefreshToken)
	}
	if got := (*received)[0].Get("token_type_hint"); got != string(TokenTypeHintRefreshToken) {
		t.Fatalf("wire token_type_hint = %q, want %q (hint normalization unchanged)", got, TokenTypeHintRefreshToken)
	}
}
