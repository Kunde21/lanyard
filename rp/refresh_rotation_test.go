package rp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
)

func newRefreshRotationRP(t *testing.T, server *httptest.Server) *RP {
	t.Helper()
	provider := metadata.Provider{
		AuthorizationServer: metadata.AuthorizationServer{
			Issuer:                            "https://issuer.test",
			AuthorizationEndpoint:             "https://issuer.test/authorize",
			TokenEndpoint:                     server.URL,
			JWKSURI:                           "https://issuer.test/jwks",
			ResponseTypesSupported:            []string{"code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
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

func TestNewRefreshTokenSource_Validation(t *testing.T) {
	if _, err := NewRefreshTokenSource(nil, "rt"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewRefreshTokenSource(nil, ...) error = %v, want ErrInvalidConfiguration", err)
	}

	r := &RP{}
	if _, err := NewRefreshTokenSource(r, "  "); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewRefreshTokenSource(r, \"\") error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestRefreshTokenSource_TracksRotation(t *testing.T) {
	// strict server: every request must carry the token it was last issued.
	var mu sync.Mutex
	expected := "initial-refresh"
	rotated := []string{"r2", "", "r4"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("ParseQuery() failed: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if got := values.Get("refresh_token"); got != expected {
			t.Errorf("refresh_token = %q, want %q", got, expected)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		next := rotated[0]
		rotated = rotated[1:]
		if next != "" {
			expected = next
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "access-" + next,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: next,
		})
	}))
	defer server.Close()

	r := newRefreshRotationRP(t, server)
	src, err := NewRefreshTokenSource(r, "initial-refresh")
	if err != nil {
		t.Fatalf("NewRefreshTokenSource() failed: %v", err)
	}

	// 1st refresh: server rotates to r2.
	token, err := src.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if diff := cmp.Diff("r2", token.RefreshToken); diff != "" {
		t.Fatalf("RefreshToken mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("r2", src.CurrentRefreshToken()); diff != "" {
		t.Fatalf("CurrentRefreshToken() mismatch (-want +got):\n%s", diff)
	}

	// 2nd refresh: response omits refresh_token; source keeps r2.
	token, err = src.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if diff := cmp.Diff("r2", token.RefreshToken); diff != "" {
		t.Fatalf("RefreshToken mismatch after no-rotation (-want +got):\n%s", diff)
	}

	// 3rd refresh: server rotates to r4.
	if _, err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if diff := cmp.Diff("r4", src.CurrentRefreshToken()); diff != "" {
		t.Fatalf("CurrentRefreshToken() mismatch (-want +got):\n%s", diff)
	}
}

func TestRefreshTokenSource_RejectionSurfacesSentinel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "refresh token expired",
		})
	}))
	defer server.Close()

	r := newRefreshRotationRP(t, server)
	src, err := NewRefreshTokenSource(r, "stale-refresh")
	if err != nil {
		t.Fatalf("NewRefreshTokenSource() failed: %v", err)
	}

	_, err = src.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() expected error for rejected token")
	}
	if !errors.Is(err, ErrRefreshTokenFailed) {
		t.Fatalf("error = %v, want ErrRefreshTokenFailed", err)
	}
	if !errors.Is(err, ErrRefreshTokenRejected) {
		t.Fatalf("error = %v, want ErrRefreshTokenRejected", err)
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error = %v, want *OAuthError", err)
	}
	if diff := cmp.Diff("invalid_grant", oauthErr.Code); diff != "" {
		t.Fatalf("OAuthError.Code mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("refresh token expired", oauthErr.Description); diff != "" {
		t.Fatalf("OAuthError.Description mismatch (-want +got):\n%s", diff)
	}
}

func TestRefreshTokenSource_ConcurrentRefreshNeverReplays(t *testing.T) {
	// Strict rotating server: replays a previously used token with
	// invalid_grant (RFC 9700 family revocation). The serialized source must
	// never trip it.
	var mu sync.Mutex
	seen := map[string]bool{"initial-refresh": false}
	expected := "initial-refresh"
	counter := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("ParseQuery() failed: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		got := values.Get("refresh_token")
		mu.Lock()
		defer mu.Unlock()
		if got != expected {
			t.Errorf("replayed refresh token %q, want %q", got, expected)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		if seen[got] {
			t.Errorf("token %q was used twice", got)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		seen[got] = true
		counter++
		next := fmt.Sprintf("rt-%d", counter)
		expected = next
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Token{
			AccessToken:  "access-" + next,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: next,
		})
	}))
	defer server.Close()

	r := newRefreshRotationRP(t, server)
	src, err := NewRefreshTokenSource(r, "initial-refresh")
	if err != nil {
		t.Fatalf("NewRefreshTokenSource() failed: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := src.Refresh(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Refresh() failed: %v", err)
	}

	if want := fmt.Sprintf("rt-%d", counter); src.CurrentRefreshToken() != want {
		t.Fatalf("CurrentRefreshToken() = %q, want %q", src.CurrentRefreshToken(), want)
	}
}
