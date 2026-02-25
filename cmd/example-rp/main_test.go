package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/rp"
)

type stubFlow struct {
	authURL      string
	authErr      error
	callbackErr  error
	callbackResp *rp.CallbackResult
}

func (s stubFlow) AuthorizationURL(_ context.Context) (string, error) {
	return s.authURL, s.authErr
}

func (s stubFlow) HandleCallback(_ context.Context, _, _ string) (*rp.CallbackResult, error) {
	if s.callbackResp != nil {
		return s.callbackResp, s.callbackErr
	}
	return &rp.CallbackResult{Subject: "sub"}, s.callbackErr
}

func TestRoot(t *testing.T) {
	h := newMuxForTest(stubFlow{authURL: "https://issuer.test/authorize"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/login") {
		t.Fatalf("expected /login link in response body")
	}
}

func TestLoginRedirects(t *testing.T) {
	h := newMuxForTest(stubFlow{authURL: "https://issuer.test/authorize?x=1"})
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got == "" {
		t.Fatalf("Location header missing")
	}
}

func TestCallbackMissingParams(t *testing.T) {
	h := newMuxForTest(stubFlow{})
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "secret") {
		t.Fatalf("response must not leak sensitive content")
	}
}

func TestCallbackInvalidState(t *testing.T) {
	h := newMuxForTest(stubFlow{callbackErr: fmt.Errorf("wrapped: %w", rp.ErrInvalidState)})
	req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=s", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got %d", w.Code)
	}
}

func TestCallbackErrorMappingAndNoSecrets(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "token error", err: fmt.Errorf("token failed: %w", rp.ErrTokenExchangeFailed)},
		{name: "id token error", err: fmt.Errorf("id token failed: %w", rp.ErrIDTokenValidationFailed)},
		{name: "userinfo error", err: fmt.Errorf("userinfo failed: %w", rp.ErrUserInfoValidationFailed)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newMuxForTest(stubFlow{callbackErr: tt.err})
			req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=s", nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status mismatch: got %d", w.Code)
			}
			if strings.Contains(strings.ToLower(w.Body.String()), "secret") || strings.Contains(strings.ToLower(w.Body.String()), "token") {
				t.Fatalf("response body should not expose sensitive details")
			}
		})
	}
}

func TestParseScopesEnv(t *testing.T) {
	t.Run("uses fallback when unset", func(t *testing.T) {
		fallback := []string{"openid", "profile"}
		got := parseScopesEnv("RP_SCOPES_TEST", fallback)
		if strings.Join(got, " ") != "openid profile" {
			t.Fatalf("unexpected fallback scopes: %v", got)
		}
	})

	t.Run("parses comma and space separated values and deduplicates", func(t *testing.T) {
		t.Setenv("RP_SCOPES_TEST", "openid, profile email openid")
		got := parseScopesEnv("RP_SCOPES_TEST", []string{"openid"})
		if strings.Join(got, " ") != "openid profile email" {
			t.Fatalf("unexpected parsed scopes: %v", got)
		}
	})
}

func TestWebFingerResourceBuilders(t *testing.T) {
	issuer := "https://suite.test/test/a/lanyard-local/"

	acct, err := webFingerAcctResource(issuer)
	if err != nil {
		t.Fatalf("webFingerAcctResource() failed: %v", err)
	}
	if acct != "acct:lanyard-local.oidcc-client-test-discovery-webfinger-acct@suite.test" {
		t.Fatalf("acct resource mismatch: %q", acct)
	}

	resourceURL, err := webFingerURLResource(issuer)
	if err != nil {
		t.Fatalf("webFingerURLResource() failed: %v", err)
	}
	if resourceURL != "https://suite.test/lanyard-local/oidcc-client-test-discovery-webfinger-url" {
		t.Fatalf("url resource mismatch: %q", resourceURL)
	}
}
