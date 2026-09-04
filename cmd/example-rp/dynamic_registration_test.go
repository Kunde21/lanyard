package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/rp"
	"github.com/google/go-cmp/cmp"
)

type stubRegistrar struct {
	reg       rp.ClientRegistration
	err       error
	gotMeta   rp.ClientMetadata
	gotCalled bool
}

func (s *stubRegistrar) Register(_ context.Context, meta rp.ClientMetadata) (rp.ClientRegistration, error) {
	s.gotCalled = true
	s.gotMeta = meta
	return s.reg, s.err
}

func serveRegisterWithRegistrar(t *testing.T, client registrar) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		handleRegisterWithBuild(w, r, func(*http.Request) (registrar, error) {
			return client, nil
		})
	}
}

func TestHandleRegisterDemo(t *testing.T) {
	stub := &stubRegistrar{
		reg: rp.ClientRegistration{
			ClientID:                "c1",
			ClientSecret:            "s1",
			RegistrationClientURI:   "https://issuer.test/register/c1",
			RegistrationAccessToken: "rat-1",
		},
	}
	handler := serveRegisterWithRegistrar(t, stub)

	req := httptest.NewRequest(http.MethodPost, "/register?client_name=My+Demo+Client", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if !stub.gotCalled {
		t.Fatal("registrar was not called")
	}
	if diff := cmp.Diff("My Demo Client", stub.gotMeta.ClientName); diff != "" {
		t.Fatalf("ClientName mismatch (-want +got):\n%s", diff)
	}
	if len(stub.gotMeta.RedirectURIs) != 1 {
		t.Fatalf("RedirectURIs = %v, want one entry", stub.gotMeta.RedirectURIs)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	if diff := cmp.Diff("c1", body["client_id"]); diff != "" {
		t.Fatalf("client_id mismatch (-want +got):\n%s", diff)
	}
	if body["manageable"] != true {
		t.Fatalf("manageable = %v, want true", body["manageable"])
	}
	if _, ok := body["registration_access_token"]; !ok {
		t.Fatal("registration_access_token missing from response")
	}
}

func TestHandleRegisterForm(t *testing.T) {
	stub := &stubRegistrar{}
	handler := serveRegisterWithRegistrar(t, stub)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Dynamic client registration") {
		t.Fatalf("body = %s, want form heading", w.Body.String())
	}
	if stub.gotCalled {
		t.Fatal("GET must not register")
	}
}

func TestHandleRegisterMethodNotAllowed(t *testing.T) {
	stub := &stubRegistrar{}
	handler := serveRegisterWithRegistrar(t, stub)

	req := httptest.NewRequest(http.MethodDelete, "/register", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if stub.gotCalled {
		t.Fatal("DELETE must not register")
	}
}

func TestHandleRegisterUpstreamErrors(t *testing.T) {
	oauthErr := &rp.OAuthError{Code: "invalid_redirect_uri", Status: 400}
	stub := &stubRegistrar{err: errors.Join(rp.ErrRegistrationFailed, oauthErr)}
	handler := serveRegisterWithRegistrar(t, stub)

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oauth error status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}

	plainFailure := &stubRegistrar{err: errors.Join(rp.ErrRegistrationFailed, errors.New("registration endpoint returned status 500: boom"))}
	handler = serveRegisterWithRegistrar(t, plainFailure)
	req = httptest.NewRequest(http.MethodPost, "/register", nil)
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("plain failure status = %d, want 502 (body: %s)", w.Code, w.Body.String())
	}
}

func TestHandleRegisterBuildFailure(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		handleRegisterWithBuild(w, r, func(*http.Request) (registrar, error) {
			return nil, errors.New("issuer not reachable")
		})
	}

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
}
