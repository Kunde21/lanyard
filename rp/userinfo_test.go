package rp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchUserInfo(t *testing.T) {
	var gotAuth string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"sub-123","name":"Alice"}`)
	}))
	defer ts.Close()

	r, err := New("https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got, err := r.fetchUserInfo(context.Background(), ts.URL, "access-token", "sub-123")
	if err != nil {
		t.Fatalf("fetchUserInfo() failed: %v", err)
	}
	if gotAuth != "Bearer access-token" {
		t.Fatalf("Authorization header mismatch: %q", gotAuth)
	}
	if got["name"] != "Alice" {
		t.Fatalf("userinfo payload mismatch")
	}
}

func TestFetchUserInfoErrors(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		expectFail bool
	}{
		{name: "non-200", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "bad", http.StatusBadRequest) }, expectFail: true},
		{name: "invalid json", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "{") }, expectFail: true},
		{name: "sub mismatch", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, `{"sub":"other"}`) }, expectFail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(tt.handler)
			defer ts.Close()

			r, err := New("https://issuer.test", "client", "secret", "https://rp.test/callback", WithHTTPClient(ts.Client()))
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			_, err = r.fetchUserInfo(context.Background(), ts.URL, "token", "sub-123")
			if tt.expectFail && err == nil {
				t.Fatalf("fetchUserInfo() expected error")
			}
			if err != nil && !strings.Contains(err.Error(), ErrUserInfoValidationFailed.Error()) {
				t.Fatalf("error mismatch: %v", err)
			}
		})
	}
}
