package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	rpstore "github.com/Kunde21/lanyard/rp/store"
	"github.com/google/go-cmp/cmp"
)

type issuerRecordingStateStore struct {
	savedState       string
	savedCorrelation rpstore.CallbackCorrelation

	consumeCorrelation rpstore.CallbackCorrelation
	consumeOK          bool
	consumeErr         error
}

func (s *issuerRecordingStateStore) SaveCorrelation(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string, correlation rpstore.CallbackCorrelation) error {
	s.savedState = state
	s.savedCorrelation = correlation
	return nil
}

func (s *issuerRecordingStateStore) ConsumeCorrelation(_ context.Context, _ http.ResponseWriter, _ *http.Request, _ string) (rpstore.CallbackCorrelation, bool, error) {
	return s.consumeCorrelation, s.consumeOK, s.consumeErr
}

func (s *issuerRecordingStateStore) LoadState(_ context.Context, _ *http.Request, _ string) (rpstore.StateScope, bool, error) {
	return rpstore.StateScope{}, false, nil
}

func (s *issuerRecordingStateStore) DeleteState(_ context.Context, _ http.ResponseWriter, _ *http.Request, _ string) error {
	return nil
}

func (s *issuerRecordingStateStore) SaveValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, _, _ string, _ []byte) error {
	return nil
}

func (s *issuerRecordingStateStore) LoadValue(_ context.Context, _ *http.Request, _, _ string) ([]byte, bool, error) {
	return nil, false, nil
}

func (s *issuerRecordingStateStore) DeleteValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, _, _ string) error {
	return nil
}

func (s *issuerRecordingStateStore) ConsumeValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, _, _ string) ([]byte, bool, error) {
	return nil, false, nil
}

func TestIssuerShorthandStore_SaveCorrelationStoresAlias(t *testing.T) {
	base := &issuerRecordingStateStore{}
	store := newIssuerShorthandStore(
		base,
		func(alias string) (string, bool) { return "", false },
		func(issuer string) (string, error) {
			if issuer != "https://suite.localhost/test/a/alias-a/" {
				t.Fatalf("extractor issuer = %q, want full issuer", issuer)
			}
			return "alias-a", nil
		},
	)

	err := store.SaveCorrelation(
		context.Background(),
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil),
		"state-1",
		rpstore.CallbackCorrelation{Issuer: "https://suite.localhost/test/a/alias-a/"},
	)
	if err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	if got := base.savedCorrelation.Issuer; got != "alias-a" {
		t.Fatalf("saved issuer = %q, want alias", got)
	}
	if got := base.savedState; got != "state-1" {
		t.Fatalf("saved state = %q, want state-1", got)
	}
}

func TestIssuerShorthandStore_ConsumeCorrelationRestoresIssuer(t *testing.T) {
	base := &issuerRecordingStateStore{
		consumeCorrelation: rpstore.CallbackCorrelation{Issuer: "alias-a"},
		consumeOK:          true,
	}
	store := newIssuerShorthandStore(
		base,
		func(alias string) (string, bool) {
			if alias != "alias-a" {
				t.Fatalf("resolver alias = %q, want alias-a", alias)
			}
			return "https://suite.localhost/test/a/alias-a/", true
		},
		func(string) (string, error) { return "", nil },
	)

	got, ok, err := store.ConsumeCorrelation(
		context.Background(),
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil),
		"state-1",
	)
	if err != nil {
		t.Fatalf("ConsumeCorrelation() failed: %v", err)
	}
	if !ok {
		t.Fatal("ConsumeCorrelation() ok = false, want true")
	}

	want := rpstore.CallbackCorrelation{Issuer: "https://suite.localhost/test/a/alias-a/"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ConsumeCorrelation() mismatch (-want +got):\n%s", diff)
	}
}

func TestResolveRPRequest_UsesIssuerAliasStateStoreForRegisteredRuntime(t *testing.T) {
	oldShared := sharedStateStore
	oldRuntimes := conformanceRuntimes
	t.Cleanup(func() {
		sharedStateStore = oldShared
		conformanceRuntimes = oldRuntimes
	})

	base := &issuerRecordingStateStore{}
	sharedStateStore = base
	conformanceRuntimes = newRuntimeRegistry()
	if err := conformanceRuntimes.Register(rpRuntimeConfig{
		Alias:        "alias-a",
		Issuer:       "https://suite.localhost/test/a/alias-a/",
		ClientID:     "client-a",
		ClientSecret: "secret-a",
		RedirectURI:  "https://rp.localhost/callback/alias-a",
		Namespace:    "ns-a",
		Scopes:       []string{"openid"},
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login?issuer=https://suite.localhost/test/a/alias-a/", nil)
	resolved, err := resolveRPRequest(req, "fallback-client", "fallback-secret", "https://rp.localhost/callback", "header")
	if err != nil {
		t.Fatalf("resolveRPRequest() failed: %v", err)
	}

	err = resolved.stateStore.SaveCorrelation(
		context.Background(),
		httptest.NewRecorder(),
		req,
		"state-1",
		rpstore.CallbackCorrelation{Issuer: "https://suite.localhost/test/a/alias-a/"},
	)
	if err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	if got := base.savedState; got != "ns-a:state-1" {
		t.Fatalf("saved state = %q, want namespaced state", got)
	}
	if got := base.savedCorrelation.Issuer; got != "alias-a" {
		t.Fatalf("saved issuer = %q, want alias shorthand", got)
	}
}
