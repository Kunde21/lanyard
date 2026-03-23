package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	rpstore "github.com/Kunde21/lanyard/rp/store"
	"github.com/google/go-cmp/cmp"
)

type recordingStateStore struct {
	savedStates []string
}

func (r *recordingStateStore) SaveCorrelation(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string, _ rpstore.CallbackCorrelation) error {
	r.savedStates = append(r.savedStates, state)
	return nil
}

func (r *recordingStateStore) ConsumeCorrelation(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string) (rpstore.CallbackCorrelation, bool, error) {
	r.savedStates = append(r.savedStates, state)
	return rpstore.CallbackCorrelation{}, false, nil
}

func (r *recordingStateStore) LoadState(_ context.Context, _ *http.Request, state string) (rpstore.StateScope, bool, error) {
	r.savedStates = append(r.savedStates, state)
	return rpstore.StateScope{}, false, nil
}

func (r *recordingStateStore) DeleteState(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string) error {
	r.savedStates = append(r.savedStates, state)
	return nil
}

func (r *recordingStateStore) SaveValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, state, _ string, _ []byte) error {
	r.savedStates = append(r.savedStates, state)
	return nil
}

func (r *recordingStateStore) LoadValue(_ context.Context, _ *http.Request, state, _ string) ([]byte, bool, error) {
	r.savedStates = append(r.savedStates, state)
	return nil, false, nil
}

func (r *recordingStateStore) DeleteValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, state, _ string) error {
	r.savedStates = append(r.savedStates, state)
	return nil
}

func (r *recordingStateStore) ConsumeValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, state, _ string) ([]byte, bool, error) {
	r.savedStates = append(r.savedStates, state)
	return nil, false, nil
}

func TestNamespacedStateStore_PrefixesStateKeys(t *testing.T) {
	base := &recordingStateStore{}
	store := newNamespacedStateStore(base, "alias-a")
	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	w := httptest.NewRecorder()

	if err := store.SaveCorrelation(context.Background(), w, req, "state-1", rpstore.CallbackCorrelation{}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}
	if err := store.SaveValue(context.Background(), w, req, "state-1", "nonce", []byte("value")); err != nil {
		t.Fatalf("SaveValue() failed: %v", err)
	}

	want := []string{"alias-a:state-1", "alias-a:state-1"}
	if diff := cmp.Diff(want, base.savedStates); diff != "" {
		t.Fatalf("namespaced state keys mismatch (-want +got):\n%s", diff)
	}
}

func TestNamespacedStateStore_DistinctNamespacesDoNotCollide(t *testing.T) {
	storeA := newNamespacedStateStore(&recordingStateStore{}, "alias-a")
	storeB := newNamespacedStateStore(&recordingStateStore{}, "alias-b")
	if gotA, gotB := storeA.namespaceKey("state-1"), storeB.namespaceKey("state-1"); gotA == gotB {
		t.Fatalf("namespaceKey collision: %q == %q", gotA, gotB)
	}
}
