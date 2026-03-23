package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/Kunde21/lanyard/rp"
	rpstore "github.com/Kunde21/lanyard/rp/store"
)

type namespacedStateStore struct {
	base      rp.StateStore
	namespace string
}

func newNamespacedStateStore(base rp.StateStore, namespace string) *namespacedStateStore {
	trimmed := strings.TrimSpace(namespace)
	if trimmed == "" {
		trimmed = "default"
	}
	return &namespacedStateStore{base: base, namespace: trimmed}
}

func (s *namespacedStateStore) namespaceKey(state string) string {
	return s.namespace + ":" + state
}

func (s *namespacedStateStore) SaveCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string, correlation rpstore.CallbackCorrelation) error {
	return s.base.SaveCorrelation(ctx, w, req, s.namespaceKey(state), correlation)
}

func (s *namespacedStateStore) ConsumeCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) (rpstore.CallbackCorrelation, bool, error) {
	return s.base.ConsumeCorrelation(ctx, w, req, s.namespaceKey(state))
}

func (s *namespacedStateStore) LoadState(ctx context.Context, req *http.Request, state string) (rpstore.StateScope, bool, error) {
	return s.base.LoadState(ctx, req, s.namespaceKey(state))
}

func (s *namespacedStateStore) DeleteState(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) error {
	return s.base.DeleteState(ctx, w, req, s.namespaceKey(state))
}

func (s *namespacedStateStore) SaveValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string, value []byte) error {
	return s.base.SaveValue(ctx, w, req, s.namespaceKey(state), name, value)
}

func (s *namespacedStateStore) LoadValue(ctx context.Context, req *http.Request, state, name string) ([]byte, bool, error) {
	return s.base.LoadValue(ctx, req, s.namespaceKey(state), name)
}

func (s *namespacedStateStore) DeleteValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) error {
	return s.base.DeleteValue(ctx, w, req, s.namespaceKey(state), name)
}

func (s *namespacedStateStore) ConsumeValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) ([]byte, bool, error) {
	return s.base.ConsumeValue(ctx, w, req, s.namespaceKey(state), name)
}
