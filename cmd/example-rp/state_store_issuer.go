package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/Kunde21/lanyard/rp"
	rpstore "github.com/Kunde21/lanyard/rp/store"
)

type issuerShorthandStore struct {
	base      rp.StateStore
	resolver  func(alias string) (string, bool)
	extractor func(issuer string) (string, error)
}

func newIssuerShorthandStore(base rp.StateStore, resolver func(alias string) (string, bool), extractor func(issuer string) (string, error)) *issuerShorthandStore {
	return &issuerShorthandStore{base: base, resolver: resolver, extractor: extractor}
}

func (s *issuerShorthandStore) SaveCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string, correlation rpstore.CallbackCorrelation) error {
	short, err := s.extractor(correlation.Issuer)
	if err == nil && short != "" {
		correlation.Issuer = short
	}
	return s.base.SaveCorrelation(ctx, w, req, state, correlation)
}

func (s *issuerShorthandStore) ConsumeCorrelation(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) (rpstore.CallbackCorrelation, bool, error) {
	correlation, ok, err := s.base.ConsumeCorrelation(ctx, w, req, state)
	if err != nil || !ok {
		return correlation, ok, err
	}
	if alias := strings.TrimSpace(correlation.Issuer); alias != "" {
		if !strings.HasPrefix(alias, "https://") {
			if full, found := s.resolver(alias); found {
				correlation.Issuer = full
			}
		}
	}
	return correlation, true, nil
}

func (s *issuerShorthandStore) LoadState(ctx context.Context, req *http.Request, state string) (rpstore.StateScope, bool, error) {
	return s.base.LoadState(ctx, req, state)
}

func (s *issuerShorthandStore) DeleteState(ctx context.Context, w http.ResponseWriter, req *http.Request, state string) error {
	return s.base.DeleteState(ctx, w, req, state)
}

func (s *issuerShorthandStore) SaveValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string, value []byte) error {
	return s.base.SaveValue(ctx, w, req, state, name, value)
}

func (s *issuerShorthandStore) LoadValue(ctx context.Context, req *http.Request, state, name string) ([]byte, bool, error) {
	return s.base.LoadValue(ctx, req, state, name)
}

func (s *issuerShorthandStore) DeleteValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) error {
	return s.base.DeleteValue(ctx, w, req, state, name)
}

func (s *issuerShorthandStore) ConsumeValue(ctx context.Context, w http.ResponseWriter, req *http.Request, state, name string) ([]byte, bool, error) {
	return s.base.ConsumeValue(ctx, w, req, state, name)
}

func wrapWithIssuerShorthand(base rp.StateStore) rp.StateStore {
	return newIssuerShorthandStore(
		base,
		func(alias string) (string, bool) {
			cfg, ok := conformanceRuntimes.Lookup(alias)
			if !ok {
				return "", false
			}
			return cfg.Issuer, true
		},
		func(issuer string) (string, error) {
			alias, err := issuerAlias(issuer)
			if err != nil {
				return "", err
			}
			if _, ok := conformanceRuntimes.Lookup(alias); !ok {
				return "", nil
			}
			return alias, nil
		},
	)
}
