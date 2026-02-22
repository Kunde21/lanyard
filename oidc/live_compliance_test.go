package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

type liveProvider struct {
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
}

func TestLiveProviders(t *testing.T) {
	if os.Getenv("LANYARD_LIVE_TESTS") != "1" {
		t.Skip("set LANYARD_LIVE_TESTS=1 to run live compliance test")
	}

	data, err := os.ReadFile("testdata/providers.json")
	if err != nil {
		t.Fatalf("ReadFile(providers.json) failed: %v", err)
	}

	var providers []liveProvider
	if err := json.Unmarshal(data, &providers); err != nil {
		t.Fatalf("Unmarshal(providers.json) failed: %v", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	client := NewClient(WithHTTPClient(httpClient))

	for _, provider := range providers {
		provider := provider
		t.Run(provider.Name, func(t *testing.T) {
			metadata, discoverErr := client.DiscoverProvider(context.Background(), provider.Issuer)
			if discoverErr != nil {
				t.Fatalf("DiscoverProvider(%q) failed: %v", provider.Issuer, discoverErr)
			}
			if metadata.Issuer == "" || metadata.JWKSURI == "" {
				t.Fatalf("provider metadata missing required fields: issuer=%q jwks_uri=%q", metadata.Issuer, metadata.JWKSURI)
			}
		})
	}
}
