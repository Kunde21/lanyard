package rp

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/Kunde21/lanyard/metadata"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNormalizeResources(t *testing.T) {
	tests := []struct {
		name            string
		resources       []string
		want            []string
		expectedError   error
		expectedMessage string
	}{
		{
			name:      "trims and preserves order",
			resources: []string{" https://api.example.com/ ", "https://payments.example.com"},
			want:      []string{"https://api.example.com/", "https://payments.example.com"},
		},
		{
			name:      "allows query component",
			resources: []string{"https://api.example.com/app?tenant=123"},
			want:      []string{"https://api.example.com/app?tenant=123"},
		},
		{
			name:            "rejects empty",
			resources:       []string{"   "},
			expectedError:   ErrInvalidConfiguration,
			expectedMessage: "resource must not be empty",
		},
		{
			name:            "rejects relative URI",
			resources:       []string{"api.example.com"},
			expectedError:   ErrInvalidConfiguration,
			expectedMessage: "resource must be an absolute URI",
		},
		{
			name:            "rejects fragment",
			resources:       []string{"https://api.example.com/#frag"},
			expectedError:   ErrInvalidConfiguration,
			expectedMessage: "resource must not include a fragment",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeResources(tc.resources)
			if tc.expectedError != nil {
				if !cmp.Equal(tc.expectedError, err, cmpopts.EquateErrors()) {
					t.Fatalf("normalizeResources() error = %v, want %v", err, tc.expectedError)
				}
				if !strings.Contains(err.Error(), tc.expectedMessage) {
					t.Fatalf("normalizeResources() error = %v, want message containing %q", err, tc.expectedMessage)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeResources() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("normalizeResources() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWithResourcesConfiguresDefaults(t *testing.T) {
	cfg := defaultClientConfig("https://issuer.example.com")
	WithResources(" https://api.example.com/ ", "https://payments.example.com/").applyConfig(&cfg)

	want := []string{"https://api.example.com/", "https://payments.example.com/"}
	if diff := cmp.Diff(want, cfg.resources); diff != "" {
		t.Fatalf("resources mismatch (-want +got):\n%s", diff)
	}
}

func TestWithResourcesRejectsInvalidResourceAtConstruction(t *testing.T) {
	_, err := NewClientCredentials(
		context.Background(),
		"https://issuer.example.com",
		WithClientID("client"),
		WithProviderMetadata(metadata.Provider{AuthorizationServer: metadata.AuthorizationServer{
			Issuer:        "https://issuer.example.com",
			TokenEndpoint: "https://issuer.example.com/token",
		}}),
		WithResources("not-a-uri"),
	)
	if !cmp.Equal(ErrInvalidConfiguration, err, cmpopts.EquateErrors()) {
		t.Fatalf("NewClientCredentials() error = %v, want ErrInvalidConfiguration", err)
	}
	if !strings.Contains(err.Error(), "resource must be an absolute URI") {
		t.Fatalf("NewClientCredentials() error = %v, want resource validation message", err)
	}
}

func TestWithTokenResourcesStoresContextResources(t *testing.T) {
	ctx := WithTokenResources(context.Background(), " https://api.example.com/ ")
	got := tokenResourcesFromContext(ctx)
	want := []string{"https://api.example.com/"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("token resources mismatch (-want +got):\n%s", diff)
	}
}

func TestAddResourceParameters(t *testing.T) {
	values := url.Values{}
	addResourceParameters(values, []string{"https://api.example.com/", "https://payments.example.com/"})

	want := []string{"https://api.example.com/", "https://payments.example.com/"}
	if diff := cmp.Diff(want, values["resource"]); diff != "" {
		t.Fatalf("resource values mismatch (-want +got):\n%s", diff)
	}
}

func TestNormalizeResources_NilInputReturnsNil(t *testing.T) {
	got, err := normalizeResources(nil)
	if err != nil {
		t.Fatalf("normalizeResources() unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("normalizeResources(nil) = %v, want nil", got)
	}
}

func TestAddResourceParameters_EmptyIsNoOp(t *testing.T) {
	values := url.Values{}
	addResourceParameters(values, nil)
	if len(values) > 0 {
		t.Fatalf("expected empty values, got %v", values)
	}
}
