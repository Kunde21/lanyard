package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRuntimeRegistry_RegisterLookupDelete(t *testing.T) {
	registry := newRuntimeRegistry()
	entry := rpRuntimeConfig{
		Alias:                  "run-a",
		ClientID:               "client-a",
		ClientSecret:           "secret-a",
		RedirectURI:            "https://rp.localhost/callback",
		Scopes:                 []string{"openid", "profile"},
		Namespace:              "ns-a",
		UserInfoTokenTransport: "header",
	}

	if err := registry.Register(entry); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	got, ok := registry.Lookup("run-a")
	if !ok {
		t.Fatal("Lookup() returned ok=false, want true")
	}
	if diff := cmp.Diff(entry, got); diff != "" {
		t.Fatalf("Lookup() mismatch (-want +got):\n%s", diff)
	}

	byIssuer, ok := registry.LookupByIssuer("https://suite.localhost/test/a/run-a/")
	if !ok {
		t.Fatal("LookupByIssuer() returned ok=false, want true")
	}
	if diff := cmp.Diff(entry, byIssuer); diff != "" {
		t.Fatalf("LookupByIssuer() mismatch (-want +got):\n%s", diff)
	}

	registry.Delete("run-a")
	if _, ok := registry.Lookup("run-a"); ok {
		t.Fatal("Lookup() after Delete() returned ok=true, want false")
	}
}

func TestRuntimeRegistry_LookupByIssuerUnknownAlias(t *testing.T) {
	registry := newRuntimeRegistry()
	if _, ok := registry.LookupByIssuer("https://suite.localhost/test/a/unknown/"); ok {
		t.Fatal("LookupByIssuer() returned ok=true for unknown alias")
	}
}

func TestRuntimeRegistry_NamespaceDefaultsToAlias(t *testing.T) {
	registry := newRuntimeRegistry()
	entry := rpRuntimeConfig{Alias: "run-b", ClientID: "client-b", RedirectURI: "https://rp.localhost/callback"}
	if err := registry.Register(entry); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	got, ok := registry.Lookup("run-b")
	if !ok {
		t.Fatal("Lookup() returned ok=false, want true")
	}
	if got.Namespace != "run-b" {
		t.Fatalf("Namespace = %q, want %q", got.Namespace, "run-b")
	}
}
