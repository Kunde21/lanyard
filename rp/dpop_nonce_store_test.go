package rp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestDPoPNonceStore_Get_MissesWhenEmpty(t *testing.T) {
	store := newDPoPNonceStore(5 * time.Minute)
	if _, ok := store.get("https://issuer.test/token"); ok {
		t.Fatal("expected cache miss on empty store")
	}
}

func TestDPoPNonceStore_PutAndGet(t *testing.T) {
	store := newDPoPNonceStore(5 * time.Minute)
	store.put("https://issuer.test/token", "nonce-abc")

	got, ok := store.get("https://issuer.test/token")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if diff := cmp.Diff("nonce-abc", got); diff != "" {
		t.Fatalf("nonce mismatch (-want +got):\n%s", diff)
	}
}

func TestDPoPNonceStore_Get_MissesAfterExpiry(t *testing.T) {
	now := time.Now()
	store := newDPoPNonceStore(5 * time.Minute)
	store.now = func() time.Time { return now }

	store.put("https://issuer.test/token", "nonce-old")
	store.now = func() time.Time { return now.Add(6 * time.Minute) }

	if _, ok := store.get("https://issuer.test/token"); ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestDPoPNonceStore_Put_OverwritesExisting(t *testing.T) {
	store := newDPoPNonceStore(5 * time.Minute)
	store.put("https://issuer.test/token", "nonce-1")
	store.put("https://issuer.test/token", "nonce-2")

	got, ok := store.get("https://issuer.test/token")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if diff := cmp.Diff("nonce-2", got); diff != "" {
		t.Fatalf("nonce mismatch (-want +got):\n%s", diff)
	}
}

func TestDPoPNonceStore_DifferentEndpoints(t *testing.T) {
	store := newDPoPNonceStore(5 * time.Minute)
	store.put("https://issuer.test/token", "nonce-token")
	store.put("https://issuer.test/userinfo", "nonce-userinfo")

	gotToken, ok := store.get("https://issuer.test/token")
	if !ok || gotToken != "nonce-token" {
		t.Fatalf("token endpoint nonce: got %q, ok %v", gotToken, ok)
	}

	gotUI, ok := store.get("https://issuer.test/userinfo")
	if !ok || gotUI != "nonce-userinfo" {
		t.Fatalf("userinfo endpoint nonce: got %q, ok %v", gotUI, ok)
	}
}

func TestDPoPNonceStore_Delete(t *testing.T) {
	store := newDPoPNonceStore(5 * time.Minute)
	store.put("https://issuer.test/token", "nonce-1")
	store.delete("https://issuer.test/token")

	if _, ok := store.get("https://issuer.test/token"); ok {
		t.Fatal("expected cache miss after delete")
	}
}

func TestDPoPNonceStore_Get_HitsWithinTTL(t *testing.T) {
	now := time.Now()
	store := newDPoPNonceStore(5 * time.Minute)
	store.now = func() time.Time { return now }

	store.put("https://issuer.test/token", "nonce-1")
	store.now = func() time.Time { return now.Add(4*time.Minute + 59*time.Second) }

	got, ok := store.get("https://issuer.test/token")
	if !ok {
		t.Fatal("expected cache hit within TTL")
	}
	if diff := cmp.Diff("nonce-1", got); diff != "" {
		t.Fatalf("nonce mismatch (-want +got):\n%s", diff)
	}
}
