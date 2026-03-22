package cookie

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"
	"github.com/google/go-cmp/cmp"
)

func TestStoreSaveWritesCookieAndLoadsCorrelation(t *testing.T) {
	store, err := New([]byte("01234567890123456789012345678901"), []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	state := "state-1"
	createdAt := time.Now().UTC().Truncate(time.Second)
	want := rpstore.CallbackCorrelation{
		Nonce:                  "nonce-1",
		CodeVerifier:           "verifier-1",
		CreatedAt:              createdAt,
		Issuer:                 "https://issuer.test",
		UserInfoTokenTransport: "header",
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil)
	rec := httptest.NewRecorder()
	if err := store.SaveCorrelation(context.Background(), rec, req, state, want); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	setCookies := rec.Result().Cookies()
	if len(setCookies) == 0 {
		t.Fatalf("SaveCorrelation() expected Set-Cookie header")
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	addCookies(req2, setCookies)
	scope, ok, err := store.LoadState(context.Background(), req2, state)
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}
	if !ok {
		t.Fatalf("LoadState() expected stored state")
	}
	if diff := cmp.Diff(want, scope.Correlation); diff != "" {
		t.Fatalf("LoadState() correlation mismatch (-want +got):\n%s", diff)
	}
}

func TestStoreValueLifecycle(t *testing.T) {
	store, err := New([]byte("01234567890123456789012345678901"), []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	state := "state-1"
	name := "app.payload"
	value := []byte("opaque-value")

	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil)
	rec := httptest.NewRecorder()
	if err := store.SaveValue(context.Background(), rec, req, state, name, value); err != nil {
		t.Fatalf("SaveValue() failed: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	addCookies(req2, rec.Result().Cookies())
	got, ok, err := store.LoadValue(context.Background(), req2, state, name)
	if err != nil {
		t.Fatalf("LoadValue() failed: %v", err)
	}
	if !ok {
		t.Fatalf("LoadValue() expected value")
	}
	if diff := cmp.Diff(value, got); diff != "" {
		t.Fatalf("LoadValue() mismatch (-want +got):\n%s", diff)
	}

	rec2 := httptest.NewRecorder()
	if err := store.DeleteValue(context.Background(), rec2, req2, state, name); err != nil {
		t.Fatalf("DeleteValue() failed: %v", err)
	}

	req3 := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	addCookies(req3, rec2.Result().Cookies())
	if _, ok, err := store.LoadValue(context.Background(), req3, state, name); err != nil {
		t.Fatalf("LoadValue() failed: %v", err)
	} else if ok {
		t.Fatalf("LoadValue() expected deleted value to be absent")
	}
}

func TestStoreConsumeCorrelationSingleUse(t *testing.T) {
	store, err := New([]byte("01234567890123456789012345678901"), []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	state := "state-1"
	correlation := rpstore.CallbackCorrelation{Nonce: "nonce", CodeVerifier: "verifier", CreatedAt: time.Now().UTC()}

	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil)
	rec := httptest.NewRecorder()
	if err := store.SaveCorrelation(context.Background(), rec, req, state, correlation); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	addCookies(req2, rec.Result().Cookies())
	rec2 := httptest.NewRecorder()
	if _, ok, err := store.ConsumeCorrelation(context.Background(), rec2, req2, state); err != nil {
		t.Fatalf("ConsumeCorrelation() failed: %v", err)
	} else if !ok {
		t.Fatalf("ConsumeCorrelation() expected state")
	}

	req3 := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	addCookies(req3, rec2.Result().Cookies())
	rec3 := httptest.NewRecorder()
	if _, ok, err := store.ConsumeCorrelation(context.Background(), rec3, req3, state); err != nil {
		t.Fatalf("ConsumeCorrelation() failed: %v", err)
	} else if ok {
		t.Fatalf("ConsumeCorrelation() expected single-use state")
	}
}

func TestStoreTamperedSessionReturnsError(t *testing.T) {
	store, err := New([]byte("01234567890123456789012345678901"), []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil)
	rec := httptest.NewRecorder()
	if err := store.SaveCorrelation(context.Background(), rec, req, "state", rpstore.CallbackCorrelation{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}
	tampered := *cookies[0]
	tampered.Value += "tamper"

	req2 := httptest.NewRequest(http.MethodGet, "https://rp.localhost/callback", nil)
	req2.AddCookie(&tampered)
	if _, _, err := store.LoadState(context.Background(), req2, "state"); err == nil {
		t.Fatalf("LoadState() expected error for tampered cookie")
	}
}

func TestStoreSecureDefaults(t *testing.T) {
	store, err := New([]byte("01234567890123456789012345678901"), []byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://rp.localhost/login", nil)
	rec := httptest.NewRecorder()
	if err := store.SaveCorrelation(context.Background(), rec, req, "state", rpstore.CallbackCorrelation{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie")
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Fatalf("HttpOnly should be enabled by default")
	}
	if !c.Secure {
		t.Fatalf("Secure should be enabled by default")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite mismatch: got %v", c.SameSite)
	}
	if c.MaxAge <= 0 {
		t.Fatalf("MaxAge should be positive by default, got %d", c.MaxAge)
	}
}

func addCookies(req *http.Request, cookies []*http.Cookie) {
	for _, c := range cookies {
		req.AddCookie(c)
	}
}
