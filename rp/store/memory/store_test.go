package memory

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"
	"github.com/google/go-cmp/cmp"
)

var (
	_ rpstore.CorrelationStore = (*Store)(nil)
	_ rpstore.StateScopeStore  = (*Store)(nil)
	_ rpstore.ValueStore       = (*Store)(nil)
	_ rpstore.StateStore       = (*Store)(nil)
)

func TestStoreSaveLoadDeleteCorrelation(t *testing.T) {
	store := New(time.Minute)
	now := time.Now().UTC()
	want := rpstore.CallbackCorrelation{Nonce: "nonce", CodeVerifier: "verifier", CreatedAt: now}

	if err := store.SaveCorrelation(context.Background(), nil, nil, "state", want); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	scope, ok, err := store.LoadState(context.Background(), nil, "state")
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}
	if !ok {
		t.Fatalf("LoadState() expected state")
	}
	if diff := cmp.Diff(want, scope.Correlation); diff != "" {
		t.Fatalf("correlation mismatch (-want +got):\n%s", diff)
	}

	if err := store.DeleteState(context.Background(), nil, nil, "state"); err != nil {
		t.Fatalf("DeleteState() failed: %v", err)
	}
	if _, ok, err := store.LoadState(context.Background(), nil, "state"); err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	} else if ok {
		t.Fatalf("LoadState() expected deleted state to be absent")
	}
}

func TestStoreValueLifecycle(t *testing.T) {
	store := New(time.Minute)
	state := "state"
	name := "app.intent"
	want := []byte("opaque-value")

	if err := store.SaveValue(context.Background(), nil, nil, state, name, want); err != nil {
		t.Fatalf("SaveValue() failed: %v", err)
	}

	got, ok, err := store.LoadValue(context.Background(), nil, state, name)
	if err != nil {
		t.Fatalf("LoadValue() failed: %v", err)
	}
	if !ok {
		t.Fatalf("LoadValue() expected value")
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("value mismatch (-want +got):\n%s", diff)
	}

	consumed, ok, err := store.ConsumeValue(context.Background(), nil, nil, state, name)
	if err != nil {
		t.Fatalf("ConsumeValue() failed: %v", err)
	}
	if !ok {
		t.Fatalf("ConsumeValue() expected value")
	}
	if diff := cmp.Diff(want, consumed); diff != "" {
		t.Fatalf("consumed value mismatch (-want +got):\n%s", diff)
	}

	if _, ok, err := store.LoadValue(context.Background(), nil, state, name); err != nil {
		t.Fatalf("LoadValue() failed: %v", err)
	} else if ok {
		t.Fatalf("LoadValue() expected consumed value to be absent")
	}

	if err := store.SaveValue(context.Background(), nil, nil, state, name, want); err != nil {
		t.Fatalf("SaveValue() failed: %v", err)
	}
	if err := store.DeleteValue(context.Background(), nil, nil, state, name); err != nil {
		t.Fatalf("DeleteValue() failed: %v", err)
	}
	if _, ok, err := store.LoadValue(context.Background(), nil, state, name); err != nil {
		t.Fatalf("LoadValue() failed: %v", err)
	} else if ok {
		t.Fatalf("LoadValue() expected deleted value to be absent")
	}
}

func TestStoreLoadValueDistinguishesNilEmptyAndAbsent(t *testing.T) {
	store := New(time.Minute)
	ctx := context.Background()

	values := []struct {
		name string
		want []byte
	}{
		{name: "nil", want: nil},
		{name: "empty", want: []byte{}},
		{name: "ordinary", want: []byte("value")},
	}
	for _, value := range values {
		if err := store.SaveValue(ctx, nil, nil, "state", value.name, value.want); err != nil {
			t.Fatalf("SaveValue(%q) failed: %v", value.name, err)
		}
	}

	for _, tt := range values {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := store.LoadValue(ctx, nil, "state", tt.name)
			if err != nil {
				t.Fatalf("LoadValue() failed: %v", err)
			}
			if !ok {
				t.Fatal("LoadValue() expected stored value")
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("value mismatch (-want +got):\n%s", diff)
			}
		})
	}

	if got, ok, err := store.LoadValue(ctx, nil, "state", "absent"); err != nil {
		t.Fatalf("LoadValue(absent) failed: %v", err)
	} else if ok || got != nil {
		t.Fatalf("LoadValue(absent) = (%v, %t), want (nil, false)", got, ok)
	}
}

func TestStoreLoadValueConcurrentNilAndMissing(t *testing.T) {
	store := New(time.Minute)
	ctx := context.Background()
	const iterations = 1000

	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				var value []byte
				switch i % 3 {
				case 1:
					value = []byte{}
				case 2:
					value = []byte("value")
				}
				if err := store.SaveValue(ctx, nil, nil, "state", "name", value); err != nil {
					t.Errorf("SaveValue() failed: %v", err)
					return
				}
				if i%2 == 0 {
					if err := store.DeleteValue(ctx, nil, nil, "state", "name"); err != nil {
						t.Errorf("DeleteValue() failed: %v", err)
						return
					}
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, _, err := store.LoadValue(ctx, nil, "state", "name"); err != nil {
					t.Errorf("LoadValue() failed: %v", err)
					return
				}
				if _, _, err := store.LoadValue(ctx, nil, "state", "absent"); err != nil {
					t.Errorf("LoadValue(absent) failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestStoreConsumeCorrelationSingleUse(t *testing.T) {
	store := New(time.Minute)
	want := rpstore.CallbackCorrelation{Nonce: "nonce", CodeVerifier: "verifier", CreatedAt: time.Now().UTC()}

	if err := store.SaveCorrelation(context.Background(), nil, nil, "state", want); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	got, ok, err := store.ConsumeCorrelation(context.Background(), nil, nil, "state")
	if err != nil {
		t.Fatalf("ConsumeCorrelation() failed: %v", err)
	}
	if !ok {
		t.Fatalf("ConsumeCorrelation() expected state")
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("consumed correlation mismatch (-want +got):\n%s", diff)
	}

	if _, ok, err := store.ConsumeCorrelation(context.Background(), nil, nil, "state"); err != nil {
		t.Fatalf("ConsumeCorrelation() failed: %v", err)
	} else if ok {
		t.Fatalf("ConsumeCorrelation() expected state to be single use")
	}
}

func TestStoreTTLExpiry(t *testing.T) {
	store := New(20 * time.Millisecond)

	if err := store.SaveCorrelation(context.Background(), nil, nil, "state", rpstore.CallbackCorrelation{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}

	time.Sleep(40 * time.Millisecond)

	if _, ok, err := store.LoadState(context.Background(), nil, "state"); err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	} else if ok {
		t.Fatalf("LoadState() expected expired state to be absent")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	store := New(time.Second)

	const goroutines = 16
	const perRoutine = 50

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perRoutine; j++ {
				state := fmt.Sprintf("state-%d-%d", i, j)
				if err := store.SaveCorrelation(context.Background(), nil, nil, state, rpstore.CallbackCorrelation{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()}); err != nil {
					t.Errorf("SaveCorrelation() failed: %v", err)
					return
				}
				if _, _, err := store.LoadState(context.Background(), nil, state); err != nil {
					t.Errorf("LoadState() failed: %v", err)
					return
				}
				if err := store.SaveValue(context.Background(), nil, nil, state, "k", []byte("v")); err != nil {
					t.Errorf("SaveValue() failed: %v", err)
					return
				}
				if err := store.DeleteState(context.Background(), nil, nil, state); err != nil {
					t.Errorf("DeleteState() failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestCorrelationBrowserBinding: a correlation saved in one browser session
// cannot be consumed by a different one (login-CSRF, RC review F1).
func TestCorrelationBrowserBinding(t *testing.T) {
	store := New(time.Minute)

	// Attacker initiates login: binding cookie lands in the attacker's
	// browser.
	attackRec := httptest.NewRecorder()
	attackReq := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	if err := store.SaveCorrelation(context.Background(), attackRec, attackReq, "state-1",
		rpstore.CallbackCorrelation{Nonce: "n"}); err != nil {
		t.Fatalf("SaveCorrelation() failed: %v", err)
	}
	if len(attackRec.Header().Values("Set-Cookie")) == 0 {
		t.Fatal("binding cookie not set")
	}
	cookies := attackRec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("binding cookies = %d, want 1", len(cookies))
	}
	if diff := cmp.Diff(http.SameSiteNoneMode, cookies[0].SameSite); diff != "" {
		t.Fatalf("binding cookie SameSite mismatch (-want +got):\n%s", diff)
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("binding cookie flags = Secure:%t HttpOnly:%t, want both true", cookies[0].Secure, cookies[0].HttpOnly)
	}

	// Victim browser (no cookie) replays the attacker's callback URL:
	// rejected.
	victimRec := httptest.NewRecorder()
	victimReq := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", nil)
	if _, ok, _ := store.ConsumeCorrelation(context.Background(), victimRec, victimReq, "state-1"); ok {
		t.Fatal("correlation consumed without the binding cookie")
	}

	// A different browser's cookie is also rejected.
	otherReq := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", nil)
	otherReq.AddCookie(&http.Cookie{Name: "lanyard_state_binding", Value: "other-browser"})
	if _, ok, _ := store.ConsumeCorrelation(context.Background(), victimRec, otherReq, "state-1"); ok {
		t.Fatal("correlation consumed with a foreign binding cookie")
	}

	// The initiating browser succeeds.
	attackerCallbackReq := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", nil)
	for _, raw := range attackRec.Header().Values("Set-Cookie") {
		parts := strings.SplitN(raw, ";", 2)
		nameValue := strings.SplitN(parts[0], "=", 2)
		attackerCallbackReq.AddCookie(&http.Cookie{Name: nameValue[0], Value: nameValue[1]})
	}
	if _, ok, _ := store.ConsumeCorrelation(context.Background(), httptest.NewRecorder(), attackerCallbackReq, "state-1"); !ok {
		t.Fatal("correlation not consumable by the initiating browser")
	}
}

// TestCorrelationBrowserBindingRenewedForNearExpiryLogin verifies a reused
// browser binding is renewed for every newly saved correlation.
func TestCorrelationBrowserBindingRenewedForNearExpiryLogin(t *testing.T) {
	const ttl = 10 * time.Minute
	current := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store := New(ttl)
	store.now = func() time.Time { return current }

	firstResponse := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	if err := store.SaveCorrelation(context.Background(), firstResponse, firstRequest, "state-1",
		rpstore.CallbackCorrelation{Nonce: "first"}); err != nil {
		t.Fatalf("first SaveCorrelation() failed: %v", err)
	}
	firstCookies := firstResponse.Result().Cookies()
	if len(firstCookies) != 1 {
		t.Fatalf("first binding cookies = %d, want 1", len(firstCookies))
	}
	firstCookie := firstCookies[0]

	// Start another login shortly before the original browser binding expires.
	// The correlation remains valid longer than that original cookie would.
	current = current.Add(ttl + 30*time.Second)
	secondResponse := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodGet, "https://rp.test/login", nil)
	secondRequest.AddCookie(&http.Cookie{Name: firstCookie.Name, Value: firstCookie.Value})
	if err := store.SaveCorrelation(context.Background(), secondResponse, secondRequest, "state-2",
		rpstore.CallbackCorrelation{Nonce: "second"}); err != nil {
		t.Fatalf("second SaveCorrelation() failed: %v", err)
	}
	secondCookies := secondResponse.Result().Cookies()
	if len(secondCookies) != 1 {
		t.Fatalf("renewal binding cookies = %d, want 1", len(secondCookies))
	}
	renewed := secondCookies[0]
	if diff := cmp.Diff(firstCookie.Value, renewed.Value); diff != "" {
		t.Fatalf("renewed binding value mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(int((ttl + time.Minute).Seconds()), renewed.MaxAge); diff != "" {
		t.Fatalf("renewed MaxAge mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(current.Add(ttl+time.Minute), renewed.Expires); diff != "" {
		t.Fatalf("renewed Expires mismatch (-want +got):\n%s", diff)
	}
	if renewed.Path != "/" || !renewed.Secure || !renewed.HttpOnly || renewed.SameSite != http.SameSiteNoneMode {
		t.Fatalf("renewed cookie attributes = Path:%q Secure:%t HttpOnly:%t SameSite:%v",
			renewed.Path, renewed.Secure, renewed.HttpOnly, renewed.SameSite)
	}

	// This is after the original cookie's expiry but well within both the
	// renewed binding lifetime and the second correlation's TTL.
	current = current.Add(time.Minute)
	callbackRequest := httptest.NewRequest(http.MethodPost, "https://rp.test/callback", nil)
	callbackRequest.AddCookie(&http.Cookie{Name: renewed.Name, Value: renewed.Value})
	got, ok, err := store.ConsumeCorrelation(
		context.Background(), httptest.NewRecorder(), callbackRequest, "state-2",
	)
	if err != nil {
		t.Fatalf("ConsumeCorrelation() failed: %v", err)
	}
	if !ok {
		t.Fatal("second correlation was not consumable with renewed browser binding")
	}
	if diff := cmp.Diff("second", got.Nonce); diff != "" {
		t.Fatalf("Nonce mismatch (-want +got):\n%s", diff)
	}
}

// TestStoreSweepBoundsMemory verifies saving beyond capacity evicts expired
// and then soonest-to-expire entries (RC review F11).
func TestStoreSweepBoundsMemory(t *testing.T) {
	store := New(time.Minute)
	for i := 0; i < maxEntries+50; i++ {
		if err := store.SaveCorrelation(context.Background(), nil, nil,
			fmt.Sprintf("s-%d", i), rpstore.CallbackCorrelation{}); err != nil {
			t.Fatalf("SaveCorrelation() failed: %v", err)
		}
	}
	store.mu.RLock()
	size := len(store.items)
	store.mu.RUnlock()
	if size > maxEntries {
		t.Fatalf("store size = %d, want <= %d", size, maxEntries)
	}
}
