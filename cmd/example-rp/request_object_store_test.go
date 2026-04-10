package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestRequestObjectStore_StoreAndLoad(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)
	id, err := store.Store("jwt-token")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	jwt, ok := store.Load(id)
	if !ok {
		t.Fatal("Load() = false, want true")
	}
	if diff := cmp.Diff("jwt-token", jwt); diff != "" {
		t.Fatalf("jwt mismatch (-want +got):\n%s", diff)
	}
}

func TestRequestObjectStore_LoadUnknownID(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)

	_, ok := store.Load("nonexistent")
	if ok {
		t.Fatal("Load() = true for unknown id, want false")
	}
}

func TestRequestObjectStore_ExpiredEntryReturnsFalse(t *testing.T) {
	store := newRequestObjectStore(1 * time.Millisecond)
	id, err := store.Store("jwt-token")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	_, ok := store.Load(id)
	if ok {
		t.Fatal("Load() = true for expired entry, want false")
	}
}

func TestRequestObjectStore_Remove(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)
	id, err := store.Store("jwt-token")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	store.Remove(id)

	_, ok := store.Load(id)
	if ok {
		t.Fatal("Load() = true after Remove(), want false")
	}
}

func TestRequestObjectStore_StoreGeneratesUniqueIDs(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)
	id1, err := store.Store("jwt1")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	id2, err := store.Store("jwt2")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	if id1 == id2 {
		t.Fatal("Store() generated duplicate IDs")
	}
}

func TestRequestObjectStore_StartCleanup(t *testing.T) {
	store := newRequestObjectStore(50 * time.Millisecond)
	store.StartCleanup(20 * time.Millisecond)

	if _, err := store.Store("will-expire"); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	if _, err := store.Store("also-will-expire"); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	store.mu.RLock()
	count := len(store.items)
	store.mu.RUnlock()

	if count != 0 {
		t.Fatalf("expected 0 items after cleanup, got %d", count)
	}
}

func TestRequestObjectStore_StoreReturnsErrorWhenRandomReadFails(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)
	oldReader := requestObjectIDReader
	requestObjectIDReader = errorReader{err: errors.New("boom")}
	defer func() {
		requestObjectIDReader = oldReader
	}()

	_, err := store.Store("jwt-token")
	if err == nil {
		t.Fatal("Store() error = nil, want non-nil")
	}
}

func TestHandleRequestObject_ValidIDReturnsJWT(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)
	id, err := store.Store("my-jwt-token")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/request/"+id, nil)
	rec := httptest.NewRecorder()
	handleRequestObject(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/jwt" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/jwt")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if diff := cmp.Diff("my-jwt-token", strings.TrimSpace(rec.Body.String())); diff != "" {
		t.Fatalf("body mismatch (-want +got):\n%s", diff)
	}
}

func TestHandleRequestObject_UnknownIDReturns404(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/request/nonexistent", nil)
	rec := httptest.NewRecorder()
	handleRequestObject(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleRequestObject_PostMethodReturns405(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)
	id, err := store.Store("jwt")
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/request/"+id, nil)
	rec := httptest.NewRecorder()
	handleRequestObject(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleRequestObject_EmptyIDReturns400(t *testing.T) {
	store := newRequestObjectStore(5 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/request/", nil)
	rec := httptest.NewRecorder()
	handleRequestObject(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}
