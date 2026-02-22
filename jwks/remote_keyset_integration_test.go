package jwks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestRemoteKeySetRotationAndConditionalRefresh(t *testing.T) {
	set1, err := os.ReadFile("testdata/jwks_rotation_set1.json")
	if err != nil {
		t.Fatalf("ReadFile(set1) failed: %v", err)
	}
	set2, err := os.ReadFile("testdata/jwks_rotation_set2.json")
	if err != nil {
		t.Fatalf("ReadFile(set2) failed: %v", err)
	}

	type state struct {
		mu         sync.Mutex
		body       []byte
		etag       string
		calls      int
		lastIfNone string
	}

	s := &state{body: set1, etag: `"k1"`}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.calls++
		s.lastIfNone = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=1")
		w.Header().Set("ETag", s.etag)
		if s.lastIfNone != "" && s.lastIfNone == s.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(s.body)
	})
	server := httptest.NewTLSServer(h)
	defer server.Close()

	r, err := NewRemoteKeySet(
		server.URL,
		WithHTTPClient(server.Client()),
		WithDefaultTTL(100*time.Millisecond),
		WithMinRefreshInterval(0),
	)
	if err != nil {
		t.Fatalf("NewRemoteKeySet() failed: %v", err)
	}

	key1, err := r.Key(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("Key(kid-1) failed: %v", err)
	}
	if diff := cmp.Diff("kid-1", key1.KeyID); diff != "" {
		t.Fatalf("kid-1 mismatch (-want +got):\n%s", diff)
	}

	cacheKey := cacheKeyPrefix + server.URL
	entry, ok := r.cache.Get(cacheKey)
	if !ok || entry == nil {
		t.Fatalf("expected cache entry")
	}

	_, err = r.refresh(context.Background(), cacheKey, entry)
	if err != nil {
		t.Fatalf("refresh() failed: %v", err)
	}

	s.mu.Lock()
	ifNone := s.lastIfNone
	s.mu.Unlock()
	if diff := cmp.Diff(`"k1"`, ifNone); diff != "" {
		t.Fatalf("If-None-Match mismatch (-want +got):\n%s", diff)
	}

	s.mu.Lock()
	s.body = set2
	s.etag = `"k2"`
	s.mu.Unlock()

	key2, err := r.Key(context.Background(), "kid-2")
	if err != nil {
		t.Fatalf("Key(kid-2) failed: %v", err)
	}
	if diff := cmp.Diff("kid-2", key2.KeyID); diff != "" {
		t.Fatalf("kid-2 mismatch (-want +got):\n%s", diff)
	}
}

func TestRemoteKeySetSingleflightNoStampede(t *testing.T) {
	set1, err := os.ReadFile("testdata/jwks_rotation_set1.json")
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	var (
		mu    sync.Mutex
		calls int
	)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=30")
		_, _ = w.Write(set1)
	})
	server := httptest.NewTLSServer(h)
	defer server.Close()

	r, err := NewRemoteKeySet(server.URL, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("NewRemoteKeySet() failed: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, keyErr := r.Keys(context.Background())
			errCh <- keyErr
		}()
	}
	wg.Wait()
	close(errCh)

	for keyErr := range errCh {
		if keyErr != nil {
			t.Fatalf("Keys() failed: %v", keyErr)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if calls > 2 {
		t.Fatalf("expected no stampede, got %d upstream calls", calls)
	}

	if calls == 0 {
		t.Fatalf("expected at least one upstream call")
	}

	_ = fmt.Sprintf("calls=%d", calls)
}
