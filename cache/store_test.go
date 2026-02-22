package cache

import (
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStoreGetSetDelete(t *testing.T) {
	store := NewStore[int]()
	store.Set("a", 42)

	got, ok := store.Get("a")
	if !ok {
		t.Fatalf("Get(a) did not find value")
	}
	if diff := cmp.Diff(42, got); diff != "" {
		t.Fatalf("Get(a) mismatch (-want +got):\n%s", diff)
	}

	store.Delete("a")
	_, ok = store.Get("a")
	if ok {
		t.Fatalf("Get(a) should not find value after delete")
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	store := NewStore[int]()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			store.Set("k", v)
			_, _ = store.Get("k")
		}(i)
	}

	wg.Wait()
}
