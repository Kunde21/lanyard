package rp

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryStateStore_SaveLoadDelete(t *testing.T) {
	store := NewMemoryStateStore(time.Minute)
	data := StateData{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()}

	store.Save("s", data)

	got, ok := store.Load("s")
	if !ok {
		t.Fatalf("Load() expected state")
	}
	if got.Nonce != data.Nonce || got.CodeVerifier != data.CodeVerifier {
		t.Fatalf("Load() mismatch: got %+v want %+v", got, data)
	}

	store.Delete("s")
	if _, ok := store.Load("s"); ok {
		t.Fatalf("Load() expected deleted state to be absent")
	}
}

func TestMemoryStateStore_TTLExpiry(t *testing.T) {
	store := NewMemoryStateStore(20 * time.Millisecond)
	store.Save("s", StateData{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()})

	time.Sleep(40 * time.Millisecond)

	if _, ok := store.Load("s"); ok {
		t.Fatalf("Load() expected expired state to be absent")
	}
}

func TestMemoryStateStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStateStore(time.Second)
	const goroutines = 16
	const perRoutine = 50

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perRoutine; j++ {
				state := fmt.Sprintf("s-%d-%d", i, j)
				store.Save(state, StateData{Nonce: "n", CodeVerifier: "v", CreatedAt: time.Now().UTC()})
				_, _ = store.Load(state)
				store.Delete(state)
			}
		}()
	}
	wg.Wait()
}
