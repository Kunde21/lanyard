package rp

import (
	"sync"
	"time"
)

// MemoryStateStore stores state data in memory.
type MemoryStateStore struct {
	mu    sync.RWMutex
	ttl   time.Duration
	items map[string]StateData
}

// NewMemoryStateStore creates an in-memory state store.
func NewMemoryStateStore(ttl time.Duration) *MemoryStateStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	return &MemoryStateStore{
		ttl:   ttl,
		items: make(map[string]StateData),
	}
}

// Save stores state data.
func (s *MemoryStateStore) Save(state string, data StateData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[state] = data
}

// Load returns state data if present and not expired.
func (s *MemoryStateStore) Load(state string) (StateData, bool) {
	s.mu.RLock()
	data, ok := s.items[state]
	s.mu.RUnlock()
	if !ok {
		return StateData{}, false
	}

	if data.CreatedAt.Add(s.ttl).Before(time.Now().UTC()) {
		s.Delete(state)
		return StateData{}, false
	}

	return data, true
}

// Delete removes state data.
func (s *MemoryStateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.items, state)
}
