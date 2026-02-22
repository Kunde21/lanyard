package cache

import "sync"

// Store is a generic in-memory cache.
// Store is safe for concurrent use.
type Store[V any] struct {
	mu   sync.RWMutex
	data map[string]V
}

// NewStore creates a new in-memory cache store.
func NewStore[V any]() *Store[V] {
	return &Store[V]{
		data: make(map[string]V),
	}
}

// Get returns a value by key.
func (s *Store[V]) Get(key string) (value V, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok = s.data[key]
	return value, ok
}

// Set stores a value by key.
func (s *Store[V]) Set(key string, value V) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = value
}

// Delete removes a value by key.
func (s *Store[V]) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
}
