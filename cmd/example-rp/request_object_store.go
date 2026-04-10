package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type requestObjectEntry struct {
	jwt       string
	expiresAt time.Time
}

type requestObjectStore struct {
	mu    sync.RWMutex
	items map[string]*requestObjectEntry
	ttl   time.Duration
}

func newRequestObjectStore(ttl time.Duration) *requestObjectStore {
	return &requestObjectStore{
		items: make(map[string]*requestObjectEntry),
		ttl:   ttl,
	}
}

func (s *requestObjectStore) Store(jwt string) string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	id := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	s.items[id] = &requestObjectEntry{
		jwt:       jwt,
		expiresAt: time.Now().Add(s.ttl),
	}
	s.mu.Unlock()

	return id
}

func (s *requestObjectStore) Load(id string) (string, bool) {
	s.mu.RLock()
	entry, ok := s.items[id]
	s.mu.RUnlock()

	if !ok {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		s.mu.Lock()
		delete(s.items, id)
		s.mu.Unlock()
		return "", false
	}

	return entry.jwt, true
}

func (s *requestObjectStore) Remove(id string) {
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
}

func (s *requestObjectStore) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.mu.Lock()
			now := time.Now()
			for id, entry := range s.items {
				if now.After(entry.expiresAt) {
					delete(s.items, id)
				}
			}
			s.mu.Unlock()
		}
	}()
}
