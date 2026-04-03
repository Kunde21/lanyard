package rp

import (
	"sync"
	"time"
)

type dpopNonceEntry struct {
	nonce     string
	createdAt time.Time
}

type dpopNonceStore struct {
	mu  sync.RWMutex
	ttl time.Duration
	now func() time.Time
	m   map[string]dpopNonceEntry
}

func newDPoPNonceStore(ttl time.Duration) *dpopNonceStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &dpopNonceStore{
		ttl: ttl,
		now: time.Now,
		m:   make(map[string]dpopNonceEntry),
	}
}

func (s *dpopNonceStore) get(endpoint string) (string, bool) {
	s.mu.RLock()
	entry, ok := s.m[endpoint]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	if s.now().Sub(entry.createdAt) > s.ttl {
		s.mu.Lock()
		delete(s.m, endpoint)
		s.mu.Unlock()
		return "", false
	}
	return entry.nonce, true
}

func (s *dpopNonceStore) put(endpoint, nonce string) {
	s.mu.Lock()
	s.m[endpoint] = dpopNonceEntry{nonce: nonce, createdAt: s.now()}
	s.mu.Unlock()
}

func (s *dpopNonceStore) delete(endpoint string) {
	s.mu.Lock()
	delete(s.m, endpoint)
	s.mu.Unlock()
}
