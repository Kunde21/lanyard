package memory

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"
)

const defaultTTL = 10 * time.Minute

// Store keeps RP state in process memory.
type Store struct {
	mu    sync.RWMutex
	ttl   time.Duration
	items map[string]stateEntry
}

type stateEntry struct {
	correlation rpstore.CallbackCorrelation
	values      map[string][]byte
	createdAt   time.Time
}

// New creates an in-memory state store.
func New(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = defaultTTL
	}

	return &Store{
		ttl:   ttl,
		items: make(map[string]stateEntry),
	}
}

// SaveCorrelation stores RP-managed callback correlation data.
func (s *Store) SaveCorrelation(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string, correlation rpstore.CallbackCorrelation) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}

	now := time.Now().UTC()
	if correlation.CreatedAt.IsZero() {
		correlation.CreatedAt = now
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.items[state]
	entry.correlation = correlation
	if entry.createdAt.IsZero() {
		entry.createdAt = correlation.CreatedAt
	}
	if entry.values == nil {
		entry.values = make(map[string][]byte)
	}
	s.items[state] = entry

	return nil
}

// ConsumeCorrelation atomically loads and removes callback correlation data.
func (s *Store) ConsumeCorrelation(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string) (rpstore.CallbackCorrelation, bool, error) {
	if state == "" {
		return rpstore.CallbackCorrelation{}, false, fmt.Errorf("state must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.items[state]
	if !ok {
		return rpstore.CallbackCorrelation{}, false, nil
	}
	if s.isExpired(entry, time.Now().UTC()) {
		delete(s.items, state)
		return rpstore.CallbackCorrelation{}, false, nil
	}

	delete(s.items, state)
	return entry.correlation, true, nil
}

// LoadState loads a state scope when present and not expired.
func (s *Store) LoadState(_ context.Context, _ *http.Request, state string) (rpstore.StateScope, bool, error) {
	if state == "" {
		return rpstore.StateScope{}, false, fmt.Errorf("state must not be empty")
	}

	s.mu.RLock()
	entry, ok := s.items[state]
	s.mu.RUnlock()
	if !ok {
		return rpstore.StateScope{}, false, nil
	}
	if s.isExpired(entry, time.Now().UTC()) {
		s.mu.Lock()
		delete(s.items, state)
		s.mu.Unlock()
		return rpstore.StateScope{}, false, nil
	}

	return rpstore.StateScope{Correlation: entry.correlation, Values: cloneValues(entry.values)}, true, nil
}

// DeleteState removes all data in a state scope.
func (s *Store) DeleteState(_ context.Context, _ http.ResponseWriter, _ *http.Request, state string) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.items, state)
	return nil
}

// SaveValue saves a caller-owned value in a state scope.
func (s *Store) SaveValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, state, name string, value []byte) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return fmt.Errorf("value name must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.items[state]
	if entry.createdAt.IsZero() {
		entry.createdAt = time.Now().UTC()
	}
	if entry.values == nil {
		entry.values = make(map[string][]byte)
	}
	entry.values[name] = cloneBytes(value)
	s.items[state] = entry

	return nil
}

// LoadValue loads a caller-owned value from a state scope.
func (s *Store) LoadValue(_ context.Context, _ *http.Request, state, name string) ([]byte, bool, error) {
	if state == "" {
		return nil, false, fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return nil, false, fmt.Errorf("value name must not be empty")
	}

	s.mu.RLock()
	entry, ok := s.items[state]
	s.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	if s.isExpired(entry, time.Now().UTC()) {
		s.mu.Lock()
		delete(s.items, state)
		s.mu.Unlock()
		return nil, false, nil
	}

	value, ok := entry.values[name]
	if !ok {
		return nil, false, nil
	}

	return cloneBytes(value), true, nil
}

// DeleteValue removes a caller-owned value from a state scope.
func (s *Store) DeleteValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, state, name string) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return fmt.Errorf("value name must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.items[state]
	if !ok {
		return nil
	}
	delete(entry.values, name)
	if len(entry.values) == 0 && isZeroCorrelation(entry.correlation) {
		delete(s.items, state)
		return nil
	}
	s.items[state] = entry

	return nil
}

// ConsumeValue atomically loads and removes a caller-owned value from a state scope.
func (s *Store) ConsumeValue(_ context.Context, _ http.ResponseWriter, _ *http.Request, state, name string) ([]byte, bool, error) {
	if state == "" {
		return nil, false, fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return nil, false, fmt.Errorf("value name must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.items[state]
	if !ok {
		return nil, false, nil
	}
	if s.isExpired(entry, time.Now().UTC()) {
		delete(s.items, state)
		return nil, false, nil
	}

	value, ok := entry.values[name]
	if !ok {
		return nil, false, nil
	}
	delete(entry.values, name)
	if len(entry.values) == 0 && isZeroCorrelation(entry.correlation) {
		delete(s.items, state)
		return cloneBytes(value), true, nil
	}
	s.items[state] = entry

	return cloneBytes(value), true, nil
}

func (s *Store) isExpired(entry stateEntry, now time.Time) bool {
	createdAt := entry.createdAt
	if !entry.correlation.CreatedAt.IsZero() {
		createdAt = entry.correlation.CreatedAt
	}
	if !createdAt.IsZero() && createdAt.Add(s.ttl).Before(now) {
		return true
	}

	if !entry.correlation.Expiry.IsZero() && entry.correlation.Expiry.Before(now) {
		return true
	}

	return false
}

func isZeroCorrelation(c rpstore.CallbackCorrelation) bool {
	return c == (rpstore.CallbackCorrelation{})
}

func cloneValues(values map[string][]byte) map[string][]byte {
	if len(values) == 0 {
		return map[string][]byte{}
	}

	cloned := make(map[string][]byte, len(values))
	for k, v := range values {
		cloned[k] = cloneBytes(v)
	}
	return cloned
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}

	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}
