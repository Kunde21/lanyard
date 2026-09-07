package memory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"
)

const (
	defaultTTL = 10 * time.Minute

	// bindingCookieName binds a saved correlation to the browser session
	// that initiated the login, defeating cross-browser login-CSRF handoffs
	// (RC review F1).
	bindingCookieName = "lanyard_state_binding"

	// maxEntries bounds memory use; the sweep evicts expired entries first
	// and then the soonest-to-expire survivors (RC review F11).
	maxEntries = 4096
)

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
	binding     string
}

// New creates an in-memory state store. Correlations saved through an HTTP
// response are bound to the initiating browser via a cookie and can only be
// consumed by a request presenting that cookie.
func New(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = defaultTTL
	}

	return &Store{
		ttl:   ttl,
		items: make(map[string]stateEntry),
	}
}

// SaveCorrelation stores RP-managed callback correlation data. When a
// response writer and request are available, the correlation is bound to
// the browser session via a secure cookie.
func (s *Store) SaveCorrelation(_ context.Context, w http.ResponseWriter, r *http.Request, state string, correlation rpstore.CallbackCorrelation) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}

	now := time.Now().UTC()
	if correlation.CreatedAt.IsZero() {
		correlation.CreatedAt = now
	}

	binding := ""
	if w != nil && r != nil {
		binding = bindingCookieValue(r)
		if binding == "" {
			token := make([]byte, 32)
			if _, err := rand.Read(token); err != nil {
				return fmt.Errorf("generate state binding: %w", err)
			}
			binding = base64.RawURLEncoding.EncodeToString(token)
			http.SetCookie(w, &http.Cookie{
				Name:     bindingCookieName,
				Value:    binding,
				Path:     "/",
				MaxAge:   int((s.ttl + time.Minute).Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteNoneMode,
			})
		}
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
	entry.binding = binding
	s.items[state] = entry
	s.sweepLocked()

	return nil
}

// ConsumeCorrelation atomically loads and removes callback correlation
// data. A correlation saved with browser binding is only consumed by a
// request presenting the same binding cookie.
func (s *Store) ConsumeCorrelation(_ context.Context, _ http.ResponseWriter, r *http.Request, state string) (rpstore.CallbackCorrelation, bool, error) {
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

	if entry.binding != "" && bindingCookieValue(r) != entry.binding {
		// Bound to a different (or absent) browser session: login-CSRF
		// handoff rejected. The entry stays for the legitimate browser.
		return rpstore.CallbackCorrelation{}, false, nil
	}

	delete(s.items, state)
	return entry.correlation, true, nil
}

func bindingCookieValue(r *http.Request) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(bindingCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// sweepLocked evicts expired entries and, when the store is over capacity,
// the soonest-to-expire survivors. Caller holds the write lock.
func (s *Store) sweepLocked() {
	now := time.Now().UTC()
	for key, entry := range s.items {
		if s.isExpired(entry, now) {
			delete(s.items, key)
		}
	}
	for len(s.items) > maxEntries {
		var oldestKey string
		var oldestExpiry time.Time
		for key, entry := range s.items {
			expiry := entry.createdAt.Add(s.ttl)
			if oldestKey == "" || expiry.Before(oldestExpiry) {
				oldestKey, oldestExpiry = key, expiry
			}
		}
		delete(s.items, oldestKey)
	}
}

// LoadState loads a state scope when present and not expired.
func (s *Store) LoadState(_ context.Context, _ *http.Request, state string) (rpstore.StateScope, bool, error) {
	if state == "" {
		return rpstore.StateScope{}, false, fmt.Errorf("state must not be empty")
	}

	// Clone while holding the read lock: SaveValue may mutate the entry's
	// value map concurrently (RC review F3).
	s.mu.RLock()
	entry, ok := s.items[state]
	var correlation rpstore.CallbackCorrelation
	var values map[string][]byte
	if ok {
		correlation = entry.correlation
		values = cloneValues(entry.values)
	}
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

	return rpstore.StateScope{Correlation: correlation, Values: values}, true, nil
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

	now := time.Now().UTC()
	s.mu.RLock()
	entry, statePresent := s.items[state]
	expired := statePresent && s.isExpired(entry, now)
	var value []byte
	var valuePresent bool
	if statePresent && !expired {
		stored, present := entry.values[name]
		value = cloneBytes(stored)
		valuePresent = present
	}
	s.mu.RUnlock()

	if !statePresent {
		return nil, false, nil
	}
	if expired {
		s.mu.Lock()
		if current, present := s.items[state]; present && s.isExpired(current, time.Now().UTC()) {
			delete(s.items, state)
		}
		s.mu.Unlock()
		return nil, false, nil
	}
	if !valuePresent {
		return nil, false, nil
	}

	return value, true, nil
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
	return c.Nonce == "" && c.CodeVerifier == "" && c.CreatedAt.IsZero() && c.Expiry.IsZero() && c.Issuer == "" && c.ClientID == "" && c.ClientSecret == "" && c.RequestURI == "" && !c.UsedPAR && len(c.Resources) == 0 && c.UserInfoTokenTransport == ""
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
