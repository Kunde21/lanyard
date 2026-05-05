package cookie

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	rpstore "github.com/Kunde21/lanyard/rp/store"
	"github.com/gorilla/sessions"
)

const payloadVersion = 1

// Store persists RP state inside a signed/encrypted gorilla session cookie.
//
// The payload is intentionally small and optimized for browser callback correlation,
// not for large arbitrary session data.
type Store struct {
	sessionName string
	payloadKey  string
	ttl         time.Duration

	cookieOptions sessions.Options
	now           func() time.Time

	store          *sessions.CookieStore
	configureStore []func(*sessions.CookieStore)
}

type payload struct {
	Version int                     `json:"version"`
	States  map[string]payloadState `json:"states,omitempty"`
}

type payloadState struct {
	Correlation *payloadCorrelation `json:"correlation,omitempty"`
	Values      map[string]string   `json:"values,omitempty"`
	CreatedAt   int64               `json:"created_at,omitempty"`
}

type payloadCorrelation struct {
	Nonce                  string   `json:"nonce,omitempty"`
	CodeVerifier           string   `json:"code_verifier,omitempty"`
	CreatedAt              int64    `json:"created_at,omitempty"`
	Expiry                 int64    `json:"expiry,omitempty"`
	Issuer                 string   `json:"issuer,omitempty"`
	RequestURI             string   `json:"request_uri,omitempty"`
	UsedPAR                bool     `json:"used_par,omitempty"`
	Resources              []string `json:"resources,omitempty"`
	UserInfoTokenTransport string   `json:"userinfo_token_transport,omitempty"`
}

// New creates a cookie-backed state store.
//
// authKey and encryptionKey are gorilla securecookie keys. authKey is required.
func New(authKey, encryptionKey []byte, opts ...Option) (*Store, error) {
	if len(authKey) == 0 {
		return nil, fmt.Errorf("auth key must not be empty")
	}

	s := &Store{
		sessionName: defaultSessionName,
		payloadKey:  defaultPayloadKey,
		ttl:         defaultTTL,
		cookieOptions: sessions.Options{
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		},
		now: func() time.Time {
			return time.Now().UTC()
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.sessionName == "" {
		return nil, fmt.Errorf("session name must not be empty")
	}
	if s.payloadKey == "" {
		return nil, fmt.Errorf("payload key must not be empty")
	}
	if s.ttl <= 0 {
		return nil, fmt.Errorf("ttl must be positive")
	}

	s.cookieOptions.MaxAge = ttlToMaxAge(s.ttl)
	s.store = sessions.NewCookieStore(authKey, encryptionKey)
	for _, configure := range s.configureStore {
		configure(s.store)
	}

	return s, nil
}

// SaveCorrelation stores RP-managed callback correlation data.
func (s *Store) SaveCorrelation(_ context.Context, w http.ResponseWriter, req *http.Request, state string, correlation rpstore.CallbackCorrelation) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}
	if err := requireMutableHTTP(w, req); err != nil {
		return err
	}

	session, current, err := s.loadSessionPayload(req)
	if err != nil {
		return err
	}

	now := s.now()
	if correlation.CreatedAt.IsZero() {
		correlation.CreatedAt = now
	}

	entry := current.States[state]
	entry.Correlation = toPayloadCorrelation(correlation)
	if entry.CreatedAt == 0 {
		entry.CreatedAt = correlation.CreatedAt.Unix()
	}
	current.States[state] = entry

	return s.saveSessionPayload(session, current, req, w)
}

// ConsumeCorrelation atomically loads and removes callback correlation state.
func (s *Store) ConsumeCorrelation(_ context.Context, w http.ResponseWriter, req *http.Request, state string) (rpstore.CallbackCorrelation, bool, error) {
	if state == "" {
		return rpstore.CallbackCorrelation{}, false, fmt.Errorf("state must not be empty")
	}
	if err := requireMutableHTTP(w, req); err != nil {
		return rpstore.CallbackCorrelation{}, false, err
	}

	session, current, err := s.loadSessionPayload(req)
	if err != nil {
		return rpstore.CallbackCorrelation{}, false, err
	}

	entry, ok := current.States[state]
	if !ok {
		return rpstore.CallbackCorrelation{}, false, nil
	}
	if s.isExpired(entry, s.now()) {
		delete(current.States, state)
		if err := s.saveSessionPayload(session, current, req, w); err != nil {
			return rpstore.CallbackCorrelation{}, false, err
		}
		return rpstore.CallbackCorrelation{}, false, nil
	}
	if entry.Correlation == nil {
		return rpstore.CallbackCorrelation{}, false, nil
	}

	correlation := fromPayloadCorrelation(*entry.Correlation)
	delete(current.States, state)
	if err := s.saveSessionPayload(session, current, req, w); err != nil {
		return rpstore.CallbackCorrelation{}, false, err
	}

	return correlation, true, nil
}

// LoadState loads a state scope.
func (s *Store) LoadState(_ context.Context, req *http.Request, state string) (rpstore.StateScope, bool, error) {
	if state == "" {
		return rpstore.StateScope{}, false, fmt.Errorf("state must not be empty")
	}
	if req == nil {
		return rpstore.StateScope{}, false, fmt.Errorf("request must not be nil")
	}

	_, current, err := s.loadSessionPayload(req)
	if err != nil {
		return rpstore.StateScope{}, false, err
	}

	entry, ok := current.States[state]
	if !ok || s.isExpired(entry, s.now()) {
		return rpstore.StateScope{}, false, nil
	}

	values, err := decodeValues(entry.Values)
	if err != nil {
		return rpstore.StateScope{}, false, err
	}

	correlation := rpstore.CallbackCorrelation{}
	if entry.Correlation != nil {
		correlation = fromPayloadCorrelation(*entry.Correlation)
	}

	return rpstore.StateScope{Correlation: correlation, Values: values}, true, nil
}

// DeleteState removes all data associated with a state scope.
func (s *Store) DeleteState(_ context.Context, w http.ResponseWriter, req *http.Request, state string) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}
	if err := requireMutableHTTP(w, req); err != nil {
		return err
	}

	session, current, err := s.loadSessionPayload(req)
	if err != nil {
		return err
	}

	delete(current.States, state)
	return s.saveSessionPayload(session, current, req, w)
}

// SaveValue stores a caller-owned value in a state scope.
func (s *Store) SaveValue(_ context.Context, w http.ResponseWriter, req *http.Request, state, name string, value []byte) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return fmt.Errorf("value name must not be empty")
	}
	if err := requireMutableHTTP(w, req); err != nil {
		return err
	}

	session, current, err := s.loadSessionPayload(req)
	if err != nil {
		return err
	}

	now := s.now()
	entry := current.States[state]
	if s.isExpired(entry, now) {
		entry = payloadState{}
	}
	if entry.CreatedAt == 0 {
		entry.CreatedAt = now.Unix()
	}
	if entry.Values == nil {
		entry.Values = make(map[string]string)
	}
	entry.Values[name] = base64.RawURLEncoding.EncodeToString(value)
	current.States[state] = entry

	return s.saveSessionPayload(session, current, req, w)
}

// LoadValue loads a caller-owned value from a state scope.
func (s *Store) LoadValue(_ context.Context, req *http.Request, state, name string) ([]byte, bool, error) {
	if state == "" {
		return nil, false, fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return nil, false, fmt.Errorf("value name must not be empty")
	}
	if req == nil {
		return nil, false, fmt.Errorf("request must not be nil")
	}

	_, current, err := s.loadSessionPayload(req)
	if err != nil {
		return nil, false, err
	}

	entry, ok := current.States[state]
	if !ok || s.isExpired(entry, s.now()) {
		return nil, false, nil
	}

	raw, ok := entry.Values[name]
	if !ok {
		return nil, false, nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode stored value: %w", err)
	}

	return decoded, true, nil
}

// DeleteValue removes a caller-owned value from a state scope.
func (s *Store) DeleteValue(_ context.Context, w http.ResponseWriter, req *http.Request, state, name string) error {
	if state == "" {
		return fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return fmt.Errorf("value name must not be empty")
	}
	if err := requireMutableHTTP(w, req); err != nil {
		return err
	}

	session, current, err := s.loadSessionPayload(req)
	if err != nil {
		return err
	}

	entry, ok := current.States[state]
	if !ok {
		return nil
	}

	delete(entry.Values, name)
	if len(entry.Values) == 0 && entry.Correlation == nil {
		delete(current.States, state)
	} else {
		current.States[state] = entry
	}

	return s.saveSessionPayload(session, current, req, w)
}

// ConsumeValue atomically loads and removes a caller-owned value from a state scope.
func (s *Store) ConsumeValue(_ context.Context, w http.ResponseWriter, req *http.Request, state, name string) ([]byte, bool, error) {
	if state == "" {
		return nil, false, fmt.Errorf("state must not be empty")
	}
	if name == "" {
		return nil, false, fmt.Errorf("value name must not be empty")
	}
	if err := requireMutableHTTP(w, req); err != nil {
		return nil, false, err
	}

	session, current, err := s.loadSessionPayload(req)
	if err != nil {
		return nil, false, err
	}

	entry, ok := current.States[state]
	if !ok || s.isExpired(entry, s.now()) {
		if ok {
			delete(current.States, state)
			if saveErr := s.saveSessionPayload(session, current, req, w); saveErr != nil {
				return nil, false, saveErr
			}
		}
		return nil, false, nil
	}

	raw, ok := entry.Values[name]
	if !ok {
		return nil, false, nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode stored value: %w", err)
	}

	delete(entry.Values, name)
	if len(entry.Values) == 0 && entry.Correlation == nil {
		delete(current.States, state)
	} else {
		current.States[state] = entry
	}

	if err := s.saveSessionPayload(session, current, req, w); err != nil {
		return nil, false, err
	}

	return decoded, true, nil
}

func (s *Store) loadSessionPayload(req *http.Request) (*sessions.Session, payload, error) {
	if req == nil {
		return nil, payload{}, fmt.Errorf("request must not be nil")
	}

	session, err := s.store.Get(req, s.sessionName)
	if err != nil {
		return nil, payload{}, fmt.Errorf("failed to load session: %w", err)
	}

	current, err := s.decodePayload(session.Values[s.payloadKey])
	if err != nil {
		return nil, payload{}, err
	}

	return session, current, nil
}

func (s *Store) decodePayload(raw any) (payload, error) {
	if raw == nil {
		return payload{Version: payloadVersion, States: map[string]payloadState{}}, nil
	}

	var encoded []byte
	switch v := raw.(type) {
	case string:
		encoded = []byte(v)
	case []byte:
		encoded = v
	default:
		return payload{}, fmt.Errorf("invalid session payload type: %T", raw)
	}

	current := payload{}
	if err := json.Unmarshal(encoded, &current); err != nil {
		return payload{}, fmt.Errorf("failed to decode session payload: %w", err)
	}
	if current.Version != payloadVersion {
		return payload{}, fmt.Errorf("unsupported payload version %d", current.Version)
	}
	if current.States == nil {
		current.States = map[string]payloadState{}
	}

	return current, nil
}

func (s *Store) saveSessionPayload(session *sessions.Session, current payload, req *http.Request, w http.ResponseWriter) error {
	if session == nil {
		return fmt.Errorf("session must not be nil")
	}

	if len(current.States) == 0 {
		delete(session.Values, s.payloadKey)
		cleared := s.cookieOptions
		cleared.MaxAge = -1
		session.Options = &cleared
		if err := session.Save(req, w); err != nil && !errors.Is(err, http.ErrNoCookie) {
			return fmt.Errorf("failed to save cleared session: %w", err)
		}
		return nil
	}

	current.Version = payloadVersion
	encoded, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("failed to encode session payload: %w", err)
	}

	session.Values[s.payloadKey] = string(encoded)
	updated := s.cookieOptions
	updated.MaxAge = ttlToMaxAge(s.ttl)
	session.Options = &updated

	if err := session.Save(req, w); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

func (s *Store) isExpired(entry payloadState, now time.Time) bool {
	createdAt := unixToTime(entry.CreatedAt)
	if entry.Correlation != nil {
		correlationCreatedAt := unixToTime(entry.Correlation.CreatedAt)
		if !correlationCreatedAt.IsZero() {
			createdAt = correlationCreatedAt
		}
	}

	if !createdAt.IsZero() && createdAt.Add(s.ttl).Before(now) {
		return true
	}

	if entry.Correlation != nil {
		expiresAt := unixToTime(entry.Correlation.Expiry)
		if !expiresAt.IsZero() && expiresAt.Before(now) {
			return true
		}
	}

	return false
}

func requireMutableHTTP(w http.ResponseWriter, req *http.Request) error {
	if req == nil {
		return fmt.Errorf("request must not be nil")
	}
	if w == nil {
		return fmt.Errorf("response writer must not be nil")
	}

	return nil
}

func decodeValues(values map[string]string) (map[string][]byte, error) {
	if len(values) == 0 {
		return map[string][]byte{}, nil
	}

	decoded := make(map[string][]byte, len(values))
	for k, raw := range values {
		value, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("failed decoding value %q: %w", k, err)
		}
		decoded[k] = value
	}
	return decoded, nil
}

func toPayloadCorrelation(correlation rpstore.CallbackCorrelation) *payloadCorrelation {
	return &payloadCorrelation{
		Nonce:                  correlation.Nonce,
		CodeVerifier:           correlation.CodeVerifier,
		CreatedAt:              correlation.CreatedAt.Unix(),
		Expiry:                 correlation.Expiry.Unix(),
		Issuer:                 correlation.Issuer,
		RequestURI:             correlation.RequestURI,
		UsedPAR:                correlation.UsedPAR,
		Resources:              correlation.Resources,
		UserInfoTokenTransport: correlation.UserInfoTokenTransport,
	}
}

func fromPayloadCorrelation(correlation payloadCorrelation) rpstore.CallbackCorrelation {
	return rpstore.CallbackCorrelation{
		Nonce:                  correlation.Nonce,
		CodeVerifier:           correlation.CodeVerifier,
		CreatedAt:              unixToTime(correlation.CreatedAt),
		Expiry:                 unixToTime(correlation.Expiry),
		Issuer:                 correlation.Issuer,
		RequestURI:             correlation.RequestURI,
		UsedPAR:                correlation.UsedPAR,
		Resources:              correlation.Resources,
		UserInfoTokenTransport: correlation.UserInfoTokenTransport,
	}
}

func unixToTime(ts int64) time.Time {
	if ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
}

func ttlToMaxAge(ttl time.Duration) int {
	seconds := int(math.Ceil(ttl.Seconds()))
	if seconds < 1 {
		return 1
	}
	return seconds
}
