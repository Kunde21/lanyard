package cookie

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

const (
	defaultSessionName = "lanyard_rp_state"
	defaultPayloadKey  = "payload"
	defaultTTL         = 10 * time.Minute
)

// Option configures a cookie-backed state store.
type Option func(*Store)

// WithSessionName sets the gorilla session cookie name.
func WithSessionName(name string) Option {
	return func(s *Store) {
		if name != "" {
			s.sessionName = name
		}
	}
}

// WithTTL sets cookie and state lifetime.
func WithTTL(ttl time.Duration) Option {
	return func(s *Store) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// WithCookiePath sets the cookie path.
func WithCookiePath(path string) Option {
	return func(s *Store) {
		if path != "" {
			s.cookieOptions.Path = path
		}
	}
}

// WithCookieDomain sets the cookie domain.
func WithCookieDomain(domain string) Option {
	return func(s *Store) {
		s.cookieOptions.Domain = domain
	}
}

// WithSecure controls the cookie Secure attribute.
func WithSecure(secure bool) Option {
	return func(s *Store) {
		s.cookieOptions.Secure = secure
	}
}

// WithHTTPOnly controls the cookie HttpOnly attribute.
func WithHTTPOnly(httpOnly bool) Option {
	return func(s *Store) {
		s.cookieOptions.HttpOnly = httpOnly
	}
}

// WithSameSite sets the cookie SameSite attribute.
func WithSameSite(sameSite http.SameSite) Option {
	return func(s *Store) {
		s.cookieOptions.SameSite = sameSite
	}
}

// WithSessionOptions allows advanced customization of gorilla session cookie options.
func WithSessionOptions(configure func(*sessions.Options)) Option {
	return func(s *Store) {
		if configure != nil {
			configure(&s.cookieOptions)
		}
	}
}

// WithCookieStore allows advanced customization of the underlying gorilla cookie store.
func WithCookieStore(configure func(*sessions.CookieStore)) Option {
	return func(s *Store) {
		if configure != nil {
			s.configureStore = append(s.configureStore, configure)
		}
	}
}

func withNow(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}
