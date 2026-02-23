package httputil

import (
	"net/http"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
)

// CalculateFreshUntil respects Cache-Control/Expires headers and falls back to
// the provided TTL when the response lacks explicit caching headers.
func CalculateFreshUntil(req *http.Request, statusCode int, headers http.Header, fallbackTTL time.Duration, now time.Time) time.Time {
	if req != nil {
		_, expiry, err := cacheobject.UsingRequestResponse(req, statusCode, headers, true)
		if err == nil && !expiry.IsZero() {
			return expiry.UTC()
		}
	}

	return now.Add(fallbackTTL)
}
