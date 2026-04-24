package validateurl

import (
	"errors"
	"fmt"
	"net/url"
)

var (
	// ErrInvalidFormat reports a URL string that cannot be parsed.
	ErrInvalidFormat = errors.New("invalid URL format")
	// ErrInvalidHTTPS reports a URL that is not absolute HTTPS with a host.
	ErrInvalidHTTPS = errors.New("URL must be an absolute https URL")
	// ErrQueryOrFragment reports a URL containing query or fragment components.
	ErrQueryOrFragment = errors.New("URL must not include query or fragment")
)

// ParseHTTPSAbsoluteNoQueryFragment validates the provided string as an absolute
// https URL that contains neither query nor fragment components.
func ParseHTTPSAbsoluteNoQueryFragment(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}

	if !u.IsAbs() || u.Scheme != "https" || u.Host == "" {
		return nil, ErrInvalidHTTPS
	}

	if u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrQueryOrFragment
	}

	return u, nil
}
