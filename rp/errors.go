package rp

import "errors"

var (
	// ErrInvalidConfiguration indicates RP configuration is invalid.
	ErrInvalidConfiguration = errors.New("invalid rp configuration")
	// ErrInvalidState indicates callback state validation failed.
	ErrInvalidState = errors.New("invalid state")
	// ErrMissingCode indicates callback is missing an authorization code.
	ErrMissingCode = errors.New("missing authorization code")
	// ErrTokenExchangeFailed indicates token exchange failed.
	ErrTokenExchangeFailed = errors.New("token exchange failed")
	// ErrIDTokenValidationFailed indicates ID token validation failed.
	ErrIDTokenValidationFailed = errors.New("id token validation failed")
	// ErrUserInfoValidationFailed indicates UserInfo validation failed.
	ErrUserInfoValidationFailed = errors.New("userinfo validation failed")
)
