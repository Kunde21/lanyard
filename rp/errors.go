package rp

import (
	"errors"
	"fmt"
	"strings"
)

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
	// ErrAuthMethodNotSupported indicates provider does not support the requested auth method.
	ErrAuthMethodNotSupported = errors.New("auth method not supported")
	// ErrClientCredentialsFailed indicates client credentials token request failed.
	ErrClientCredentialsFailed = errors.New("client credentials token request failed")
	// ErrRefreshTokenFailed indicates a refresh token request failed.
	ErrRefreshTokenFailed = errors.New("refresh token request failed")
	// ErrRefreshTokenRejected indicates the authorization server rejected the
	// refresh token (invalid_grant). Per RFC 9700, callers must discard the
	// refresh token and restart the authorization flow; replaying a rotated
	// token typically triggers revocation of the whole token family.
	ErrRefreshTokenRejected = errors.New("refresh token was rejected")
	// ErrTokenUnbound indicates a token lacked a required sender-constraint binding.
	ErrTokenUnbound = errors.New("token is not sender-constrained")
	// ErrTokenBindingMismatch indicates a token's cnf binding did not match the expected key.
	ErrTokenBindingMismatch = errors.New("token binding mismatch")
)

// AuthMethodError indicates token endpoint auth method selection/validation failure.
type AuthMethodError struct {
	Method    AuthMethod
	Supported []string
	Err       error
}

// Error implements error.
func (e *AuthMethodError) Error() string {
	if e == nil {
		return "auth method validation failed"
	}

	msg := "auth method validation failed"
	if e.Method != "" {
		msg = fmt.Sprintf("token endpoint auth method %q", e.Method)
	}
	if len(e.Supported) > 0 {
		msg = fmt.Sprintf("%s is not supported (supported: %s)", msg, strings.Join(e.Supported, ", "))
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}

	return msg
}

// Unwrap returns wrapped error.
func (e *AuthMethodError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is supports errors.Is against ErrAuthMethodNotSupported.
func (e *AuthMethodError) Is(target error) bool {
	if target == ErrAuthMethodNotSupported {
		return true
	}

	return e != nil && errors.Is(e.Err, target)
}
