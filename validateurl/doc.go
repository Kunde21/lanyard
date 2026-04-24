// Package validateurl contains URL validation helpers shared by Lanyard
// packages.
//
// The primary helper, [ParseHTTPSAbsoluteNoQueryFragment], accepts only
// absolute HTTPS URLs without query or fragment components. It returns sentinel
// errors such as [ErrInvalidFormat], [ErrInvalidHTTPS], and
// [ErrQueryOrFragment] so callers can classify validation failures with
// errors.Is.
package validateurl
