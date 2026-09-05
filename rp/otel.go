package rp

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// spanStart begins a span using the client's tracer.
func (c *clientConfig) spanStart(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if c.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return c.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// spanError marks the span failed with a description guaranteed free of
// response previews (which may embed token material): sentinel errors reduce
// to their name, everything else to the type name.
func spanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.SetStatus(codes.Error, safeSpanErrorDescription(err))
}

func safeSpanErrorDescription(err error) string {
	for _, sentinel := range []error{
		ErrInvalidConfiguration,
		ErrIDTokenValidationFailed,
		ErrUserInfoValidationFailed,
		ErrTokenExchangeFailed,
		ErrRefreshTokenFailed,
		ErrRefreshTokenRejected,
		ErrClientCredentialsFailed,
		ErrIntrospectionFailed,
		ErrRegistrationFailed,
		ErrGrantManagementFailed,
		ErrAuthorizationFailed,
		ErrInvalidGrantID,
		ErrInvalidState,
		ErrMissingCode,
	} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	return fmt.Sprintf("%T", err)
}

// urlPathAttribute records scheme://host/path — query strings (which carry
// state, nonce, and PKCE challenges in authorization URLs) are stripped by
// construction.
func urlPathAttribute(key, raw string) attribute.KeyValue {
	return attribute.String(key, stripURLQuery(raw))
}

func stripURLQuery(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path
}
