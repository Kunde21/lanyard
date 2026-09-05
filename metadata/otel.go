package metadata

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// spanStart begins a span using the client's tracer.
func (c *Client) spanStart(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if c.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return c.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// spanError marks the span failed with a description that is guaranteed free
// of response bodies (which may embed token material): HTTP errors reduce to
// their status code, everything else to the sentinel or type name.
func spanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.SetStatus(codes.Error, safeErrorDescription(err))
}

func safeErrorDescription(err error) string {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return fmt.Sprintf("http status %d", statusErr.StatusCode)
	}
	if errors.Is(err, ErrDiscoveryFailed) {
		return "discovery failed"
	}
	return fmt.Sprintf("%T", err)
}
