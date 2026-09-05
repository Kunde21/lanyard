package rp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// spanRecorder captures spans for assertions.
type spanRecorder struct {
	provider *sdktrace.TracerProvider
	recorder *tracetest.SpanRecorder
}

func newSpanRecorder(t *testing.T) *spanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})
	return &spanRecorder{provider: provider, recorder: recorder}
}

func (s *spanRecorder) spans() []sdktrace.ReadOnlySpan {
	return s.recorder.Ended()
}

func (s *spanRecorder) spanNames() []string {
	names := make([]string, 0, len(s.spans()))
	for _, span := range s.spans() {
		names = append(names, span.Name())
	}
	return names
}

func TestTracerPlumbing(t *testing.T) {
	sr := newSpanRecorder(t)

	r := claimsTestRP(t, WithTracerProvider(sr.provider))

	_, span := r.tracer.Start(context.Background(), "plumbing.probe")
	span.SetAttributes(attribute.String("probe", "ok"))
	span.End()

	spans := sr.spans()
	if len(spans) != 1 {
		t.Fatalf("recorded spans = %d, want 1", len(spans))
	}
	if spans[0].Name() != "plumbing.probe" {
		t.Fatalf("span name = %q, want plumbing.probe", spans[0].Name())
	}
}

func TestTracerDefaultsToNoop(t *testing.T) {
	// No tracer provider installed: constructing and using an RP must not
	// panic and yields no recording spans (the global provider is a no-op).
	r := claimsTestRP(t)

	_, span := r.tracer.Start(context.Background(), "noop.probe")
	span.End()
	if span.IsRecording() {
		t.Fatal("span recording under default no-op provider")
	}
}

// assertNoSecrets walks every recorded span's attributes and events and
// fails if any sentinel substring appears — the standing guarantee that no
// secret value enters telemetry.
func assertNoSecrets(t *testing.T, spans []sdktrace.ReadOnlySpan, sentinels []string) {
	t.Helper()
	contains := func(haystack string) (string, bool) {
		for _, sentinel := range sentinels {
			if strings.Contains(haystack, sentinel) {
				return sentinel, true
			}
		}
		return "", false
	}
	for _, span := range spans {
		for _, kv := range span.Attributes() {
			if found, hit := contains(fmt.Sprintf("%s=%v", kv.Key, kv.Value.AsString())); hit {
				t.Fatalf("span %q attribute %q leaks secret sentinel %q", span.Name(), kv.Key, found)
			}
		}
		for _, event := range span.Events() {
			for _, kv := range event.Attributes {
				if found, hit := contains(fmt.Sprintf("%s=%v", kv.Key, kv.Value.AsString())); hit {
					t.Fatalf("span %q event %q attribute %q leaks secret sentinel %q", span.Name(), event.Name, kv.Key, found)
				}
			}
			if found, hit := contains(event.Name); hit {
				t.Fatalf("span %q event name leaks secret sentinel %q", span.Name(), found)
			}
		}
	}
}
