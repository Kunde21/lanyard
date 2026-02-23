package validateurl

import (
	"errors"
	"testing"
)

func TestParseHTTPSAbsoluteNoQueryFragment(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{name: "valid https", raw: "https://example.com/path", wantErr: nil},
		{name: "non https scheme", raw: "http://example.com", wantErr: ErrInvalidHTTPS},
		{name: "missing host", raw: "https://", wantErr: ErrInvalidHTTPS},
		{name: "query present", raw: "https://example.com/?foo=bar", wantErr: ErrQueryOrFragment},
		{name: "fragment present", raw: "https://example.com/#frag", wantErr: ErrQueryOrFragment},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseHTTPSAbsoluteNoQueryFragment(tt.raw)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
