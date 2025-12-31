package errors

import (
	"errors"
	"testing"
)

func TestWAFError(t *testing.T) {
	tests := []struct {
		name     string
		err      *WAFError
		wantType ErrorType
	}{
		{
			name:     "Network error",
			err:      NewNetworkError("https://example.com", errors.New("connection refused")),
			wantType: ErrorTypeNetwork,
		},
		{
			name:     "Timeout error",
			err:      NewTimeoutError("https://example.com"),
			wantType: ErrorTypeTimeout,
		},
		{
			name:     "Invalid URL error",
			err:      NewInvalidURLError("not-a-url", errors.New("parse error")),
			wantType: ErrorTypeInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Type != tt.wantType {
				t.Errorf("Error type = %v, want %v", tt.err.Type, tt.wantType)
			}
			if tt.err.Error() == "" {
				t.Error("Error message should not be empty")
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	originalErr := errors.New("original error")
	wafErr := NewNetworkError("https://example.com", originalErr)
	unwrapped := errors.Unwrap(wafErr)
	if unwrapped != originalErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, originalErr)
	}
}
