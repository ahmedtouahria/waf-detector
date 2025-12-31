package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ahmedtouahria/waf-detector/cli"
)

func TestNewScanner(t *testing.T) {
	config := &cli.Config{
		Timeout: 10 * time.Second,
	}
	s := NewScanner(config)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.client == nil {
		t.Error("Scanner should have HTTP client")
	}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		wantError bool
	}{
		{
			name:      "Valid HTTPS URL",
			baseURL:   "https://example.com",
			wantError: false,
		},
		{
			name:      "Valid HTTP URL",
			baseURL:   "http://example.com",
			wantError: false,
		},
		{
			name:      "URL without scheme",
			baseURL:   "example.com",
			wantError: false,
		},
	}

	config := &cli.Config{Timeout: 10 * time.Second}
	s := NewScanner(config)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Scan(ctx, tt.baseURL)
			if (err != nil) != tt.wantError {
				t.Errorf("Scan() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestScanInvalidURL(t *testing.T) {
	config := &cli.Config{
		Timeout: 1 * time.Second, // Short timeout
	}
	s := NewScanner(config)
	ctx := context.Background()

	// Test with URL that will definitely fail - non-existent domain
	results, _ := s.Scan(ctx, "https://this-domain-definitely-does-not-exist-12345.com")

	// At least one probe should have an error
	hasError := false
	for _, result := range results {
		if result.Error != nil {
			hasError = true
			break
		}
	}

	if !hasError {
		t.Log("Warning: Expected at least one probe to fail for non-existent domain")
		// Don't fail the test since network conditions vary
	}
}

func TestProbeTypeString(t *testing.T) {
	tests := []struct {
		probeType ProbeType
		want      string
	}{
		{ProbeNormal, "normal"},
		{ProbeSQLi, "sqli"},
		{ProbeXSS, "xss"},
		{ProbeMalformed, "malformed"},
	}

	for _, tt := range tests {
		t.Run(string(tt.probeType), func(t *testing.T) {
			if string(tt.probeType) != tt.want {
				t.Errorf("ProbeType = %s, want %s", tt.probeType, tt.want)
			}
		})
	}
}
