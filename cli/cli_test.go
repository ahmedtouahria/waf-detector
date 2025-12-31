package cli

import (
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	config := &Config{
		URL:        "https://example.com",
		Threads:    10,
		OutputFile: "results.json",
		Format:     "json",
		Timeout:    10 * time.Second,
		UserAgent:  "test-agent",
		Silent:     false,
		NoColor:    false,
		Debug:      false,
	}

	if config.URL != "https://example.com" {
		t.Errorf("URL = %s, want https://example.com", config.URL)
	}
	if config.Threads != 10 {
		t.Errorf("Threads = %d, want 10", config.Threads)
	}
	if config.Format != "json" {
		t.Errorf("Format = %s, want json", config.Format)
	}
}
